// =============== src/arbitrage_detector.rs ===============
use crate::amm_interactor;
use crate::{Pool, Token};
use alloy::primitives::U256;
use alloy::providers::Provider;
use eyre::{Result, WrapErr};
use std::sync::Arc; // Assuming Pool and Token structs are in main.rs or lib.rs

// A constant for scaling fixed-point arithmetic, e.g., 10^18
// Should match the typical decimal count of well-used tokens like WETH
const PRICE_SCALE_FACTOR_U256: U256 = U256::from_limbs([1_000_000_000_000_000_000, 0, 0, 0]); // 10^18

#[derive(Debug)]
pub struct ArbitrageOpportunity {
    pub description: String,
    pub profit_token_a_scaled: U256, // Profit in terms of token_a, scaled
    pub profit_token_b_scaled: U256, // Profit in terms of token_b, scaled
    pub amount_to_trade_token_a: U256,
    // Add more details like path, estimated gas, etc.
}

/// Calculates the amount of output token received for a given input amount from a constant product pool.
/// (reserve_in * amount_in_with_fee) / (reserve_out * 1000 + amount_in_with_fee)
/// This is a simplified version for Uniswap V2 style pools (0.3% fee).
/// reserve_in: Reserve of the input token.
/// reserve_out: Reserve of the output token.
/// amount_in: Amount of input token.
/// Returns: Amount of output token.
pub fn get_amount_out(reserve_in: U256, reserve_out: U256, amount_in: U256) -> Result<U256> {
    if reserve_in.is_zero() || reserve_out.is_zero() || amount_in.is_zero() {
        return Ok(U256::ZERO);
    }

    let amount_in_with_fee = amount_in * U256::from(997); // amount_in * (1 - 0.003)
    let numerator = amount_in_with_fee * reserve_out;
    let denominator = reserve_in * U256::from(1000) + amount_in_with_fee;

    if denominator.is_zero() {
        return Err(eyre::eyre!(
            "Denominator is zero in get_amount_out calculation"
        ));
    }

    Ok(numerator / denominator)
}

/// Calculates the spot price of token1 in terms of token0, scaled by PRICE_SCALE_FACTOR_U256.
/// Price = (reserve1 * SCALE) / reserve0
pub fn get_scaled_price_token1_per_token0(
    reserve0: U256,
    reserve1: U256,
    token0_decimals: u8,
    token1_decimals: u8,
) -> Result<U256> {
    if reserve0.is_zero() {
        return Err(eyre::eyre!("Reserve0 is zero, cannot calculate price"));
    }

    // Adjust reserves for decimals to get a common base for price calculation
    // price = (reserve1 / 10^dec1) / (reserve0 / 10^dec0)
    // price_scaled = ( (reserve1 * 10^dec0) / (reserve0 * 10^dec1) ) * SCALE_FACTOR
    // For simplicity, let's assume reserves are already comparable or we normalize them first.
    // A more robust way is to convert to a common "value" unit if prices from an oracle are available,
    // or normalize to a common decimal place before calculating ratio.

    // Simple ratio: (reserve1 * PRICE_SCALE_FACTOR) / reserve0
    // This gives price of token0 in terms of token1 if reserve0 is amount of token0
    // To get price of token1 in terms of token0: (reserve0 * PRICE_SCALE_FACTOR) / reserve1
    // Let's define price as: How much of token0 do I get for 1 unit of token1 (scaled)?
    // Or, how much of token1 do I get for 1 unit of token0 (scaled)?

    // Price of token1 in terms of token0 = reserve1 / reserve0
    // Scaled price = (reserve1 * PRICE_SCALE_FACTOR_U256) / reserve0

    // Adjust for decimals:
    // Effective reserve0 = reserve0 / 10^token0_decimals
    // Effective reserve1 = reserve1 / 10^token1_decimals
    // Price = (reserve1 * 10^token0_decimals) / (reserve0 * 10^token1_decimals)
    // Scaled_price = (reserve1 * 10^token0_decimals * PRICE_SCALE_FACTOR_U256) / (reserve0 * 10^token1_decimals)

    let factor0 = U256::pow(U256::from(10), U256::from(token0_decimals));
    let factor1 = U256::pow(U256::from(10), U256::from(token1_decimals));

    if reserve0.is_zero() || factor1.is_zero() {
        return Err(eyre::eyre!(
            "Cannot divide by zero due to reserve0 or factor1"
        ));
    }

    let numerator = reserve1 * factor0 * PRICE_SCALE_FACTOR_U256;
    let denominator = reserve0 * factor1;

    if denominator.is_zero() {
        return Err(eyre::eyre!(
            "Denominator became zero after decimal adjustment"
        ));
    }

    Ok(numerator / denominator)
}

pub async fn find_arbitrage_opportunities_between_pools(
    provider: Arc<impl Provider>,
    pools: &[Pool],
    base_token: Arc<Token>,  // e.g., WETH, the token we want to accumulate
    quote_token: Arc<Token>, // e.g., USDC, the token we trade against
    min_profit_usd_f64: f64, // For comparing profit, assuming we can get a USD price for base_token
) -> Result<Vec<ArbitrageOpportunity>> {
    let mut opportunities = Vec::new();

    if pools.len() < 2 {
        println!("Need at least two pools to find arbitrage.");
        return Ok(opportunities);
    }

    // For simplicity, this example compares the first two pools for WETH/USDC like pair.
    // A real system would iterate through all pool combinations and token pairs.

    let pool_a = &pools[0];
    let pool_b = &pools[1];

    println!("Fetching reserves for Pool A ({})...", pool_a.exchange_name);
    let (reserves0_a, reserves1_a, p_a_t0_addr, p_a_t1_addr) =
        amm_interactor::get_pool_reserves_and_tokens(provider.clone(), pool_a.address).await?;

    // Determine which reserve corresponds to base_token and quote_token for Pool A
    let (reserve_base_a, reserve_quote_a) =
        if p_a_t0_addr == base_token.address && p_a_t1_addr == quote_token.address {
            (reserves0_a, reserves1_a)
        } else if p_a_t0_addr == quote_token.address && p_a_t1_addr == base_token.address {
            (reserves1_a, reserves0_a)
        } else {
            return Err(eyre::eyre!(
                "Pool A ({}) tokens ({}, {}) do not match base ({}) / quote ({})",
                pool_a.address,
                p_a_t0_addr,
                p_a_t1_addr,
                base_token.address,
                quote_token.address
            ));
        };
    println!(
        "Pool A ({}): Base ({}) Reserves: {}, Quote ({}) Reserves: {}",
        pool_a.exchange_name,
        base_token.symbol,
        reserve_base_a,
        quote_token.symbol,
        reserve_quote_a
    );

    println!("Fetching reserves for Pool B ({})...", pool_b.exchange_name);
    let (reserves0_b, reserves1_b, p_b_t0_addr, p_b_t1_addr) =
        amm_interactor::get_pool_reserves_and_tokens(provider.clone(), pool_b.address).await?;

    let (reserve_base_b, reserve_quote_b) =
        if p_b_t0_addr == base_token.address && p_b_t1_addr == quote_token.address {
            (reserves0_b, reserves1_b)
        } else if p_b_t0_addr == quote_token.address && p_b_t1_addr == base_token.address {
            (reserves1_b, reserves0_b)
        } else {
            return Err(eyre::eyre!(
                "Pool B ({}) tokens ({}, {}) do not match base ({}) / quote ({})",
                pool_b.address,
                p_b_t0_addr,
                p_b_t1_addr,
                base_token.address,
                quote_token.address
            ));
        };
    println!(
        "Pool B ({}): Base ({}) Reserves: {}, Quote ({}) Reserves: {}",
        pool_b.exchange_name,
        base_token.symbol,
        reserve_base_b,
        quote_token.symbol,
        reserve_quote_b
    );

    // Calculate scaled price of quote_token in terms of base_token for each pool
    // Price = How many base_tokens per one quote_token (scaled)
    // Price = (reserve_base * SCALE) / reserve_quote
    let price_base_per_quote_a_scaled = get_scaled_price_token1_per_token0(
        reserve_quote_a,
        reserve_base_a,
        quote_token.decimals,
        base_token.decimals,
    )
    .wrap_err(format!(
        "Failed to calculate price for pool A ({})",
        pool_a.exchange_name
    ))?;
    let price_base_per_quote_b_scaled = get_scaled_price_token1_per_token0(
        reserve_quote_b,
        reserve_base_b,
        quote_token.decimals,
        base_token.decimals,
    )
    .wrap_err(format!(
        "Failed to calculate price for pool B ({})",
        pool_b.exchange_name
    ))?;

    println!(
        "Pool A Scaled Price ({} per {}): {}",
        base_token.symbol, quote_token.symbol, price_base_per_quote_a_scaled
    );
    println!(
        "Pool B Scaled Price ({} per {}): {}",
        base_token.symbol, quote_token.symbol, price_base_per_quote_b_scaled
    );

    // --- Arbitrage Logic ---
    // Scenario 1: Buy base_token on Pool A (if cheaper), Sell base_token on Pool B (if more expensive)
    // Cheaper means: more base_token per quote_token. So if price_base_per_quote_a_scaled > price_base_per_quote_b_scaled, A gives more base for quote.
    // This means base_token is "cheaper" on A if you are spending quote_token.

    // Let's use an example trade amount of quote_token, e.g., 100 USDC
    // Amount must be adjusted for quote_token's decimals
    let amount_quote_to_trade =
        U256::from(100) * U256::pow(U256::from(10), U256::from(quote_token.decimals)); // e.g., 100 USDC

    // Path 1: Pool A (Quote -> Base) then Pool B (Base -> Quote)
    if price_base_per_quote_a_scaled > price_base_per_quote_b_scaled {
        // Base is "cheaper" on A (more base per quote)
        let base_received_on_a =
            get_amount_out(reserve_quote_a, reserve_base_a, amount_quote_to_trade)?;
        if base_received_on_a.is_zero() {
            println!("Path 1: Trade on A yields zero base tokens.");
            return Ok(opportunities);
        }

        let quote_received_on_b =
            get_amount_out(reserve_base_b, reserve_quote_b, base_received_on_a)?;

        println!(
            "Path 1 ({} -> {} -> {}): Start with {} {}, Get {} {}, End with {} {}",
            pool_a.exchange_name,
            base_token.symbol,
            pool_b.exchange_name,
            amount_quote_to_trade / U256::pow(U256::from(10), U256::from(quote_token.decimals)),
            quote_token.symbol,
            base_received_on_a / U256::pow(U256::from(10), U256::from(base_token.decimals)),
            base_token.symbol,
            quote_received_on_b / U256::pow(U256::from(10), U256::from(quote_token.decimals)),
            quote_token.symbol
        );

        if quote_received_on_b > amount_quote_to_trade {
            let profit_quote_scaled = quote_received_on_b - amount_quote_to_trade;
            // TODO: Convert profit_quote_scaled to USD equivalent to compare with min_profit_usd_f64
            // This requires an oracle or another price source for quote_token/USD.
            // For now, let's assume 1 quote_token = 1 USD for simplicity if quote is USDC.
            let profit_usd_approx = profit_quote_scaled
                .to_string()
                .parse::<f64>()
                .unwrap_or(0.0)
                / (10.0_f64.powi(quote_token.decimals as i32));

            println!(
                "Potential Profit (Path 1): {} {} (approx ${})",
                profit_quote_scaled / U256::pow(U256::from(10), U256::from(quote_token.decimals)),
                quote_token.symbol,
                profit_usd_approx
            );

            if profit_usd_approx > min_profit_usd_f64 {
                // Simplified profit check
                opportunities.push(ArbitrageOpportunity {
                    description: format!(
                        "Buy {} on {} (spend {}), Sell {} on {} (receive {})",
                        base_token.symbol,
                        pool_a.exchange_name,
                        quote_token.symbol,
                        base_token.symbol,
                        pool_b.exchange_name,
                        quote_token.symbol
                    ),
                    profit_token_a_scaled: U256::ZERO, // Profit is in quote token for this path
                    profit_token_b_scaled: profit_quote_scaled,
                    amount_to_trade_token_a: base_received_on_a, // This is intermediate amount
                });
            }
        }
    }
    // Scenario 2: Buy base_token on Pool B (if cheaper), Sell base_token on Pool A (if more expensive)
    else if price_base_per_quote_b_scaled > price_base_per_quote_a_scaled {
        // Base is "cheaper" on B
        let base_received_on_b =
            get_amount_out(reserve_quote_b, reserve_base_b, amount_quote_to_trade)?;
        if base_received_on_b.is_zero() {
            println!("Path 2: Trade on B yields zero base tokens.");
            return Ok(opportunities);
        }

        let quote_received_on_a =
            get_amount_out(reserve_base_a, reserve_quote_a, base_received_on_b)?;

        println!(
            "Path 2 ({} -> {} -> {}): Start with {} {}, Get {} {}, End with {} {}",
            pool_b.exchange_name,
            base_token.symbol,
            pool_a.exchange_name,
            amount_quote_to_trade / U256::pow(U256::from(10), U256::from(quote_token.decimals)),
            quote_token.symbol,
            base_received_on_b / U256::pow(U256::from(10), U256::from(base_token.decimals)),
            base_token.symbol,
            quote_received_on_a / U256::pow(U256::from(10), U256::from(quote_token.decimals)),
            quote_token.symbol
        );

        if quote_received_on_a > amount_quote_to_trade {
            let profit_quote_scaled = quote_received_on_a - amount_quote_to_trade;
            let profit_usd_approx = profit_quote_scaled
                .to_string()
                .parse::<f64>()
                .unwrap_or(0.0)
                / (10.0_f64.powi(quote_token.decimals as i32));
            println!(
                "Potential Profit (Path 2): {} {} (approx ${})",
                profit_quote_scaled / U256::pow(U256::from(10), U256::from(quote_token.decimals)),
                quote_token.symbol,
                profit_usd_approx
            );

            if profit_usd_approx > min_profit_usd_f64 {
                opportunities.push(ArbitrageOpportunity {
                    description: format!(
                        "Buy {} on {} (spend {}), Sell {} on {} (receive {})",
                        base_token.symbol,
                        pool_b.exchange_name,
                        quote_token.symbol,
                        base_token.symbol,
                        pool_a.exchange_name,
                        quote_token.symbol
                    ),
                    profit_token_a_scaled: U256::ZERO,
                    profit_token_b_scaled: profit_quote_scaled,
                    amount_to_trade_token_a: base_received_on_b,
                });
            }
        }
    } else {
        println!(
            "Prices are too similar or an issue occurred, no clear arbitrage path starting with quote token."
        );
    }

    // TODO: Add logic to account for gas fees. Gas fees should be estimated and subtracted from profit.
    // TODO: Implement more sophisticated optimal trade amount calculation rather than a fixed amount.

    Ok(opportunities)
}
