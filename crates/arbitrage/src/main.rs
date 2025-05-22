use alloy::primitives::Address;
use alloy::providers::{ProviderBuilder, WsConnect};
use eyre::{Result, WrapErr};
use futures_util::StreamExt;
use std::sync::Arc;
 // Required for stream.next()

mod amm_interactor;
mod arbitrage_detector;
mod config;
mod ethereum_client;
// mod utils; // If you add a utils.rs

// A simple representation of a token
#[derive(Debug, Clone)]
pub struct Token {
    pub address: Address,
    pub symbol: String,
    pub decimals: u8,
}

// A simple representation of an AMM pool we are monitoring
#[derive(Debug, Clone)]
pub struct Pool {
    pub address: Address,
    pub token0: Arc<Token>, // Using Arc for shared ownership if tokens are reused
    pub token1: Arc<Token>,
    pub exchange_name: String, // e.g., "UniswapV2", "Sushiswap"
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    println!("🚀 Starting AMM Arbitrage Detector (Alloy-rs)...");

    let app_config = config::load_config().wrap_err("Failed to load configuration")?;
    println!("✅ Configuration loaded.");
    println!("Attempting to connect to RPC: {}", app_config.rpc_url);

    let ws_connect = WsConnect::new(&app_config.rpc_url);
    let provider = Arc::new(ProviderBuilder::new().connect_ws(ws_connect).await?);

    // --- Define Tokens (example) ---
    // These would ideally be loaded from config or a token list
    let weth_address: Address = app_config
        .weth_address
        .parse()
        .wrap_err("Invalid WETH address")?;
    let usdc_address: Address = app_config
        .usdc_address
        .parse()
        .wrap_err("Invalid USDC address")?;

    let weth = Arc::new(Token {
        address: weth_address,
        symbol: "WETH".to_string(),
        decimals: 18,
    });
    let usdc = Arc::new(Token {
        address: usdc_address,
        symbol: "USDC".to_string(),
        decimals: 6,
    });

    println!(
        "🪙 Tokens defined: WETH ({}), USDC ({})",
        weth.address, usdc.address
    );

    // --- Define Pools to Monitor (example) ---
    // These addresses are illustrative and for a specific network (e.g., Mainnet)
    // Ensure they are correct for the network you are targeting.
    let pool1_address_str = &app_config.pool1_address;
    let pool2_address_str = &app_config.pool2_address;

    let pool1_address: Address = pool1_address_str
        .parse()
        .wrap_err(format!("Invalid Pool 1 address: {}", pool1_address_str))?;
    let pool2_address: Address = pool2_address_str
        .parse()
        .wrap_err(format!("Invalid Pool 2 address: {}", pool2_address_str))?;

    // Important: You need to verify which token is token0 and token1 for each pool
    // or fetch it dynamically. For this example, we assume WETH is token0 for pool1
    // and USDC is token0 for pool2 (this might not be true and is just for structure).
    // A robust solution would call `token0()` and `token1()` on the pair contract.

    // For simplicity, let's assume we know the token order or fetch it.
    // Here, we'll try to fetch the actual token order for pool1.
    let (fetched_t0_p1_addr, fetched_t1_p1_addr) =
        amm_interactor::get_pool_token_addresses(provider.clone(), pool1_address)
            .await
            .wrap_err(format!(
                "Failed to get token addresses for pool {}",
                pool1_address
            ))?;

    let (pool1_token0, pool1_token1) =
        if fetched_t0_p1_addr == weth.address && fetched_t1_p1_addr == usdc.address {
            (weth.clone(), usdc.clone())
        } else if fetched_t0_p1_addr == usdc.address && fetched_t1_p1_addr == weth.address {
            (usdc.clone(), weth.clone())
        } else {
            eyre::bail!(
                "Pool 1 ({}) tokens do not match expected WETH/USDC. Got {} and {}",
                pool1_address,
                fetched_t0_p1_addr,
                fetched_t1_p1_addr
            );
        };
    println!(
        "Pool 1 ({}) uses Token0: {} ({}), Token1: {} ({})",
        pool1_address,
        pool1_token0.symbol,
        pool1_token0.address,
        pool1_token1.symbol,
        pool1_token1.address
    );

    let pool1 = Pool {
        address: pool1_address,
        token0: pool1_token0.clone(),
        token1: pool1_token1.clone(),
        exchange_name: "DEX1".to_string(), // e.g., UniswapV2_Pool1
    };

    // For pool2, let's assume a similar setup or a different pair
    // For this example, let's assume pool2 is also WETH/USDC for direct comparison
    let (fetched_t0_p2_addr, fetched_t1_p2_addr) =
        amm_interactor::get_pool_token_addresses(provider.clone(), pool2_address)
            .await
            .wrap_err(format!(
                "Failed to get token addresses for pool {}",
                pool2_address
            ))?;

    let (pool2_token0, pool2_token1) =
        if fetched_t0_p2_addr == weth.address && fetched_t1_p2_addr == usdc.address {
            (weth.clone(), usdc.clone())
        } else if fetched_t0_p2_addr == usdc.address && fetched_t1_p2_addr == weth.address {
            (usdc.clone(), weth.clone())
        } else {
            eyre::bail!(
                "Pool 2 ({}) tokens do not match expected WETH/USDC. Got {} and {}",
                pool2_address,
                fetched_t0_p2_addr,
                fetched_t1_p2_addr
            );
        };
    println!(
        "Pool 2 ({}) uses Token0: {} ({}), Token1: {} ({})",
        pool2_address,
        pool2_token0.symbol,
        pool2_token0.address,
        pool2_token1.symbol,
        pool2_token1.address
    );

    let pool2 = Pool {
        address: pool2_address,
        token0: pool2_token0.clone(),
        token1: pool2_token1.clone(),
        exchange_name: "DEX2".to_string(), // e.g., Sushiswap_Pool1
    };

    let pools_to_monitor = vec![pool1, pool2];
    println!(
        "Monitoring: {:?}",
        pools_to_monitor
            .iter()
            .map(|p| (&p.exchange_name, p.address))
            .collect::<Vec<_>>()
    );

    // --- Main Arbitrage Detection Loop ---
    // For a real bot, you'd subscribe to new blocks or use a more sophisticated event loop.
    // ethereum_client::subscribe_to_new_blocks(provider.clone()).await?; // Example subscription

    println!("\n--- Starting Arbitrage Detection Loop (runs once for demo) ---");
    // For continuous operation:
    // let mut interval = tokio::time::interval(Duration::from_secs(app_config.poll_interval_seconds));
    // loop {
    //    interval.tick().await;
    //    println!("\n[{:?}] Checking for arbitrage opportunities...", chrono::Utc::now());
    //    match arbitrage_detector::find_arbitrage_opportunities_between_pools(provider.clone(), &pools_to_monitor, weth.clone(), usdc.clone(), app_config.min_profit_threshold_usd.parse()?).await {
    //        Ok(opportunities) => {
    //            if opportunities.is_empty() {
    //                println!("No arbitrage opportunities found in this cycle.");
    //            } else {
    //                for opp in opportunities {
    //                    println!("💰 Arbitrage Opportunity Found: {:?}", opp);
    //                }
    //            }
    //        }
    //        Err(e) => {
    //            eprintln!("Error finding arbitrage: {:?}", e);
    //        }
    //    }
    // }

    // Single run for demonstration:
    match arbitrage_detector::find_arbitrage_opportunities_between_pools(
        provider.clone(),
        &pools_to_monitor,
        weth.clone(), // Base token for price representation
        usdc.clone(), // Quote token for price representation
        app_config.min_profit_threshold_usd.parse().unwrap_or(0.01), // Example threshold
    )
    .await
    {
        Ok(opportunities) => {
            if opportunities.is_empty() {
                println!("🏁 No arbitrage opportunities found in this run.");
            } else {
                for opp in opportunities {
                    println!("💰 Arbitrage Opportunity Found: {:?}", opp);
                    // Here you would add logic to execute the arbitrage if desired and configured
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Error finding arbitrage opportunities: {:?}", e);
        }
    }

    println!("👋 Detector finished.");
    Ok(())
}
