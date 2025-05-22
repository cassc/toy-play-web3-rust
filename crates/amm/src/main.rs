use rust_decimal::Decimal;
use rust_decimal::dec;
use rust_decimal::prelude::*;

// Constants
const FEE_BPS: u64 = 30; // 0.30% trading fee (30 basis points)
const MINIMUM_LIQUIDITY: Decimal = dec!(0.000001); // A tiny amount of LP tokens to burn initially

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Token {
    symbol: String,
    // In a real scenario, this might include contract address, decimals, etc.
}

impl Token {
    fn new(symbol: &str) -> Self {
        Token {
            symbol: symbol.to_string(),
        }
    }
}

#[derive(Debug)]
struct Pool {
    token_a: Token,
    token_b: Token,
    reserve_a: Decimal,
    reserve_b: Decimal,
    total_lp_tokens: Decimal,
    k_last: Decimal, // The constant product x*y=k. This will grow slightly with fees.
    fee: Decimal,    // Fee percentage, e.g., 0.003 for 0.3%
}

impl Pool {
    ///Creates a new liquidity pool with the given tokens and initial reserves.
    pub fn restore(
        token_a: Token,
        token_b: Token,
        initial_amount_a: Decimal,
        initial_amount_b: Decimal,
        // Making MINIMUM_LIQUIDITY a parameter or a well-defined const is better.
        // For now, assuming it's a const defined elsewhere. If not, pass it as an argument.
        // Here, I'll add it as a known constant for the example.
        // In a real scenario, this would be: crate::MINIMUM_LIQUIDITY or similar.
        min_liquidity_param: Decimal, // Parameterizing for clarity
    ) -> Result<(Self, Decimal), String> {
        // Returns (Pool, lp_tokens_for_minter)
        if initial_amount_a <= Decimal::ZERO || initial_amount_b <= Decimal::ZERO {
            return Err("Initial liquidity amounts must be positive.".to_string());
        }

        let k = initial_amount_a * initial_amount_b;

        // Calculate the total potential LP tokens (geometric mean of liquidity)
        // This will be the total_lp_tokens for the pool state, equivalent to Uniswap's `totalSupply()`
        let total_potential_lp = k
            .sqrt()
            .ok_or("Failed to calculate sqrt for initial LP tokens. k might be negative if amounts are strange.".to_string())?;

        if total_potential_lp < min_liquidity_param {
            return Err(format!(
                "Total potential LP tokens ({}) is less than MINIMUM_LIQUIDITY ({}). Provide more initial liquidity.",
                total_potential_lp, min_liquidity_param
            ));
        }

        // The actual LP tokens the first minter receives
        let lp_for_minter = total_potential_lp - min_liquidity_param;

        if lp_for_minter <= Decimal::ZERO {
            return Err(format!(
                "Initial liquidity too small ({} for minter after burning {}). Provide more liquidity.",
                lp_for_minter, min_liquidity_param
            ));
        }

        // The pool's `total_lp_tokens` state reflects the overall minted supply, including the burned part.
        let pool_total_lp_tokens = total_potential_lp;

        Ok((
            Pool {
                token_a,
                token_b,
                reserve_a: initial_amount_a,
                reserve_b: initial_amount_b,
                total_lp_tokens: pool_total_lp_tokens, // This is sqrt(k)
                k_last: k, // k_last is initialized with the first k value
                fee: Decimal::from_u64(FEE_BPS).ok_or("Failed to convert FEE_BPS to Decimal")?
                    / dec!(10000),
            },
            lp_for_minter, // This is the amount the caller (initial LP) actually gets
        ))
    }

    /// Initializes a new liquidity pool.
    /// The first liquidity provider sets the initial price.
    pub fn init(
        token_a: Token,
        token_b: Token,
        initial_amount_a: Decimal,
        initial_amount_b: Decimal,
    ) -> Result<Self, String> {
        if initial_amount_a <= Decimal::ZERO || initial_amount_b <= Decimal::ZERO {
            return Err("Initial liquidity amounts must be positive.".to_string());
        }

        let k = initial_amount_a * initial_amount_b;
        // Initial LP tokens are based on the geometric mean of the initial liquidity.
        // A small amount is "burned" by sending to address 0 in real contracts,
        // here we just subtract it from the first minter's share.
        let initial_lp = k
            .sqrt()
            .ok_or("Failed to calculate sqrt for initial LP tokens")?
            - MINIMUM_LIQUIDITY;

        if initial_lp <= Decimal::ZERO {
            return Err("Initial liquidity too small to create meaningful LP tokens after MINIMUM_LIQUIDITY".to_string());
        }

        Ok(Pool {
            token_a,
            token_b,
            reserve_a: initial_amount_a,
            reserve_b: initial_amount_b,
            total_lp_tokens: initial_lp,
            k_last: k,
            fee: Decimal::from_u64(FEE_BPS).unwrap() / dec!(10000), // e.g., 30/10000 = 0.003
        })
    }

    /// Recalculates and updates k. This should be called after reserves change.
    fn update_k(&mut self) {
        self.k_last = self.reserve_a * self.reserve_b;
    }

    /// Calculates the amount of output token received for a given input amount of input token, without performing the swap.
    /// This considers the fee.
    pub fn calculate_output_amount(
        &self,
        input_token: &Token,
        input_amount: Decimal,
    ) -> Result<Decimal, String> {
        if input_amount <= Decimal::ZERO {
            return Err("Input amount must be positive.".to_string());
        }

        let (reserve_in, reserve_out) = if *input_token == self.token_a {
            (self.reserve_a, self.reserve_b)
        } else if *input_token == self.token_b {
            (self.reserve_b, self.reserve_a)
        } else {
            return Err("Input token not part of this pool.".to_string());
        };

        if reserve_in.is_zero() || reserve_out.is_zero() {
            return Err("Pool has zero reserve for one of the tokens.".to_string());
        }

        // Fee is taken from the input amount
        let input_amount_after_fee = input_amount * (Decimal::ONE - self.fee); // e.g., input * 0.997

        // x * y = k  => (x + dx) * (y - dy) = k
        // dy = y - k / (x + dx_after_fee)
        let numerator = reserve_out * input_amount_after_fee;
        let denominator = reserve_in + input_amount_after_fee;
        // output_amount = (reserve_out * input_amount_after_fee) / (reserve_in + input_amount_after_fee)
        // This is equivalent to: output_amount = reserve_out - (k / (reserve_in + input_amount_after_fee))
        // where k = reserve_in * reserve_out.
        // Let's use the common formula: output_amount = (input_amount_after_fee * reserve_out) / (reserve_in + input_amount_after_fee)
        // This can also be written as:
        // new_reserve_in_effective = reserve_in + input_amount_after_fee
        // new_reserve_out = self.k_last / new_reserve_in_effective
        // output_amount = reserve_out - new_reserve_out
        // Ensure k_last is up to date for this calculation, though it shouldn't change between swaps if calculated correctly.

        let k = reserve_in * reserve_out; // Use current reserves to calculate k for THIS trade
        let new_reserve_out = k / (reserve_in + input_amount_after_fee);
        let output_amount = reserve_out - new_reserve_out;

        if output_amount <= Decimal::ZERO {
            Err(
                "Output amount would be zero or negative (likely due to large fee or tiny input)."
                    .to_string(),
            )
        } else if output_amount > reserve_out {
            // Should not happen with x*y=k
            Err("Calculated output exceeds available reserve.".to_string())
        } else {
            Ok(output_amount)
        }
    }

    /// Performs a swap and updates reserves.
    pub fn swap(
        &mut self,
        input_token_symbol: &str,
        input_amount: Decimal,
    ) -> Result<Decimal, String> {
        let input_token_obj = if input_token_symbol == self.token_a.symbol {
            &self.token_a
        } else if input_token_symbol == self.token_b.symbol {
            &self.token_b
        } else {
            return Err(format!("Token {} not found in pool.", input_token_symbol));
        };

        let output_amount = self.calculate_output_amount(input_token_obj, input_amount)?;

        // Update reserves
        if *input_token_obj == self.token_a {
            self.reserve_a += input_amount;
            self.reserve_b -= output_amount;
        } else {
            self.reserve_b += input_amount;
            self.reserve_a -= output_amount;
        }

        // The k_last constant product increases slightly due to fees effectively being added to reserves.
        self.update_k();
        Ok(output_amount)
    }

    /// Adds liquidity to the pool.
    /// User specifies desired amounts of token A and B.
    /// The amounts actually added will be proportional to the current reserves.
    /// Returns (actual_amount_a_added, actual_amount_b_added, lp_tokens_minted)
    pub fn add_liquidity(
        &mut self,
        desired_amount_a: Decimal,
        desired_amount_b: Decimal,
    ) -> Result<(Decimal, Decimal, Decimal), String> {
        if desired_amount_a <= Decimal::ZERO && desired_amount_b <= Decimal::ZERO {
            return Err("Must provide a positive amount for at least one token.".to_string());
        }
        // This function assumes it's not the first liquidity addition,
        // which is handled by Pool::new implicitly.
        // If it were to handle first addition, it would need a special case like:
        if self.total_lp_tokens.is_zero() || self.reserve_a.is_zero() || self.reserve_b.is_zero() {
            return Err(
                "Pool not initialized or has zero reserves. Use Pool::new for initial liquidity."
                    .to_string(),
            );
        }

        let (actual_amount_a, actual_amount_b);
        // Determine optimal amounts to add based on current ratio and desired amounts
        // amount_b / amount_a = reserve_b / reserve_a
        // So, optimal_b = desired_amount_a * reserve_b / reserve_a
        // And optimal_a = desired_amount_b * reserve_a / reserve_b

        let optimal_b_for_desired_a = desired_amount_a * self.reserve_b / self.reserve_a;

        if desired_amount_b >= optimal_b_for_desired_a {
            // User has enough or more B than needed for their desired A
            actual_amount_a = desired_amount_a;
            actual_amount_b = optimal_b_for_desired_a;
        } else {
            // User has less B than needed for their desired A. So, limit A based on B.
            // desired_amount_b is the limiting factor.
            actual_amount_b = desired_amount_b;
            actual_amount_a = desired_amount_b * self.reserve_a / self.reserve_b;
        }

        if actual_amount_a.is_zero() || actual_amount_b.is_zero() {
            return Err("Calculated deposit amounts are zero. Provide more liquidity relative to pool reserves.".to_string());
        }

        // Calculate LP tokens to mint:
        // (amount_a_added / reserve_a_before) * total_lp_tokens_before
        // OR (amount_b_added / reserve_b_before) * total_lp_tokens_before. They should be equal.
        let lp_mint_ratio_a = actual_amount_a / self.reserve_a;
        // let lp_mint_ratio_b = actual_amount_b / self.reserve_b;
        // assert!((lp_mint_ratio_a - lp_mint_ratio_b).abs() < dec!(0.00000001)); // Should be very close

        let lp_tokens_minted = lp_mint_ratio_a * self.total_lp_tokens;

        if lp_tokens_minted.is_zero() {
            return Err("Not enough liquidity provided to mint any LP tokens.".to_string());
        }

        self.reserve_a += actual_amount_a;
        self.reserve_b += actual_amount_b;
        self.total_lp_tokens += lp_tokens_minted;
        self.update_k();

        Ok((actual_amount_a, actual_amount_b, lp_tokens_minted))
    }

    /// Removes liquidity from the pool.
    /// User specifies the amount of LP tokens to burn.
    /// Returns (amount_a_returned, amount_b_returned)
    pub fn remove_liquidity(
        &mut self,
        lp_tokens_to_burn: Decimal,
    ) -> Result<(Decimal, Decimal), String> {
        if lp_tokens_to_burn <= Decimal::ZERO {
            return Err("LP tokens to burn must be positive.".to_string());
        }
        if lp_tokens_to_burn > self.total_lp_tokens {
            return Err(format!(
                "Cannot burn more LP tokens ({}) than total supply ({}).",
                lp_tokens_to_burn, self.total_lp_tokens
            ));
        }

        let share_to_remove = lp_tokens_to_burn / self.total_lp_tokens;

        let amount_a_out = share_to_remove * self.reserve_a;
        let amount_b_out = share_to_remove * self.reserve_b;

        self.reserve_a -= amount_a_out;
        self.reserve_b -= amount_b_out;
        self.total_lp_tokens -= lp_tokens_to_burn;

        if self.total_lp_tokens.is_zero() {
            // If all liquidity is removed, k might become 0.
            // Real AMMs might burn a MINIMUM_LIQUIDITY to prevent this or handle it.
            // For our simulation, if total_lp_tokens is zero, k should be effectively zero.
            self.k_last = Decimal::ZERO;
        } else {
            self.update_k();
        }

        Ok((amount_a_out, amount_b_out))
    }

    /// Get current price of token_a in terms of token_b (how much B per A)
    pub fn get_price_a_in_b(&self) -> Result<Decimal, String> {
        if self.reserve_a.is_zero() {
            return Err("Reserve A is zero, price undefined.".to_string());
        }
        Ok(self.reserve_b / self.reserve_a)
    }

    /// Get current price of token_b in terms of token_a (how much A per B)
    pub fn get_price_b_in_a(&self) -> Result<Decimal, String> {
        if self.reserve_b.is_zero() {
            return Err("Reserve B is zero, price undefined.".to_string());
        }
        Ok(self.reserve_a / self.reserve_b)
    }

    pub fn print_state(&self, title: &str) {
        println!("\n--- {} ---", title);
        println!(
            "Reserves: {} {}, {} {}",
            self.reserve_a.round_dp(4),
            self.token_a.symbol,
            self.reserve_b.round_dp(4),
            self.token_b.symbol
        );
        println!("Total LP Tokens: {}", self.total_lp_tokens.round_dp(4));
        println!("K (x*y): {}", self.k_last.round_dp(4));
        if let Ok(price) = self.get_price_a_in_b() {
            println!(
                "Price: 1 {} = {} {}",
                self.token_a.symbol,
                price.round_dp(4),
                self.token_b.symbol
            );
        }
        if let Ok(price) = self.get_price_b_in_a() {
            println!(
                "Price: 1 {} = {} {}",
                self.token_b.symbol,
                price.round_dp(4),
                self.token_a.symbol
            );
        }
        println!("--------------------");
    }
}

fn main() {
    // 1. Initialize Tokens
    // https://etherscan.io/address/0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc#readContract
    let token_eth = Token::new("ETH");
    let token_usdc = Token::new("USDC");

    // 2. Initialize Pool
    println!("--- Initializing Pool ---");
    let initial_eth = dec!(1.7102192313899137e+4); // WETH
    let initial_usdc = dec!(45686712.571636); // USDC

    let mut pool = match Pool::init(
        token_eth.clone(),
        token_usdc.clone(),
        initial_eth,
        initial_usdc,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error initializing pool: {}", e);
            return;
        }
    };
    pool.print_state("Pool Initialized");
    // Expected LP tokens: sqrt(eth * usdc) - MIN_LIQUIDITY

    // 3. Simulate a Swap (ETH for USDC)
    println!("\n--- Simulating Swap: 1 ETH for USDC ---");
    let eth_to_swap = dec!(1.0);
    let price_before_swap = pool.get_price_a_in_b().unwrap_or_default();

    match pool.calculate_output_amount(&token_eth, eth_to_swap) {
        Ok(usdc_out_calc) => println!(
            "Calculated: Swapping {} {} would yield approx {} {}",
            eth_to_swap,
            token_eth.symbol,
            usdc_out_calc.round_dp(4),
            token_usdc.symbol
        ),
        Err(e) => println!("Error calculating swap: {}", e),
    }

    match pool.swap(token_eth.symbol.as_str(), eth_to_swap) {
        Ok(usdc_received) => {
            println!(
                "Swapped {} {} for {} {}",
                eth_to_swap,
                token_eth.symbol,
                usdc_received.round_dp(4),
                token_usdc.symbol
            );
            pool.print_state("After Swapping 1 ETH for USDC");
            let price_after_swap = pool.get_price_a_in_b().unwrap_or_default();
            let price_impact =
                ((price_after_swap - price_before_swap) / price_before_swap * dec!(100)).abs();
            println!("Price impact: {:.4}%", price_impact);
        }
        Err(e) => eprintln!("Error during swap: {}", e),
    }
    // Calculation for 1 ETH swap:
    // Fee = 0.3% on 1 ETH = 0.003 ETH. ETH for swap = 1 - 0.003 = 0.997 ETH.
    // Old reserves: 10 ETH, 20000 USDC. k = 200000.
    // New ETH reserve (for k calc): 10 + 0.997 = 10.997 ETH.
    // New USDC reserve (for k calc): 200000 / 10.997 = 18186.7782122 USDC.
    // USDC out: 20000 - 18186.7782122 = 1813.2217878 USDC.
    // Actual final reserves: ETH = 10 + 1 = 11. USDC = 20000 - 1813.2217878 = 18186.7782122 USDC.
    // New k = 11 * 18186.7782122 = 200054.5603342. (k increased due to fee)

    // 4. Simulate another Swap (USDC for ETH) - showing price impact
    println!("\n--- Simulating Swap: 2000 USDC for ETH ---");
    let usdc_to_swap = dec!(2000);
    let price_before_swap2 = pool.get_price_b_in_a().unwrap_or_default();

    match pool.swap(token_usdc.symbol.as_str(), usdc_to_swap) {
        Ok(eth_received) => {
            println!(
                "Swapped {} {} for {} {}",
                usdc_to_swap,
                token_usdc.symbol,
                eth_received.round_dp(6), // More precision for ETH
                token_eth.symbol
            );
            pool.print_state("After Swapping 2000 USDC for ETH");
            let price_after_swap2 = pool.get_price_b_in_a().unwrap_or_default();
            let price_impact2 =
                ((price_after_swap2 - price_before_swap2) / price_before_swap2 * dec!(100)).abs();
            println!("Price impact: {:.4}%", price_impact2);
        }
        Err(e) => eprintln!("Error during swap: {}", e),
    }

    // 5. Add Liquidity
    println!("\n--- Adding Liquidity ---");
    // Current state (approx): ETH: 10.0831, USDC: 20186.7782. Price ~1999 USDC/ETH
    // Let's try to add 2 ETH. The pool will calculate required USDC.
    // Required USDC = 2 * (current_USDC_reserve / current_ETH_reserve)
    let desired_eth_add = dec!(2.0);
    let desired_usdc_add = dec!(5000.0); // Provide more USDC than strictly necessary for 2 ETH to test proportionality

    match pool.add_liquidity(desired_eth_add, desired_usdc_add) {
        Ok((eth_added, usdc_added, lp_minted)) => {
            println!(
                "Added Liquidity: {} {}, {} {}. Received {} LP tokens.",
                eth_added.round_dp(4),
                token_eth.symbol,
                usdc_added.round_dp(4),
                token_usdc.symbol,
                lp_minted.round_dp(4)
            );
            pool.print_state("After Adding Liquidity");
        }
        Err(e) => eprintln!("Error adding liquidity: {}", e),
    }

    // 6. Remove Liquidity
    println!("\n--- Removing Liquidity ---");
    let lp_to_burn = pool.total_lp_tokens / dec!(2); // Remove 50% of current LP tokens
    println!("Attempting to burn {} LP tokens.", lp_to_burn.round_dp(4));

    match pool.remove_liquidity(lp_to_burn) {
        Ok((eth_out, usdc_out)) => {
            println!(
                "Removed Liquidity: Got back {} {} and {} {}",
                eth_out.round_dp(4),
                token_eth.symbol,
                usdc_out.round_dp(4),
                token_usdc.symbol
            );
            pool.print_state("After Removing Liquidity");
        }
        Err(e) => eprintln!("Error removing liquidity: {}", e),
    }
}
