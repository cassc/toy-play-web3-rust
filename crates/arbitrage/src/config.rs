use eyre::{Result, WrapErr};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub rpc_url: String,
    pub weth_address: String,
    pub usdc_address: String,
    pub pool1_address: String, // Example: A WETH/USDC pool on Uniswap V2
    pub pool2_address: String, // Example: A WETH/USDC pool on Sushiswap
    pub poll_interval_seconds: u64,
    pub min_profit_threshold_usd: String, // Using string to parse into f64 or a precise decimal type later
                                          // Add private_key here if you plan to execute transactions.
                                          // Ensure it's handled very securely (e.g., from env var, not hardcoded).
                                          // pub private_key: Option<String>,
}

pub fn load_config() -> Result<Config> {
    // Consider using a library like `config` for more complex configurations (e.g., from file + env)
    Ok(Config {
        rpc_url: std::env::var("ETH_RPC_URL").wrap_err("ETH_RPC_URL not set in .env file")?,
        weth_address: std::env::var("WETH_ADDRESS")
            .wrap_err("WETH_ADDRESS not set in .env file")?,
        usdc_address: std::env::var("USDC_ADDRESS")
            .wrap_err("USDC_ADDRESS not set in .env file")?,
        pool1_address: std::env::var("POOL1_ADDRESS")
            .wrap_err("POOL1_ADDRESS not set in .env file")?,
        pool2_address: std::env::var("POOL2_ADDRESS")
            .wrap_err("POOL2_ADDRESS not set in .env file")?,
        poll_interval_seconds: std::env::var("POLL_INTERVAL_SECONDS")
            .unwrap_or_else(|_| "15".to_string()) // Default to 15 seconds
            .parse::<u64>()
            .wrap_err("Invalid POLL_INTERVAL_SECONDS")?,
        min_profit_threshold_usd: std::env::var("MIN_PROFIT_THRESHOLD_USD")
            .unwrap_or_else(|_| "1.0".to_string()), // Default to $1.0 profit
    })
}
