use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use alloy_sol_types::{SolCall, sol};
use eyre::{Context, Result};
use std::sync::Arc; // For building the call

// Define the ABI for Uniswap V2 Pair using alloy::sol_types::sol
// This generates structs and traits for ABI encoding/decoding.
sol! {
    // It's good practice to name the contract/interface uniquely if you might have others
    #[sol(rpc)] // Allows using these calls with RPC providers
    interface IUniswapV2Pair {
        function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
        function token0() external view returns (address);
        function token1() external view returns (address);
        // We can add more functions like `kLast`, `price0CumulativeLast`, etc. if needed
    }
}

sol! {
    #[sol(rpc)]
    interface IUniswapV3Pool {
        function token0() external view returns (address);
        function token1() external view returns (address);
        function fee() external view returns (uint24); // Fee tier of the pool
        function slot0() external view returns (
            uint160 sqrtPriceX96,
            int24 tick,
            uint16 observationIndex,
            uint16 observationCardinality,
            uint16 observationCardinalityNext,
            uint8 feeProtocol,
            bool unlocked
        );
        function liquidity() external view returns (uint128); // Current active liquidity
        // function ticks(int24 tick) external view returns (uint128 liquidityGross, int128 liquidityNet, ...);
        // More functions for ticks, positions, etc. might be needed for full V3 swap simulation
    }
}

pub async fn get_pool_token_addresses(
    provider: Arc<impl Provider>,
    pair_address: Address,
) -> Result<(Address, Address)> {
    let pair = IUniswapV2Pair::new(pair_address, provider.clone());
    let token0_address: Address = pair.token0().call().await?;
    let token1_address: Address = pair.token1().call().await?;

    Ok((token0_address, token1_address))
}

pub async fn get_pool_reserves_and_tokens(
    provider: Arc<impl Provider>,
    pair_address: Address,
) -> Result<(U256, U256, Address, Address)> {
    // reserveA, reserveB, tokenA_addr, tokenB_addr

    let pair = IUniswapV2Pair::new(pair_address, provider.clone());

    let (token0_addr, token1_addr) = get_pool_token_addresses(provider.clone(), pair_address)
        .await
        .context("Failed to get token addresses")?;

    let reserves: IUniswapV2Pair::getReservesReturn = pair
        .getReserves()
        .call()
        .await
        .context("Failed to get reserves")?;

    if token0_addr < token1_addr {
        Ok((
            U256::from(reserves.reserve0),
            U256::from(reserves.reserve1),
            token0_addr, // This is token0's address
            token1_addr, // This is token1's address
        ))
    } else {
        Ok((
            U256::from(reserves.reserve1),
            U256::from(reserves.reserve0),
            token1_addr, // This is token1's address
            token0_addr, // This is token0's address
        ))
    }
}
