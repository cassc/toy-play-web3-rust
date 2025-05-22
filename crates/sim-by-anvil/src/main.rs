//  Copied from https://github.com/alloy-rs/examples

use std::sync::Arc;

use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    primitives::{U256, address},
    providers::{Provider, ProviderBuilder, ext::AnvilApi},
};
use alloy_node_bindings::Anvil;
use alloy_sol_types::sol;
use eyre::{Context, Result};

sol! {
    #[sol(rpc)]
    interface IWETH {
        function deposit() external payable;
        function withdraw(uint wad) external;
        function approve(address guy, uint wad) external returns (bool);
        function transfer(address dst, uint wad) external returns (bool);
        function transferFrom(address src, address dst, uint wad) external returns (bool);
        function balanceOf(address owner) external view returns (uint);
        function totalSupply() external view returns (uint);
    }
    #[sol(rpc)]
    interface IUniswapV2Router {
        function swapExactTokensForTokens(
            uint amountIn,
            uint amountOutMin,
            address[] calldata path,
            address to,
            uint deadline
        ) external returns (uint[] memory amounts);
        function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);
    }

    #[sol(rpc)]
    interface IPoolAddressesProvider {
        function getPool() external view returns (address);
        function setMarketId(string calldata newMarketId) external;
        function getAddress(bytes32 id) external view returns (address);
    }

    #[sol(rpc)]
    interface IAAVEPool {
       function flashLoanSimple(
           address receiverAddress,
           address asset,
           uint256 amount,
           bytes calldata params,
           uint16 referralCode
       ) external;

       function supply(
           address asset,
           uint256 amount,
           address onBehalfOf,
           uint16 referralCode
       ) external;
    }


    #[sol(rpc, bytecode = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/SimpleFlashLoan.bin")))]
    interface ISimpleFlashLoan{ // this is the contract we will deploy to take flashloan
        constructor(address aavePool);
        function flashLoan(
            address token,
            uint256 amount
        ) external;
        function executeOperation(
            address[] calldata assets,
            uint256[] calldata amounts,
            uint256[] calldata premiums,
            address initiator,
            bytes calldata params
        ) external returns (bool);
    }

}

#[tokio::main]
async fn main() -> Result<()> {
    // Spin up a forked Anvil node.
    // Ensure `anvil` is available in $PATH.
    let rpc_url = "https://reth-ethereum.ithaca.xyz/rpc";
    let anvil = Anvil::new()
        .fork(rpc_url)
        .fork_block_number(22557371)
        .try_spawn()?;

    let user = anvil
        .addresses()
        .get(0)
        .expect("No addresses found from anvil");
    let wallet = anvil.wallet().expect("No wallet found from anvil");
    let aave_pool = address!("0x2f39d218133AFaB8F2B819B1066c7E434Ad94E9e");
    let _uniswap_v2_router = address!("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D");
    let weth = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    let usdc = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    let _dai = address!("0x6B175474E89094C44Da98b954EedeAC495271d0F");

    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(anvil.endpoint_url());

    let provider = Arc::new(provider);

    provider.anvil_impersonate_account(*user).await?;

    let minted_weth = U256::from_str_radix("5_000_000_000_000_000_000", 10).unwrap();

    let weth = IWETH::new(weth, provider.clone());
    weth.deposit()
        .value(minted_weth)
        .send()
        .await
        .context("Depositing WETH failed")?
        .get_receipt()
        .await
        .context("Getting receipt for WETH deposit failed")?;

    let simple_flash_loan = ISimpleFlashLoan::deploy(provider.clone(), aave_pool).await?;

    weth.transfer(*simple_flash_loan.address(), minted_weth)
        .send()
        .await
        .context("Transferring WETH from user to ISimpleFlashLoan failed")?
        .get_receipt()
        .await
        .context("Getting receipt for WETH transfer failed")?;

    let weth_balance = weth
        .balanceOf(*simple_flash_loan.address())
        .call()
        .await
        .context("Getting WETH balance failed")?;

    println!("WETH balance: {weth_balance}");

    assert!(
        weth_balance == minted_weth,
        "Initial WETH balance mismatch: {weth_balance} != {minted_weth}"
    );

    // Get node info using the Anvil API.
    let info = provider.anvil_node_info().await?;

    println!("Node info: {info:#?}");

    assert_eq!(info.environment.chain_id, 1);
    assert_eq!(info.fork_config.fork_url, Some(rpc_url.to_string()));

    // Use the current gas price
    // let gas_price = provider.get_gas_price().await?;

    let tx = simple_flash_loan.flashLoan(
        *weth.address(),
        U256::from_str_radix("1_000_000_000", 10).unwrap(),
    );

    // Estimate gas for the transaction
    let tx_request = tx.clone().into_transaction_request();
    let gas_limit = provider.estimate_gas(tx_request).await?;

    let eip1559_estimation = provider.estimate_eip1559_fees().await?;

    let tx_receipt = tx
        .gas(gas_limit)
        // .gas_price(gas_price)
        .max_fee_per_gas(eip1559_estimation.max_fee_per_gas)
        .max_priority_fee_per_gas(eip1559_estimation.max_priority_fee_per_gas)
        .send()
        .await
        .context("Sending tx failed")?
        .get_receipt()
        .await
        .context("Getting receipt failed")?;

    println!("Transaction receipt: {tx_receipt:#?}");

    let weth_balance = weth
        .balanceOf(*simple_flash_loan.address())
        .call()
        .await
        .context("Getting WETH balance failed")?;

    println!("WETH balance in the end: {weth_balance}");

    let block_number = provider
        .get_block(BlockId::from(BlockNumberOrTag::Latest))
        .await?
        .take()
        .unwrap()
        .header
        .number;
    println!("Block number: {}", block_number); // 22557375

    println!("💯 Flash loan executed successfully!");
    Ok(())
}
