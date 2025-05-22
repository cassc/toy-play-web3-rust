use alloy::eips::BlockNumberOrTag;
use alloy::primitives::B256;

use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{BlockTransactions, Transaction};
use dotenvy::dotenv;
use eyre::{Context, Result, bail, eyre};
use hex;
use std::env;
use url::Url;

// Root hash of an empty MPT, specifically keccak256(rlp_encode("")) == keccak256(0x80)
// This is the standard empty root for Ethereum tries (state, transaction, receipt).
const EMPTY_MPT_ROOT_HASH: B256 = B256::new([
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
]);

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok(); // Load .env file

    let rpc_url_str = env::var("ETH_RPC_URL").context("ETH_RPC_URL not found in .env file.")?;
    let rpc_url = Url::parse(&rpc_url_str)?;

    println!("Using RPC URL: {}", rpc_url);

    // --- 1. Setup Ethereum Provider ---
    let provider = ProviderBuilder::new().connect_http(rpc_url);

    // --- 2. Fetch a Block WITH FULL TRANSACTIONS ---
    // Block 19,000,000 on Ethereum Mainnet (has transactions)
    let block_number_to_fetch = 19_000_000u64;
    // Or a block with fewer transactions for faster demo, e.g., block 17_000_000
    // let block_number_to_fetch = 17_000_000u64;
    // Or a block known to have 0 transactions for testing that edge case.
    // E.g. Block 14_000_001 (check etherscan, it has 0 tx)
    // let block_number_to_fetch = 14_000_001u64;

    println!("\nFetching block number: {}", block_number_to_fetch);

    // Second argument `true` requests full transaction objects
    let block_opt = provider
        .get_block_by_number(BlockNumberOrTag::Number(block_number_to_fetch))
        .full()
        .await?;

    let block = block_opt.ok_or_else(|| eyre!("Block {} not found", block_number_to_fetch))?;

    println!(
        "Fetched Block Hash: 0x{}",
        hex::encode(block.header.hash.as_slice())
    );
    let official_transactions_root = block.header.transactions_root;
    println!(
        "Official Block Transactions Root (MPT from header): 0x{}",
        hex::encode(official_transactions_root.as_slice())
    );

    // --- 3. Extract Full Transaction Objects and Prepare MPT Leaves ---
    let transactions: Vec<Transaction> = match block.transactions {
        BlockTransactions::Full(txs) => txs,
        BlockTransactions::Hashes(_) => {
            bail!(
                "Expected full transaction objects, but got only hashes. Ensure get_block_by_number requests full transactions."
            );
        }
        BlockTransactions::Uncle => {
            // This means the block only contains uncle headers, not regular transactions.
            // This can happen for certain blocks.
            println!(
                "Block {} contains only uncle information, no standard transactions.",
                block_number_to_fetch
            );
            Vec::new() // Treat as no transactions
        }
    };

    // --- 4. Build the Merkle Patricia Trie (MPT) ---
    // We need a mutable storage backend for the trie. MemStorage is an in-memory one.

    println!("\nBuilding MPT from {} transactions:", transactions.len());

    for (index, tx) in transactions.iter().enumerate() {
        println!(
            "  Tx {}: 0x{}",
            index,
            hex::encode(tx.info().hash.expect("Tx has no hash").as_slice())
        );
        // todo create a MPT from the transactions
    }

    println!("\nCalculated MPT Root: 0x{}", "TODO");
    println!(
        "Official Block Tx Root:  0x{}",
        hex::encode(official_transactions_root.as_slice())
    );

    println!("\nFull MPT transaction validation and proof demonstration complete.");
    Ok(())
}
