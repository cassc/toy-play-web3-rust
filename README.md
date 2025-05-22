
# **A Playground for Testing Web3 Libraries**

Several toy demos demonstrate the basics of Web3 development using Rust.

> **Note:** Some tests require setting the `ETH_RPC_URL` environment variable to a valid **WebSocket Ethereum node URL**. See `envrc-sample` for an example configuration.

> Most demos were (co)written by AI.

---

## **Elliptic Curve Cryptography (ECC)**
Demonstrates signing and verifying messages using elliptic curve cryptography (ECC) from a raw private key or an **Alloy-rs wallet**.

```bash
cargo run --bin ecc
```

---

## **Keccak256**
Demonstrates `keccak` hashing, including function and event signature generation.

```bash
cargo run --bin keccak
```

---

## **AMM (Automated Market Maker)**
A Rust-based mock of **[Uniswap V2](https://github.com/cassc/uniswap-v2-contracts)**. While Foundry is typically used for simulating AMM contracts, this implementation is fast, simple, and educational.

```bash
cargo run --bin amm
```

---

## **Merkle Tree**
A basic Merkle tree implementation.

⚠ **Warning:** This is **not** the **Merkle Patricia Trie** used in Ethereum—just a simplified Merkle tree.

```bash
cargo run --bin merkle
```

---

## **MPT (Merkle Patricia Trie)**
A demo showing how to compute the **root hash** using block data.

🔹 **Requires:** `ETH_RPC_URL` set to a valid Ethereum node URL (e.g., Infura, Alchemy).

```bash
cargo run --bin mpt
```

---

## **Arbitrage Detector**
A simple arbitrage detector that works **only for pools with identical token pairs and ordering**. Fees are **not** considered.

🔹 **Requires:** `ETH_RPC_URL` set to a **WebSocket Ethereum node URL** (e.g., Infura, Alchemy).

> `crates/arbitrage/src/amm_interactor.rs` demonstrates **on-chain contract interaction** using Alloy-rs `sol!` macros.

```bash
cargo run --bin arbitrage
```

---

## **Simple Transaction Simulation**
This project (copied from **REVM** examples) demonstrates:
1. Pulling account state from the chain.
2. Creating a new in-memory database with the account state.
3. Simulating a transaction.

⚠ **Limitation:** It **does not** fetch missing state data on the fly.

```bash
cargo run --bin sim
```

---

## **Flash Loan Transaction Simulation**
Simulates a flash loan transaction by:
1. Forking Ethereum mainnet using **Anvil**.
2. Deploying the `SimpleFlashLoan` contract (`crates/sim-by-anvil/SimpleFlashLoan.sol`).
3. Calling the `flashLoan` method to execute the flash loan.

> **Note:** Anvil mines a new block after each transaction by default.

```bash
# Compile the deployment binary:
cd crates/sim-by-anvil
~/.solcx/solc-v0.8.10 --bin SimpleFlashLoan.sol -o output
mv output/SimpleFlashLoan.bin ./

cargo run --bin sim-by-anvil
```
