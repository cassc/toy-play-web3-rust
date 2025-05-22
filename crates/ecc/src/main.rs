use alloy::primitives::{Address, B256, Signature, hex, utils};
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;
use k256::ecdsa::Signature as ECDSASignature;
use k256::ecdsa::SigningKey;
use k256::ecdsa::signature::Signer;
use k256::ecdsa::signature::Verifier;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::str::FromStr;

use eyre::Result;

// This function is also available in the alloy-rs library
#[allow(dead_code)]
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// Helper function for Ethereum's personal_sign message hashing
fn eth_message_hash(message: &str) -> [u8; 32] {
    // Prefix defined by EIP-191: "\x19Ethereum Signed Message:\n" + message.length
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message.as_bytes());
    hasher.finalize().into() // .into() converts GenericArray<u8, N> to [u8; N]
}

// If the recovery process successfully computes a public key (hence the address), it means the signature is valid.
pub fn recover_eth_address_alloy(message: &str, sig_hex: &str) -> Option<Address> {
    // 1. Decode the hex-encoded signature string.
    //    `strip_prefix` handles optional "0x".
    //    `alloy_primitives::hex::decode` is a re-export of the `hex` crate's decode.
    let sig_bytes_vec = hex::decode(sig_hex.strip_prefix("0x").unwrap_or(sig_hex)).ok()?;

    // 2. Parse the byte slice into an `alloy_primitives::Signature`.
    //    `Signature::try_from` expects a 65-byte slice: [R (32 bytes), S (32 bytes), V (1 byte)].
    //    It correctly handles V values of 0, 1, 27, or 28 (standard for Ethereum non-EIP155 and y-parity).
    //    If `sig_bytes_vec` is not 65 bytes, or V is invalid, this will return an error (and thus None).
    let signature = Signature::try_from(sig_bytes_vec.as_slice()).ok()?;

    // 3. Hash the message according to EIP-191 (standard for "personal_sign").
    //    `alloy_primitives::utils::eip191_hash_message` creates the prefixed hash:
    //    keccak256("\x19Ethereum Signed Message:\n" + message.length + message)
    let message_hash: B256 = utils::eip191_hash_message(message);

    // 4. Recover the signer's address from the signature and the pre-computed message hash.
    //    `recover_signer_from_prehash` returns a `Result<Address, SignatureError>`.
    //    `.ok()` converts this to `Option<Address>`.
    signature.recover_address_from_prehash(&message_hash).ok()
}

fn main() -> Result<()> {
    println!("--- ECC Sign & Verify using k256 library (secp256k1) ---");

    // 1. Key Generation
    // SigningKey is the private key
    let mut rng = rand::thread_rng();
    let private_key: SigningKey = SigningKey::random(&mut rng); // Securely generates a new private key

    // VerifyingKey is the public key, derived from the private key
    let public_key = private_key.verifying_key();

    println!("\nGenerated Keys:");
    // Note: Private keys are sensitive, typically not printed or logged.
    // For educational purposes, we might show its byte representation (but be careful!)
    let private_key_bytes = private_key.to_bytes();
    println!("  Private Key (bytes): {}", hex::encode(private_key_bytes));

    // Public keys are often represented in compressed or uncompressed SEC1 format
    let public_key_sec1_compressed = public_key.to_encoded_point(true); // true for compressed
    let public_key_sec1_uncompressed = public_key.to_encoded_point(false); // false for uncompressed

    println!(
        "  Public Key (SEC1 Compressed): {}",
        hex::encode(&public_key_sec1_compressed)
    );
    println!(
        "  Public Key (SEC1 Uncompressed): {}",
        hex::encode(&public_key_sec1_uncompressed)
    );

    // 2. Message to Sign
    let message = b"Hello, k256 ECC world!";
    println!("\nMessage: {}", String::from_utf8_lossy(message));

    // 3. Hashing the Message (ECDSA signs the hash of the message)
    // While k256::ecdsa::Signer can take a prehashed message,
    // it's common to hash it first with a standard like SHA-256.
    // The `k256` crate with `sha256` feature can often handle this internally
    // if you pass the message directly to `sign`, but let's be explicit.
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash = hasher.finalize(); // This is a GenericArray<u8, U32>

    println!("  Message Hash (SHA256): {}", hex::encode(&message_hash));

    // 4. Signing the Message Hash
    // The `Signer` trait is implemented for `SigningKey`.
    // It will produce a recoverable signature by default if the necessary features are enabled.
    // For a standard non-recoverable signature:
    let signature: ECDSASignature = private_key.sign(&message_hash);
    // If you wanted to sign the message directly (library handles hashing):
    // let signature: Signature = private_key.sign(message);

    println!(
        "\nSignature (ASN.1 DER encoded): {}",
        hex::encode(signature.to_der())
    );
    // Signatures are often represented as (r, s) components.
    // The `k256::ecdsa::Signature` type can be converted to these components if needed,
    // but DER encoding is a common standard.

    // 5. Verification
    // The `Verifier` trait is implemented for `VerifyingKey`.
    println!("\nVerification Process:");
    match public_key.verify(&message_hash, &signature) {
        // Or if you signed the message directly:
        // match public_key.verify(message, &signature) {
        Ok(_) => println!("  Signature is VALID!"),
        Err(e) => println!("  Signature is INVALID: {}", e),
    }

    // Create an sign an Ethereum personal_sign message
    println!("\nAttempting to verify custom message signed:");
    let personal_message = "Hello, Ethereum!";
    let message_hash = eth_message_hash(personal_message);
    let personal_signature = private_key.sign_recoverable(&message_hash).unwrap();
    let k256_sig_rs_only = personal_signature.0;
    let recovery_id = personal_signature.1;

    let s_bytes = k256_sig_rs_only.s().to_bytes();
    let r_bytes = k256_sig_rs_only.r().to_bytes();
    let v_byte = recovery_id.to_byte() + 27; // Adjust for Ethereum's V value

    let mut signature_rsv_bytes = [0u8; 65];
    signature_rsv_bytes[0..32].copy_from_slice(&r_bytes);
    signature_rsv_bytes[32..64].copy_from_slice(&s_bytes);
    signature_rsv_bytes[64] = v_byte;

    let personal_signature_hex = hex::encode(signature_rsv_bytes);

    let recovered_address = recover_eth_address_alloy(personal_message, &personal_signature_hex);
    match recovered_address {
        Some(address) => println!(
            "  Recovered address from custom signed message: {} (Correct!)",
            address
        ),
        None => println!("  Failed to recover address from custom signed message (Incorrect!)"),
    }

    // 6. Attempt to verify with a tampered message
    let tampered_message = b"Hello, tampered k256 ECC world!";
    let mut tampered_hasher = Sha256::new();
    tampered_hasher.update(tampered_message);
    let tampered_message_hash = tampered_hasher.finalize();

    println!("\nAttempting to verify tampered message with original signature:");
    match public_key.verify(&tampered_message_hash, &signature) {
        Ok(_) => println!("  Tampered message verification: VALID (ERROR! This should not happen)"),
        Err(_) => println!("  Tampered message verification: INVALID (Correct!)"),
    }

    // 7. Attempt to verify with a different public key
    let another_private_key = SigningKey::random(&mut rng);
    let another_public_key = another_private_key.verifying_key();

    println!("\nAttempting to verify original message and signature with a different public key:");
    match another_public_key.verify(&message_hash, &signature) {
        Ok(_) => {
            println!("  Different public key verification: VALID (ERROR! This should not happen)")
        }
        Err(_) => println!("  Different public key verification: INVALID (Correct!)"),
    }

    // 8. Verifiy a signature signed on chain, no knowledge of the private key
    // https://etherscan.io/verifySig/273429
    println!("\nVerifying a signature signed on chain from https://etherscan.io/verifySig/273453");
    let signature_hash = "0x689d956481c40f52da7b530ec652ee270545f20086144dff63a343263f4905750c1b1f6f8d45cd15506371e574204c70294b3f5c417d267fb3f8c6429afdadd81c";
    let message = "@mteamisloading looking to participate in Lido Dual Governance Tiebreaker committee with the address 0xb04b6fb471e766d7f21a6aa0e4e25b2aea0a75ab";
    let address = Address::from_str("0xb04b6fb471e766d7f21a6aa0e4e25b2aea0a75ab").unwrap();

    match recover_eth_address_alloy(message, signature_hash) {
        Some(recovered_address) => {
            if recovered_address == address {
                println!(
                    "  Signature recovery successful! Address matches: {}",
                    recovered_address
                );
            } else {
                println!(
                    "  Signature recovery successful! Address does NOT match: {} != {}",
                    recovered_address, address
                );
            }
        }
        None => println!("  Signature recovery failed!"),
    }

    // 9. Sign and verify using alloy-rs library
    println!("\n--- ECC Sign & Verify using alloy-rs library ---");
    let signing_key = SigningKey::from_bytes(&private_key_bytes).unwrap();
    let wallet: PrivateKeySigner = signing_key.clone().into();
    let address = wallet.address();
    let message = "Hello, alloy-rs world!";
    let signature = wallet.sign_message_sync(message.as_bytes()).unwrap(); // Sign the message after adding the EIP-191 prefix
    let signed_message = signature.as_bytes();
    match recover_eth_address_alloy(&message, &hex::encode(signed_message)) {
        Some(recovered_address) => {
            if recovered_address == address {
                println!(
                    "  Alloy-rs Signature recovery successful! Address matches: {} (Correct!)",
                    recovered_address
                );
            } else {
                println!(
                    "  Alloy-rs Signature recovery successful! Address does NOT match: {} != {} (Incorrect!)",
                    recovered_address, address
                );
            }
        }
        None => println!("  Alloy-rs Signature recovery failed! (Incorrect!)"),
    }

    Ok(())
}
