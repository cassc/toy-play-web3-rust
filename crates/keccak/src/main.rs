use alloy::primitives::{B256, U256, utils::keccak256}; // B256 is a 32-byte array, U256 for numbers
use hex; // For displaying byte arrays as hex

// --- Core Hashing Functions ---

/// Computes the Keccak256 hash of a string.
fn hash_string(input: &str) -> B256 {
    keccak256(input.as_bytes())
}

/// Computes the Keccak256 hash of a byte slice.
fn hash_bytes(input: &[u8]) -> B256 {
    keccak256(input)
}

// --- Ethereum Specific Applications ---

/// Derives an Ethereum function selector from a function signature string.
/// Example: "transfer(address,uint256)" -> 0xa9059cbb
fn derive_function_selector(function_signature: &str) -> [u8; 4] {
    let hash = hash_string(function_signature);
    // The selector is the first 4 bytes of the hash
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash[0..4]);
    selector
}

/// Derives an Ethereum event topic (topic0) from an event signature string.
/// Example: "Transfer(address,address,uint256)" -> keccak256 hash
fn derive_event_topic0(event_signature: &str) -> B256 {
    hash_string(event_signature)
}

/// Hashes a U256 value as it would be for an indexed event argument (topic).
/// Indexed arguments (except dynamic types like string/bytes) are padded to 32 bytes and hashed.
fn hash_indexed_u256_argument(value: U256) -> B256 {
    // U256.to_be_bytes() gives a [u8; 32] directly, which is what keccak256 expects
    // for simple value types when they are topics.
    // Note: For actual event topic encoding, the value is directly used if it fits in 32 bytes.
    // Hashing is generally for dynamic types or when the spec requires it.
    // Here, we'll just show the direct 32-byte representation, which is what an indexed uint256 becomes.
    // If you wanted to *hash* the value itself (less common for simple uint256 topics), you'd do:
    // keccak256(value.to_be_bytes::<32>())
    // For an indexed uint256, the value itself (padded to 32 bytes) is the topic.
    B256::from(value.to_be_bytes())
}

fn main() {
    println!("--- Keccak256 Playground ---\n");

    // 1. Hashing simple strings
    println!("Hashing Strings:");
    let str1 = "hello world";
    let hash_str1 = hash_string(str1);
    println!("  Input: \"{}\"", str1);
    println!("  Keccak256: 0x{}", hex::encode(hash_str1));

    let str2 = "alloy-rs is awesome!";
    let hash_str2 = hash_string(str2);
    println!("  Input: \"{}\"", str2);
    println!("  Keccak256: 0x{}", hex::encode(hash_str2));
    println!();

    // 2. Hashing byte arrays
    println!("Hashing Byte Arrays:");
    let bytes1: [u8; 5] = [0x01, 0x02, 0x03, 0x04, 0x05];
    let hash_bytes1 = hash_bytes(&bytes1);
    println!("  Input: 0x{}", hex::encode(bytes1));
    println!("  Keccak256: 0x{}", hex::encode(hash_bytes1));

    // Empty byte array
    let bytes_empty: [u8; 0] = [];
    let hash_bytes_empty = hash_bytes(&bytes_empty);
    println!("  Input (empty): 0x{}", hex::encode(bytes_empty));
    println!("  Keccak256: 0x{}", hex::encode(hash_bytes_empty)); // c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    println!();

    // 3. Deriving Function Selectors
    println!("Deriving Function Selectors:");
    let func_sig1 = "transfer(address,uint256)";
    let selector1 = derive_function_selector(func_sig1);
    println!("  Function Signature: \"{}\"", func_sig1);
    println!("  Selector: 0x{}", hex::encode(selector1)); // Expected: a9059cbb

    let func_sig2 = "balanceOf(address)";
    let selector2 = derive_function_selector(func_sig2);
    println!("  Function Signature: \"{}\"", func_sig2);
    println!("  Selector: 0x{}", hex::encode(selector2)); // Expected: 70a08231
    println!();

    // 4. Deriving Event Topics (Topic0)
    println!("Deriving Event Topics (Topic0):");
    let event_sig1 = "Transfer(address,address,uint256)";
    let topic0_1 = derive_event_topic0(event_sig1);
    println!("  Event Signature: \"{}\"", event_sig1);
    println!("  Topic0: 0x{}", hex::encode(topic0_1)); // Expected: ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef

    let event_sig2 = "Approval(address,address,uint256)";
    let topic0_2 = derive_event_topic0(event_sig2);
    println!("  Event Signature: \"{}\"", event_sig2);
    println!("  Topic0: 0x{}", hex::encode(topic0_2)); // Expected: 8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925
    println!();

    // 5. Indexed Event Argument (U256 as topic)
    // For indexed arguments that are not dynamic types (like uint256, address, bool, fixed-size bytes arrays),
    // the value itself, padded to 32 bytes, is used as the topic. It is not typically hashed again.
    println!("Indexed Event Arguments (U256 value as topic):");
    let u256_val1 = U256::from(12345);
    let topic_u256_1 = hash_indexed_u256_argument(u256_val1); // In this case, it's just the value padded
    println!("  Input U256: {}", u256_val1);
    println!(
        "  As Topic (32-byte value): 0x{}",
        hex::encode(topic_u256_1)
    );

    let u256_val2 = U256::from_str_radix("deadbeefcafebabe", 16).unwrap();
    let topic_u256_2 = hash_indexed_u256_argument(u256_val2);
    println!(
        "  Input U256: {} (0x{})",
        u256_val2,
        hex::encode(u256_val2.to_be_bytes::<32>().as_ref())
    );
    println!(
        "  As Topic (32-byte value): 0x{}",
        hex::encode(topic_u256_2)
    );
    println!();

    // Example of hashing a dynamic type for an indexed event argument (e.g. string)
    println!("Indexed Event Arguments (hashed dynamic type like string):");
    let dynamic_string_value = "This is an indexed string";
    let topic_dynamic_string = hash_string(dynamic_string_value); // For indexed strings/bytes, their Keccak256 hash is the topic
    println!("  Input string: \"{}\"", dynamic_string_value);
    println!(
        "  As Topic (Keccak256 of string): 0x{}",
        hex::encode(topic_dynamic_string)
    );

    println!("\n--- End of Playground ---");
}
