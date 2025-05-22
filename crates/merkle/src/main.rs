use hex;
use sha2::{Digest, Sha256}; // Optional for displaying hashes

// Represents a node in the Merkle tree.
// For simplicity, we'll just store the hash.
// Leaves will have the hash of the data, internal nodes will have the hash of their children.
#[derive(Debug, Clone, PartialEq, Eq, Hash)] // Added Hash for potential use in Sets/Maps
pub struct Node {
    pub hash: Vec<u8>,
}

// Represents a Merkle Proof.
// It contains the leaf hash and the path of sibling hashes needed to reconstruct the root.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf_hash: Vec<u8>,
    /// Path of sibling hashes from leaf to root.
    /// Each tuple: (sibling_hash, is_sibling_on_the_left_side_of_path_node)
    pub path: Vec<(Vec<u8>, bool)>,
}

// The Merkle Tree itself.
#[derive(Debug)]
pub struct MerkleTree {
    pub root: Node,
    /// Layers of nodes, from leaves (index 0) up to the root layer.
    /// layers[0] = leaves
    /// layers[layers.len() - 1] = [root_node]
    pub layers: Vec<Vec<Node>>,
}

// Helper function to hash data (e.g., a transaction string)
fn hash_data(data: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hasher.finalize().to_vec()
}

// Helper function to hash two concatenated hashes
// Convention: hash(left_child_hash | right_child_hash)
fn hash_pair(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

impl MerkleTree {
    /// Builds a Merkle tree from a list of data items (strings in this case).
    pub fn new(data_items: &[String]) -> Result<Self, String> {
        if data_items.is_empty() {
            return Err("Cannot build Merkle tree with no data items.".to_string());
        }

        // 1. Create leaf nodes
        let leaves: Vec<Node> = data_items
            .iter()
            .map(|item| Node {
                hash: hash_data(item),
            })
            .collect();

        // This check is technically redundant due to the initial data_items.is_empty() check,
        // but it's a good safeguard if the mapping somehow resulted in an empty list.
        if leaves.is_empty() {
            return Err("Leaf creation resulted in no leaves, unexpectedly.".to_string());
        }

        let mut tree_layers: Vec<Vec<Node>> = vec![leaves.clone()];
        let mut current_layer_nodes = leaves;

        // 2. Build the tree layer by layer
        while current_layer_nodes.len() > 1 {
            let mut next_layer_nodes = Vec::new();
            let mut i = 0;
            while i < current_layer_nodes.len() {
                let left_node = &current_layer_nodes[i];
                // If there's an odd number of nodes, duplicate the last one to pair it with itself
                let right_node = if i + 1 < current_layer_nodes.len() {
                    &current_layer_nodes[i + 1]
                } else {
                    left_node // Duplicate the last node
                };
                let parent_hash = hash_pair(&left_node.hash, &right_node.hash);
                next_layer_nodes.push(Node { hash: parent_hash });
                i += 2;
            }
            current_layer_nodes = next_layer_nodes;
            tree_layers.push(current_layer_nodes.clone());
        }

        // The last layer will contain the single root node.
        // This unwrap is safe because the loop `while current_layer_nodes.len() > 1` ensures
        // `current_layer_nodes` will eventually have length 1, and it's pushed to `tree_layers`.
        // The `[0]` access is safe because a layer with one node has an element at index 0.
        let root_node = tree_layers.last().unwrap()[0].clone();

        Ok(MerkleTree {
            root: root_node,
            layers: tree_layers,
        })
    }

    /// Generates a Merkle proof for a data item at a given leaf index.
    pub fn generate_proof(&self, item_index: usize) -> Option<MerkleProof> {
        if self.layers.is_empty() || item_index >= self.layers[0].len() {
            return None; // Index out of bounds or tree is not initialized properly
        }

        let leaf_hash = self.layers[0][item_index].hash.clone();
        let mut proof_path = Vec::new();
        let mut current_node_index_in_layer = item_index;

        // Iterate through layers from leaves up to the layer just before the root
        // self.layers.len() - 1 is the index of the root layer.
        // The loop goes up to, but does not include, the root layer.
        for layer_idx in 0..(self.layers.len() - 1) {
            let current_layer = &self.layers[layer_idx];
            let is_current_node_left = current_node_index_in_layer % 2 == 0;

            let sibling_node_index_in_layer;
            if is_current_node_left {
                sibling_node_index_in_layer = current_node_index_in_layer + 1;
            } else {
                sibling_node_index_in_layer = current_node_index_in_layer - 1;
            }

            // Get sibling hash.
            // If sibling_node_index_in_layer is out of bounds, it means the current_node_index_in_layer
            // was the last element of an odd-length layer, and it was paired with itself (duplicated).
            // In this case, its "sibling" for the proof is its own hash.
            let sibling_hash = if sibling_node_index_in_layer < current_layer.len() {
                current_layer[sibling_node_index_in_layer].hash.clone()
            } else {
                // This node was the last in an odd-numbered list and was duplicated.
                // Its "sibling" in the pairing was itself.
                current_layer[current_node_index_in_layer].hash.clone()
            };

            // The boolean indicates if the SIBLING_HASH is on the LEFT side of the pair
            // that forms the parent.
            // If current_node_index_in_layer is a left child (even), its sibling is on the right (so is_sibling_left is false).
            // If current_node_index_in_layer is a right child (odd), its sibling is on the left (so is_sibling_left is true).
            let is_sibling_left = !is_current_node_left;
            proof_path.push((sibling_hash, is_sibling_left));

            // Move to the parent's index in the next layer up
            current_node_index_in_layer /= 2;
        }

        Some(MerkleProof {
            leaf_hash,
            path: proof_path,
        })
    }

    /// Verifies a Merkle proof against the Merkle root.
    pub fn verify_proof(root_hash: &[u8], proof: &MerkleProof) -> bool {
        let mut current_computed_hash = proof.leaf_hash.clone();

        for (sibling_hash_in_path, is_sibling_on_left) in &proof.path {
            current_computed_hash = if *is_sibling_on_left {
                // Sibling is on the left, current_computed_hash is on the right
                hash_pair(sibling_hash_in_path, &current_computed_hash)
            } else {
                // Sibling is on the right, current_computed_hash is on the left
                hash_pair(&current_computed_hash, sibling_hash_in_path)
            };
        }
        current_computed_hash == root_hash
    }

    /// Bonus: Simple text visualization of the tree (hashes).
    pub fn visualize(&self) {
        println!("\nMerkle Tree Visualization (Root to Leaves):");
        if self.layers.is_empty() {
            println!("Tree is empty or not initialized.");
            return;
        }
        for (i, layer_nodes) in self.layers.iter().rev().enumerate() {
            let layer_num_from_root = i;
            let layer_num_from_leaves = self.layers.len() - 1 - layer_num_from_root;

            let mut layer_label = format!("Layer {} (from leaves)", layer_num_from_leaves);
            if layer_num_from_leaves == self.layers.len() - 1 {
                layer_label.push_str(" [Root]");
            } else if layer_num_from_leaves == 0 {
                layer_label.push_str(" [Leaves]");
            } else {
                layer_label.push_str(" [Intermediate]");
            }

            print!("{}: ", layer_label);
            for node in layer_nodes {
                // Print first 4 bytes of hash for brevity
                print!(
                    "{} | ",
                    hex::encode(&node.hash[0..std::cmp::min(4, node.hash.len())])
                );
            }
            println!();
        }
        println!("Full Root Hash: {}", hex::encode(&self.root.hash));
    }
}

// Main function to demonstrate Merkle Tree usage
fn main() {
    println!("Simple Merkle Tree Builder & Prover");

    // 1. Define some sample data
    let data_items = vec![
        "Transaction A".to_string(),
        "Transaction B".to_string(),
        "Transaction C".to_string(),
        "Transaction D".to_string(),
        "Transaction E".to_string(),
    ];
    println!("\nOriginal Data Items: {:?}", data_items);

    // 2. Build the Merkle Tree
    match MerkleTree::new(&data_items) {
        Ok(tree) => {
            println!("\nMerkle Tree built successfully!");
            tree.visualize();

            // 3. Generate a proof for a specific item
            let item_to_prove_index = 2; // Let's prove "Transaction C"
            if item_to_prove_index < data_items.len() {
                let item_to_prove = &data_items[item_to_prove_index];
                println!(
                    "\nAttempting to generate proof for item at index {}: '{}'",
                    item_to_prove_index, item_to_prove
                );

                match tree.generate_proof(item_to_prove_index) {
                    Some(proof) => {
                        println!("Proof generated successfully.");
                        println!(
                            "  Leaf Hash (for '{}'): {}",
                            item_to_prove,
                            hex::encode(&proof.leaf_hash)
                        );
                        println!("  Proof Path (sibling_hash, is_sibling_left):");
                        for (i, (sibling_hash, is_left)) in proof.path.iter().enumerate() {
                            println!(
                                "    {}: ({}, {})",
                                i,
                                hex::encode(&sibling_hash[0..4]),
                                is_left
                            );
                        }

                        // 4. Verify the proof
                        let is_valid = MerkleTree::verify_proof(&tree.root.hash, &proof);
                        println!("\nIs the proof valid? {}", is_valid);
                        if !is_valid {
                            println!("Verification FAILED!");
                        }

                        // Demonstrate an invalid proof (e.g., with a tampered leaf)
                        let mut tampered_proof = proof.clone();
                        tampered_proof.leaf_hash = hash_data("Tampered Transaction");
                        let is_tampered_valid =
                            MerkleTree::verify_proof(&tree.root.hash, &tampered_proof);
                        println!("\nIs the tampered proof valid? {}", is_tampered_valid);
                    }
                    None => {
                        println!(
                            "Could not generate proof for item at index {}.",
                            item_to_prove_index
                        );
                    }
                }
            } else {
                println!(
                    "\nCannot generate proof: Index {} is out of bounds for data items (len {}).",
                    item_to_prove_index,
                    data_items.len()
                );
            }
        }
        Err(e) => {
            eprintln!("Error building Merkle Tree: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_sample_data(count: usize) -> Vec<String> {
        (0..count).map(|i| format!("tx{}", i + 1)).collect()
    }

    #[test]
    fn test_construction_even_items() {
        let data = get_sample_data(4); // tx1, tx2, tx3, tx4
        let tree = MerkleTree::new(&data).expect("Tree construction failed");
        assert!(!tree.root.hash.is_empty(), "Root hash should not be empty");
        tree.visualize();
        // Expected structure:
        // Layer 2 [Root]: H(H(H(tx1,tx2),H(tx3,tx4))) |
        // Layer 1 [Intermediate]: H(H(tx1,tx2)) | H(H(tx3,tx4)) |
        // Layer 0 [Leaves]: H(tx1) | H(tx2) | H(tx3) | H(tx4) |
        assert_eq!(tree.layers.len(), 3); // Leaves, 1 intermediate, root
        assert_eq!(tree.layers[0].len(), 4); // 4 leaves
        assert_eq!(tree.layers[1].len(), 2); // 2 nodes in intermediate layer
        assert_eq!(tree.layers[2].len(), 1); // 1 root node
    }

    #[test]
    fn test_construction_odd_items() {
        let data = get_sample_data(3); // tx1, tx2, tx3
        let tree = MerkleTree::new(&data).expect("Tree construction failed");
        assert!(!tree.root.hash.is_empty());
        tree.visualize();
        // Expected structure:
        // Layer 2 [Root]: H(H(H(tx1,tx2),H(tx3,tx3))) |
        // Layer 1 [Intermediate]: H(H(tx1,tx2)) | H(H(tx3,tx3)) |
        // Layer 0 [Leaves]: H(tx1) | H(tx2) | H(tx3) |
        assert_eq!(tree.layers.len(), 3);
        assert_eq!(tree.layers[0].len(), 3);
        assert_eq!(tree.layers[1].len(), 2); // H(tx1,tx2), H(tx3,tx3)
        assert_eq!(tree.layers[2].len(), 1);
    }

    #[test]
    fn test_construction_single_item() {
        let data = get_sample_data(1); // tx1
        let tree = MerkleTree::new(&data).expect("Tree construction failed");
        tree.visualize();
        assert_eq!(tree.root.hash, hash_data("tx1"));
        assert_eq!(tree.layers.len(), 1); // Only leaf layer, which is also the root layer
        assert_eq!(tree.layers[0].len(), 1);
    }

    #[test]
    fn test_proof_generation_and_verification_even() {
        let data = get_sample_data(4); // tx1, tx2, tx3, tx4
        let tree = MerkleTree::new(&data).expect("Tree construction failed");
        tree.visualize();

        for i in 0..data.len() {
            println!("\nGenerating and verifying proof for: {}", data[i]);
            let proof = tree
                .generate_proof(i)
                .expect(&format!("Failed to generate proof for item {}", i));

            println!("  Leaf Hash: {}", hex::encode(&proof.leaf_hash));
            for (idx, (hash, on_left)) in proof.path.iter().enumerate() {
                println!(
                    "  Sibling {}: {} (is_left: {})",
                    idx,
                    hex::encode(&hash[0..4]),
                    on_left
                );
            }

            assert_eq!(
                proof.leaf_hash,
                hash_data(&data[i]),
                "Leaf hash in proof does not match original data hash for item {}",
                i
            );
            assert!(
                MerkleTree::verify_proof(&tree.root.hash, &proof),
                "Proof verification failed for item {}",
                i
            );
        }
    }

    #[test]
    fn test_proof_generation_and_verification_odd() {
        let data = get_sample_data(5); // tx1, tx2, tx3, tx4, tx5
        let tree = MerkleTree::new(&data).expect("Tree construction failed");
        tree.visualize();

        for i in 0..data.len() {
            println!("\nGenerating and verifying proof for: {}", data[i]);
            let proof = tree
                .generate_proof(i)
                .expect(&format!("Failed to generate proof for item {}", i));
            assert_eq!(
                proof.leaf_hash,
                hash_data(&data[i]),
                "Leaf hash mismatch for item {}",
                i
            );
            assert!(
                MerkleTree::verify_proof(&tree.root.hash, &proof),
                "Proof verification failed for item {}",
                i
            );
        }
    }

    #[test]
    fn test_proof_for_single_item_tree() {
        let data = get_sample_data(1); // tx1
        let tree = MerkleTree::new(&data).expect("Tree construction failed");
        let proof = tree
            .generate_proof(0)
            .expect("Proof generation failed for single item");

        assert_eq!(proof.leaf_hash, hash_data("tx1"));
        assert!(
            proof.path.is_empty(),
            "Proof path for single item tree should be empty"
        );
        assert!(
            MerkleTree::verify_proof(&tree.root.hash, &proof),
            "Proof verification failed for single item tree"
        );
    }

    #[test]
    fn test_invalid_proof_wrong_root() {
        let data1 = get_sample_data(3);
        let tree1 = MerkleTree::new(&data1).unwrap();

        let data2 = vec![
            "itemA".to_string(),
            "itemB".to_string(),
            "itemC".to_string(),
        ];
        let tree2 = MerkleTree::new(&data2).unwrap(); // Different tree, different root

        let proof_from_tree1 = tree1.generate_proof(0).unwrap();

        // Try to verify proof from tree1 against root of tree2
        assert!(
            !MerkleTree::verify_proof(&tree2.root.hash, &proof_from_tree1),
            "Proof should be invalid with wrong root"
        );
    }

    #[test]
    fn test_invalid_proof_tampered_leaf() {
        let data = get_sample_data(4);
        let tree = MerkleTree::new(&data).unwrap();
        let mut proof = tree.generate_proof(1).unwrap(); // Proof for "tx2"

        // Tamper the leaf hash in the proof
        proof.leaf_hash = hash_data("not_tx2");

        assert!(
            !MerkleTree::verify_proof(&tree.root.hash, &proof),
            "Proof should be invalid with tampered leaf hash"
        );
    }

    #[test]
    fn test_invalid_proof_tampered_path() {
        let data = get_sample_data(4);
        let tree = MerkleTree::new(&data).unwrap();
        let mut proof = tree.generate_proof(0).unwrap(); // Proof for "tx1"

        if !proof.path.is_empty() {
            // Tamper one of the sibling hashes in the path
            proof.path[0].0 = hash_data("tampered_sibling_hash");
        } else {
            // This case shouldn't happen for a 4-item tree, but good to be aware
            println!("Proof path is empty, cannot tamper path for this test.");
            return;
        }

        assert!(
            !MerkleTree::verify_proof(&tree.root.hash, &proof),
            "Proof should be invalid with tampered path hash"
        );
    }

    #[test]
    fn test_empty_data_input() {
        let data: Vec<String> = vec![];
        assert!(
            MerkleTree::new(&data).is_err(),
            "Tree construction with empty data should return an error"
        );
    }

    #[test]
    fn test_generate_proof_out_of_bounds_index() {
        let data = get_sample_data(2);
        let tree = MerkleTree::new(&data).unwrap();
        assert!(
            tree.generate_proof(2).is_none(),
            "Generating proof for out-of-bounds index should return None"
        );
        assert!(
            tree.generate_proof(100).is_none(),
            "Generating proof for far out-of-bounds index should return None"
        );
    }
}
