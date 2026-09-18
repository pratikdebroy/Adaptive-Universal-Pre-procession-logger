use crate::models::ProvenanceRecord;
use chrono::Utc;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Cryptographic audit proof for verifying a leaf against a Merkle root.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_hash: String,
    /// Vector of (sibling_hash, is_left_sibling)
    pub audit_path: Vec<(String, bool)>,
    pub root_hash: String,
}

/// Computes SHA-256 hash of two concatenated byte slices.
fn hash_pair(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

/// Micro-batch Merkle Tree builder and local provenance ledger adapter.
pub struct MerkleTree {
    pub batch_size: usize,
    leaves: Vec<Vec<u8>>,
    db_conn: Arc<Mutex<Connection>>,
    batch_counter: u64,
}

impl MerkleTree {
    /// Initialize with batch size (default 500) and embedded ledger file.
    pub fn new<P: AsRef<Path>>(batch_size: usize, db_path: P) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS provenance_ledger (
                batch_id TEXT PRIMARY KEY,
                start_index INTEGER NOT NULL,
                event_count INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )",
            [],
        )?;

        Ok(Self {
            batch_size,
            leaves: Vec::with_capacity(batch_size),
            db_conn: Arc::new(Mutex::new(conn)),
            batch_counter: 0,
        })
    }

    /// Add a leaf SHA-256 hex string to the current micro-batch.
    /// If batch reaches `batch_size`, automatically anchors and returns `Some(ProvenanceRecord)`.
    pub fn add_event_hash(&mut self, hash_hex: &str) -> Result<Option<ProvenanceRecord>, String> {
        let bytes = hex::decode(hash_hex).map_err(|e| format!("Invalid hex hash: {}", e))?;
        self.leaves.push(bytes);

        if self.leaves.len() >= self.batch_size {
            let record = self.commit_batch()?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    /// Force commit the current batch (e.g. at shutdown or flush).
    pub fn commit_batch(&mut self) -> Result<ProvenanceRecord, String> {
        if self.leaves.is_empty() {
            return Err("Cannot commit empty batch".to_string());
        }

        self.batch_counter += 1;
        let root_bytes = self.compute_root(&self.leaves);
        let root_hex = hex::encode(root_bytes);
        let count = self.leaves.len();
        let batch_id = format!("batch_{}_{}", self.batch_counter, Utc::now().timestamp_millis());
        let now = Utc::now();

        let record = ProvenanceRecord {
            batch_id: batch_id.clone(),
            start_index: (self.batch_counter - 1) * (self.batch_size as u64),
            event_count: count,
            merkle_root: root_hex.clone(),
            timestamp: now,
        };

        // Anchor to local append-only provenance ledger
        let conn = self.db_conn.lock().unwrap();
        conn.execute(
            "INSERT INTO provenance_ledger (batch_id, start_index, event_count, merkle_root, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                record.batch_id,
                record.start_index as i64,
                record.event_count as i64,
                record.merkle_root,
                record.timestamp.to_rfc3339()
            ],
        )
        .map_err(|e| format!("Failed to anchor batch to provenance ledger: {}", e))?;

        self.leaves.clear();
        Ok(record)
    }

    /// Compute Merkle Root for a slice of leaves.
    fn compute_root(&self, leaves: &[Vec<u8>]) -> Vec<u8> {
        if leaves.is_empty() {
            return Sha256::digest(b"").to_vec();
        }
        if leaves.len() == 1 {
            return leaves[0].clone();
        }

        let mut current_level = leaves.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);

            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(hash_pair(&chunk[0], &chunk[1]));
                } else {
                    // Duplicate last odd leaf
                    next_level.push(hash_pair(&chunk[0], &chunk[0]));
                }
            }

            current_level = next_level;
        }

        current_level[0].clone()
    }

    /// Generate an audit proof for a specific leaf within a slice of leaves.
    pub fn generate_proof(leaves: &[String], leaf_index: usize) -> Result<MerkleProof, String> {
        if leaf_index >= leaves.len() {
            return Err(format!("Index {} out of bounds ({})", leaf_index, leaves.len()));
        }

        let mut current_level: Vec<Vec<u8>> = leaves
            .iter()
            .map(|h| hex::decode(h).unwrap_or_default())
            .collect();

        let target_leaf_hash = leaves[leaf_index].clone();
        let mut idx = leaf_index;
        let mut audit_path = Vec::new();

        while current_level.len() > 1 {
            let is_right_node = idx % 2 == 1;
            let sibling_idx = if is_right_node { idx - 1 } else { idx + 1 };

            let sibling_hash = if sibling_idx < current_level.len() {
                hex::encode(&current_level[sibling_idx])
            } else {
                hex::encode(&current_level[idx])
            };

            audit_path.push((sibling_hash, is_right_node));

            // Compute parent level
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(hash_pair(&chunk[0], &chunk[1]));
                } else {
                    next_level.push(hash_pair(&chunk[0], &chunk[0]));
                }
            }

            current_level = next_level;
            idx /= 2;
        }

        let root_hash = hex::encode(&current_level[0]);

        Ok(MerkleProof {
            leaf_index,
            leaf_hash: target_leaf_hash,
            audit_path,
            root_hash,
        })
    }

    /// Verify an audit proof against an expected Merkle root.
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current = match hex::decode(&proof.leaf_hash) {
            Ok(b) => b,
            Err(_) => return false,
        };

        for (sibling_hex, is_left_sibling) in &proof.audit_path {
            let sibling = match hex::decode(sibling_hex) {
                Ok(b) => b,
                Err(_) => return false,
            };

            current = if *is_left_sibling {
                hash_pair(&sibling, &current)
            } else {
                hash_pair(&current, &sibling)
            };
        }

        hex::encode(current).eq_ignore_ascii_case(&proof.root_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_proof_and_verification() {
        let mut hashes = Vec::new();
        for i in 0..8 {
            let mut hasher = Sha256::new();
            hasher.update(format!("event_{}", i).as_bytes());
            hashes.push(hex::encode(hasher.finalize()));
        }

        let proof = MerkleTree::generate_proof(&hashes, 3).unwrap();
        assert!(MerkleTree::verify_proof(&proof));

        // Tamper test: modify leaf hash
        let mut tampered_proof = proof.clone();
        tampered_proof.leaf_hash = hex::encode(Sha256::digest(b"tampered_data"));
        assert!(!MerkleTree::verify_proof(&tampered_proof));
    }
}
