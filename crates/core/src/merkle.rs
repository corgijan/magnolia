use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::errors::CoreError;

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(text).map_err(serde::de::Error::custom)
    }
}

mod hex_vec_vec {
    use serde::ser::{SerializeSeq, Serializer};
    use serde::{Deserialize, Deserializer};

    pub fn serialize<S: Serializer>(
        value: &Vec<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for item in value {
            seq.serialize_element(&hex::encode(item))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        let list: Vec<String> = Vec::deserialize(deserializer)?;
        list.into_iter()
            .map(|item| hex::decode(item).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// One step in a proof walk: a sibling node hash and which side of the
/// parent it occupies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStep {
    #[serde(with = "hex_vec")]
    pub hash: Vec<u8>,
    /// True when the sibling was the left child (the walked node was the
    /// right child).
    pub sibling_is_left: bool,
}

/// Proof that a leaf is included in a Merkle Mountain Range of `tree_size`.
///
/// `sibling_path` walks from the leaf up to the root of the mountain that
/// contains it. `peaks` are all current MMR peaks, left to right;
/// `peak_index` identifies which peak is the leaf's mountain. Verification:
/// hash the leaf up with `sibling_path` (must match `peaks[peak_index]`),
/// then fold `peaks` left to right to obtain the tree root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub peak_index: u32,
    #[serde(with = "hex_vec_vec")]
    pub peaks: Vec<Vec<u8>>,
    pub sibling_path: Vec<ProofStep>,
}

/// For one old MMR peak: its identity in the old tree, the new peak that now
/// subsumes it, and the sibling chain connecting the two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeakProof {
    pub leaf_start: u64,
    pub level: u32,
    #[serde(with = "hex_vec")]
    pub peak_hash: Vec<u8>,
    pub new_peak_index: u32,
    pub steps: Vec<ProofStep>,
}

/// Proof that a tree of `new_tree_size` extends a tree of `old_tree_size`
/// without modifying any of the first `old_tree_size` leaves.
///
/// `peaks` are the new frontier. Each old peak (identified by
/// `(leaf_start, level)`, which the verifier recomputes from `old_tree_size`)
/// must hash up through `steps` to the peak at `new_peak_index`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub old_tree_size: u64,
    pub new_tree_size: u64,
    #[serde(with = "hex_vec_vec")]
    pub peaks: Vec<Vec<u8>>,
    pub peak_proofs: Vec<PeakProof>,
}

#[derive(Debug, Clone)]
pub struct MerkleNode {
    pub level: i32,
    pub index: i64,
    pub hash: Vec<u8>,
}

/// Append-only Merkle Mountain Range.
///
/// The tree keeps the full MMR append sequence in memory so that proofs can
/// be generated for any historical or current leaf. The frontier stores one
/// entry per level (`None` when that level has no peak); peaks are ordered
/// left to right by level, which matches the left-to-right leaf ranges.
#[derive(Debug, Clone, Default)]
pub struct MerkleTree {
    tree_size: u64,
    nodes: Vec<Vec<u8>>,
    levels: Vec<u32>,
    parents: Vec<Option<usize>>,
    siblings: Vec<Option<usize>>,
    mountain_starts: Vec<u64>,
    frontier: Vec<Option<usize>>,
    leaf_positions: Vec<usize>,
    mountain_index: HashMap<(u64, u32), usize>,
    root_hash: Vec<u8>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }

    pub fn is_empty(&self) -> bool {
        self.tree_size == 0
    }

    pub fn root_hash(&self) -> &[u8] {
        &self.root_hash
    }

    /// Peak positions in left-to-right leaf order. Spatial order is
    /// descending level: the binary decomposition of the tree size tiles
    /// `[0, tree_size)` left to right with decreasing block sizes.
    fn ordered_peaks(&self) -> Vec<usize> {
        let mut peaks: Vec<(u32, usize)> = self
            .frontier
            .iter()
            .enumerate()
            .filter_map(|(level, pos)| pos.map(|pos| (level as u32, pos)))
            .collect();
        peaks.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        peaks.into_iter().map(|(_, pos)| pos).collect()
    }

    /// Peak hashes, left to right by leaf range.
    pub fn frontier_hashes(&self) -> Vec<Vec<u8>> {
        self.ordered_peaks()
            .into_iter()
            .map(|pos| self.nodes[pos].clone())
            .collect()
    }

    pub fn leaf_hash_at(&self, leaf_index: u64) -> Option<&[u8]> {
        let pos = self.leaf_positions.get(leaf_index as usize)?;
        Some(&self.nodes[*pos])
    }

    /// Append raw data as a new leaf; returns the leaf hash.
    pub fn add_leaf(&mut self, leaf_data: &[u8]) -> Vec<u8> {
        let leaf_hash = Self::hash_leaf(leaf_data);
        self.append(leaf_hash.clone());
        leaf_hash
    }

    /// Append a precomputed leaf hash (e.g. when rebuilding from the
    /// `merkle_leaves` table after a restart).
    pub fn add_leaf_hash(&mut self, leaf_hash: &[u8]) {
        self.append(leaf_hash.to_vec());
    }

    fn append(&mut self, leaf_hash: Vec<u8>) {
        let leaf_pos = self.nodes.len();
        let leaf_start = self.tree_size;

        self.nodes.push(leaf_hash.clone());
        self.levels.push(0);
        self.parents.push(None);
        self.siblings.push(None);
        self.mountain_starts.push(leaf_start);
        self.leaf_positions.push(leaf_pos);
        self.mountain_index.insert((leaf_start, 0), leaf_pos);

        let mut cur_pos = leaf_pos;
        let mut cur_level = 0u32;
        let mut cur_hash = leaf_hash;

        loop {
            let occupied = self
                .frontier
                .get(cur_level as usize)
                .copied()
                .flatten()
                .is_some();
            if !occupied {
                if cur_level as usize == self.frontier.len() {
                    self.frontier.push(Some(cur_pos));
                } else {
                    self.frontier[cur_level as usize] = Some(cur_pos);
                }
                break;
            }
            let old_peak = self.frontier[cur_level as usize].take().unwrap();
            let merged = Self::hash_pair(&self.nodes[old_peak], &cur_hash);
            let new_pos = self.nodes.len();

            self.nodes.push(merged.clone());
            self.levels.push(cur_level + 1);
            self.parents.push(None);
            self.siblings.push(None);
            let new_start = self.mountain_starts[old_peak];
            self.mountain_starts.push(new_start);
            self.mountain_index.insert((new_start, cur_level + 1), new_pos);

            self.parents[old_peak] = Some(new_pos);
            self.parents[cur_pos] = Some(new_pos);
            self.siblings[old_peak] = Some(cur_pos);
            self.siblings[cur_pos] = Some(old_peak);

            cur_hash = merged;
            cur_pos = new_pos;
            cur_level += 1;
        }

        self.tree_size += 1;
        self.root_hash = self.calculate_root();
    }

    fn calculate_root(&self) -> Vec<u8> {
        fold_peaks(&self.frontier_hashes()).unwrap_or_default()
    }

    /// Sibling chain from `pos` up to (and including) the peak of the
    /// mountain containing it. Steps are ordered bottom-up.
    fn steps_to_peak(&self, pos: usize) -> Vec<ProofStep> {
        let mut steps = Vec::new();
        let mut cur = pos;
        while let Some(parent) = self.parents[cur] {
            if let Some(sibling) = self.siblings[cur] {
                steps.push(ProofStep {
                    hash: self.nodes[sibling].clone(),
                    sibling_is_left: sibling < cur,
                });
            }
            cur = parent;
        }
        steps
    }

    fn peak_position_of(&self, pos: usize) -> Option<usize> {
        let mut cur = pos;
        while self.parents[cur].is_some() {
            cur = self.parents[cur].unwrap();
        }
        self.ordered_peaks()
            .iter()
            .position(|&peak| peak == cur)
    }

    /// Canonical `(level, leaf_start)` pairs for the frontier of a tree with
    /// `size` leaves, in left-to-right leaf order (descending level). The MMR
    /// shape is fully determined by the size: one peak per set bit, and the
    /// blocks of the binary decomposition tile the leaf range left to right.
    pub fn frontier_ranges(size: u64) -> Vec<(u32, u64)> {
        let mut levels: Vec<u32> = (0..64)
            .filter(|&level| size >> level & 1 == 1)
            .map(|level| level as u32)
            .collect();
        levels.sort_unstable_by(|a, b| b.cmp(a));

        let mut ranges = Vec::new();
        let mut start = 0u64;
        for level in levels {
            ranges.push((level, start));
            start += 1u64 << level;
        }
        ranges
    }

    pub fn generate_inclusion_proof(
        &self,
        leaf_index: u64,
    ) -> Result<InclusionProof, CoreError> {
        if self.tree_size == 0 || leaf_index >= self.tree_size {
            return Err(CoreError::TreeError(format!(
                "leaf index {} out of range (tree size {})",
                leaf_index, self.tree_size
            )));
        }

        let pos = self.leaf_positions[leaf_index as usize];
        let peak_index = self
            .peak_position_of(pos)
            .ok_or_else(|| CoreError::TreeError("peak not found in frontier".to_string()))?;

        Ok(InclusionProof {
            leaf_index,
            tree_size: self.tree_size,
            peak_index: peak_index as u32,
            peaks: self.frontier_hashes(),
            sibling_path: self.steps_to_peak(pos),
        })
    }

    pub fn generate_consistency_proof(
        &self,
        old_tree_size: u64,
    ) -> Result<ConsistencyProof, CoreError> {
        if old_tree_size == 0 || old_tree_size > self.tree_size {
            return Err(CoreError::TreeError(format!(
                "old tree size {} invalid for tree of size {}",
                old_tree_size, self.tree_size
            )));
        }

        let mut peak_proofs = Vec::new();
        for (level, start) in Self::frontier_ranges(old_tree_size) {
            let pos = *self
                .mountain_index
                .get(&(start, level))
                .ok_or_else(|| {
                    CoreError::TreeError(format!(
                        "mountain (start {}, level {}) not found",
                        start, level
                    ))
                })?;
            let new_peak_index = self.peak_position_of(pos).ok_or_else(|| {
                CoreError::TreeError("old peak has no containing peak".to_string())
            })?;
            peak_proofs.push(PeakProof {
                leaf_start: start,
                level,
                peak_hash: self.nodes[pos].clone(),
                new_peak_index: new_peak_index as u32,
                steps: self.steps_to_peak(pos),
            });
        }

        Ok(ConsistencyProof {
            old_tree_size,
            new_tree_size: self.tree_size,
            peaks: self.frontier_hashes(),
            peak_proofs,
        })
    }

    pub fn verify_inclusion(proof: &InclusionProof, leaf_hash: &[u8], root: &[u8]) -> bool {
        let peak_idx = proof.peak_index as usize;
        if proof.tree_size == 0
            || proof.leaf_index >= proof.tree_size
            || peak_idx >= proof.peaks.len()
        {
            return false;
        }

        let mut hash = leaf_hash.to_vec();
        for step in &proof.sibling_path {
            hash = if step.sibling_is_left {
                Self::hash_pair(&step.hash, &hash)
            } else {
                Self::hash_pair(&hash, &step.hash)
            };
        }
        if hash != proof.peaks[peak_idx] {
            return false;
        }

        fold_peaks(&proof.peaks) == Some(root.to_vec())
    }

    pub fn verify_consistency(
        proof: &ConsistencyProof,
        old_root: &[u8],
        new_root: &[u8],
    ) -> bool {
        if proof.old_tree_size == 0 || proof.new_tree_size < proof.old_tree_size {
            return false;
        }
        let expected = Self::frontier_ranges(proof.old_tree_size);
        if proof.peak_proofs.len() != expected.len() {
            return false;
        }

        let mut old_acc: Option<Vec<u8>> = None;
        for (i, peak_proof) in proof.peak_proofs.iter().enumerate() {
            if (peak_proof.level, peak_proof.leaf_start) != expected[i] {
                return false;
            }
            let mut hash = peak_proof.peak_hash.clone();
            for step in &peak_proof.steps {
                hash = if step.sibling_is_left {
                    Self::hash_pair(&step.hash, &hash)
                } else {
                    Self::hash_pair(&hash, &step.hash)
                };
            }
            let new_peak_idx = peak_proof.new_peak_index as usize;
            if new_peak_idx >= proof.peaks.len() || hash != proof.peaks[new_peak_idx] {
                return false;
            }
            old_acc = Some(match old_acc {
                None => peak_proof.peak_hash.clone(),
                Some(acc) => Self::hash_pair(&acc, &peak_proof.peak_hash),
            });
        }

        old_acc.as_deref() == Some(old_root) && fold_peaks(&proof.peaks) == Some(new_root.to_vec())
    }

    pub fn hash_leaf(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&[0u8]); // leaf prefix
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    pub fn hash_pair(left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&[1u8]); // node prefix
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().to_vec()
    }
}

fn fold_peaks(peaks: &[Vec<u8>]) -> Option<Vec<u8>> {
    let mut acc: Option<Vec<u8>> = None;
    for peak in peaks {
        acc = Some(match acc {
            None => peak.clone(),
            Some(acc) => MerkleTree::hash_pair(&acc, peak),
        });
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(size: u64) -> (MerkleTree, Vec<Vec<u8>>) {
        let mut tree = MerkleTree::new();
        let mut leaf_hashes = Vec::new();
        for i in 0..size {
            let data = format!("sbom-leaf-{}", i).into_bytes();
            let hash = tree.add_leaf(&data);
            leaf_hashes.push(hash);
        }
        (tree, leaf_hashes)
    }

    fn leaf_data(i: u64) -> Vec<u8> {
        format!("sbom-leaf-{}", i).into_bytes()
    }

    #[test]
    fn empty_tree_has_empty_root() {
        let tree = MerkleTree::new();
        assert_eq!(tree.tree_size(), 0);
        assert!(tree.root_hash().is_empty());
        assert!(tree.frontier_hashes().is_empty());
    }

    #[test]
    fn single_leaf_root_is_the_leaf_hash() {
        let (tree, leaf_hashes) = build(1);
        assert_eq!(tree.root_hash(), &leaf_hashes[0]);
    }

    #[test]
    fn two_leaves_root_uses_correct_child_order() {
        let (tree, leaf_hashes) = build(2);
        let expected = MerkleTree::hash_pair(&leaf_hashes[0], &leaf_hashes[1]);
        assert_eq!(tree.root_hash(), &expected);
    }

    #[test]
    fn frontier_has_one_peak_per_set_bit() {
        for size in 1..=48u64 {
            let (tree, _) = build(size);
            let set_bits = size.count_ones();
            assert_eq!(
                tree.frontier_hashes().len(),
                set_bits as usize,
                "size {}",
                size
            );
        }
    }

    #[test]
    fn every_leaf_verifies_at_every_size() {
        let mut tree = MerkleTree::new();
        let mut leaf_hashes = Vec::new();
        for i in 0..48u64 {
            let hash = tree.add_leaf(&leaf_data(i));
            leaf_hashes.push(hash);
            let root = tree.root_hash().to_vec();
            for (idx, lh) in leaf_hashes.iter().enumerate() {
                let proof = tree
                    .generate_inclusion_proof(idx as u64)
                    .expect("proof generation");
                assert!(
                    MerkleTree::verify_inclusion(&proof, lh, &root),
                    "size {}, leaf {}",
                    i,
                    idx
                );
            }
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_leaf_hash() {
        let (tree, leaf_hashes) = build(10);
        let root = tree.root_hash().to_vec();
        let proof = tree.generate_inclusion_proof(0).unwrap();
        assert!(!MerkleTree::verify_inclusion(&proof, &leaf_hashes[1], &root));
    }

    #[test]
    fn inclusion_proof_rejects_tampered_root() {
        let (tree, leaf_hashes) = build(7);
        let mut root = tree.root_hash().to_vec();
        root[0] ^= 0xFF;
        let proof = tree.generate_inclusion_proof(3).unwrap();
        assert!(!MerkleTree::verify_inclusion(&proof, &leaf_hashes[3], &root));
    }

    #[test]
    fn tampered_leaf_breaks_all_proofs() {
        let (tree, leaf_hashes) = build(9);
        let root_before = tree.root_hash().to_vec();
        let proofs_before: Vec<InclusionProof> = (0..9)
            .map(|i| tree.generate_inclusion_proof(i).unwrap())
            .collect();

        // Rebuild the same tree but with leaf 4 rewritten.
        let mut tampered = MerkleTree::new();
        for i in 0..9u64 {
            let data = if i == 4 { b"evil sbom".to_vec() } else { leaf_data(i) };
            tampered.add_leaf(&data);
        }
        assert_ne!(tampered.root_hash(), &root_before);

        for (i, proof) in proofs_before.iter().enumerate() {
            assert!(
                !MerkleTree::verify_inclusion(proof, &leaf_hashes[i], tampered.root_hash()),
                "leaf {} must not verify against tampered tree",
                i
            );
        }
    }

    #[test]
    fn consistency_proofs_verify_across_extensions() {
        let cases = [(1u64, 2u64), (1, 5), (2, 3), (3, 8), (4, 7), (5, 6), (5, 12), (8, 9)];
        for (old, new) in cases {
            let (mut tree, _) = build(old);
            let old_root = tree.root_hash().to_vec();
            for i in old..new {
                tree.add_leaf(&leaf_data(i));
            }
            let proof = tree.generate_consistency_proof(old).unwrap();
            assert!(
                MerkleTree::verify_consistency(&proof, &old_root, tree.root_hash()),
                "case old={} new={}",
                old,
                new
            );
        }
    }

    #[test]
    fn consistency_proof_rejects_rewritten_leaf() {
        let (mut original, _) = build(6);
        let old_root = original.root_hash().to_vec();
        for i in 6..10u64 {
            original.add_leaf(&leaf_data(i));
        }

        // Same first 6 leaves except leaf 2 rewritten, same extension.
        let mut rewritten = MerkleTree::new();
        for i in 0..10u64 {
            let data = if i == 2 { b"rewritten".to_vec() } else { leaf_data(i) };
            rewritten.add_leaf(&data);
        }

        let proof = rewritten.generate_consistency_proof(6).unwrap();
        assert!(
            !MerkleTree::verify_consistency(&proof, &old_root, rewritten.root_hash()),
            "rewritten leaf must be detected"
        );
    }

    #[test]
    fn consistency_proof_rejects_reordered_leaves() {
        let (mut original, _) = build(5);
        let old_root = original.root_hash().to_vec();
        for i in 5..9u64 {
            original.add_leaf(&leaf_data(i));
        }

        let mut reordered = MerkleTree::new();
        let order: Vec<u64> = vec![0, 2, 1, 3, 4, 5, 6, 7, 8];
        for i in order {
            reordered.add_leaf(&leaf_data(i));
        }

        let proof = reordered.generate_consistency_proof(5).unwrap();
        assert!(
            !MerkleTree::verify_consistency(&proof, &old_root, reordered.root_hash()),
            "reordered leaves must be detected"
        );
    }

    #[test]
    fn consistency_proof_same_size_still_verifies() {
        let (tree, _) = build(6);
        let root = tree.root_hash().to_vec();
        let proof = tree.generate_consistency_proof(6).unwrap();
        assert!(MerkleTree::verify_consistency(&proof, &root, &root));
    }

    #[test]
    fn proofs_survive_json_roundtrip() {
        let (tree, leaf_hashes) = build(13);
        let root = tree.root_hash().to_vec();

        let inclusion = tree.generate_inclusion_proof(4).unwrap();
        let inclusion_json = serde_json::to_string(&inclusion).unwrap();
        let inclusion_rt: InclusionProof = serde_json::from_str(&inclusion_json).unwrap();
        assert!(MerkleTree::verify_inclusion(&inclusion_rt, &leaf_hashes[4], &root));

        let consistency = tree.generate_consistency_proof(5).unwrap();
        let consistency_json = serde_json::to_string(&consistency).unwrap();
        let old_root_5 = {
            let (t5, _) = build(5);
            t5.root_hash().to_vec()
        };
        let consistency_rt: ConsistencyProof =
            serde_json::from_str(&consistency_json).unwrap();
        assert!(MerkleTree::verify_consistency(
            &consistency_rt,
            &old_root_5,
            &root
        ));
    }

    #[test]
    fn rebuild_from_leaf_hashes_matches_original() {
        let (tree, leaf_hashes) = build(17);
        let root = tree.root_hash().to_vec();
        let frontier = tree.frontier_hashes();

        let mut rebuilt = MerkleTree::new();
        for hash in &leaf_hashes {
            rebuilt.add_leaf_hash(hash);
        }
        assert_eq!(rebuilt.root_hash(), &root);
        assert_eq!(rebuilt.frontier_hashes(), frontier);

        let proof = tree.generate_inclusion_proof(9).unwrap();
        let rebuilt_proof = rebuilt.generate_inclusion_proof(9).unwrap();
        assert_eq!(proof, rebuilt_proof);
    }

    #[test]
    fn invalid_leaf_index_rejected() {
        let (tree, _) = build(4);
        assert!(tree.generate_inclusion_proof(4).is_err());
        assert!(tree.generate_inclusion_proof(u64::MAX).is_err());
        let empty = MerkleTree::new();
        assert!(empty.generate_inclusion_proof(0).is_err());
    }

    #[test]
    fn invalid_consistency_sizes_rejected() {
        let (tree, _) = build(8);
        assert!(tree.generate_consistency_proof(0).is_err());
        assert!(tree.generate_consistency_proof(9).is_err());
        assert!(tree.generate_consistency_proof(100).is_err());
    }

    #[test]
    fn frontier_ranges_cover_all_leaves() {
        for size in 1..=64u64 {
            let ranges = MerkleTree::frontier_ranges(size);
            let mut start = 0u64;
            for (level, range_start) in &ranges {
                assert_eq!(*range_start, start, "size {}", size);
                start += 1u64 << level;
            }
            assert_eq!(start, size, "size {}", size);
        }
    }
}