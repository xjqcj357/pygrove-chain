//! State store trait + in-memory stub.
//!
//! The production backend is GroveDB. The trait here exists so consensus and node code
//! can be written, tested, and fuzzed against the stub before the GroveDB bring-up on
//! Linux/MSVC.

use std::collections::BTreeMap;
use crate::subtrees::Subtree;

pub trait StateStore {
    fn put(&mut self, sub: Subtree, key: &[u8], value: &[u8]);
    fn get(&self, sub: Subtree, key: &[u8]) -> Option<Vec<u8>>;
    fn root(&self) -> [u8; 32];
}

/// Deterministic in-memory store. Root is Blake3 over the sorted (tag, key, value)
/// sequence. Good enough to bootstrap tests; not good enough to ship.
#[derive(Default)]
pub struct MemState {
    data: BTreeMap<(u8, Vec<u8>), Vec<u8>>,
}

impl MemState {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateStore for MemState {
    fn put(&mut self, sub: Subtree, key: &[u8], value: &[u8]) {
        self.data.insert((sub as u8, key.to_vec()), value.to_vec());
    }
    fn get(&self, sub: Subtree, key: &[u8]) -> Option<Vec<u8>> {
        self.data.get(&(sub as u8, key.to_vec())).cloned()
    }
    fn root(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"PGmemroot\x00");
        for ((s, k), v) in &self.data {
            h.update(&[*s]);
            h.update(&(k.len() as u32).to_le_bytes());
            h.update(k);
            h.update(&(v.len() as u32).to_le_bytes());
            h.update(v);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }
}
