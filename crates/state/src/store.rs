//! State store trait + in-memory stub.
//!
//! The production backend is GroveDB. The trait here exists so consensus and node code
//! can be written, tested, and fuzzed against the stub before the GroveDB bring-up on
//! Linux/MSVC.
//!
//! The stub's root commitment funnels through `pygrove_core::hash::hash_with_domain`
//! so the domain-tag discipline that protects header and witness hashes also covers
//! the in-memory tree's Merkle proxy.

use std::collections::BTreeMap;
use crate::subtrees::Subtree;
use pygrove_core::hash::{hash_with_domain, truncate_to_32, HashAlgo};

pub trait StateStore {
    fn put(&mut self, sub: Subtree, key: &[u8], value: &[u8]);
    fn get(&self, sub: Subtree, key: &[u8]) -> Option<Vec<u8>>;
    fn root(&self) -> [u8; 32];
}

/// Deterministic in-memory store. Root is a domain-tagged digest over the sorted
/// (subtree-tag, key, value) sequence. Good enough to bootstrap tests; not good
/// enough to ship.
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
        let mut buf: Vec<u8> = Vec::new();
        for ((s, k), v) in &self.data {
            buf.push(*s);
            buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
            buf.extend_from_slice(k);
            buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
            buf.extend_from_slice(v);
        }
        let d = hash_with_domain(HashAlgo::Blake3Xof512, "memroot", &buf);
        truncate_to_32(&d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_is_stable() {
        let s = MemState::new();
        assert_eq!(s.root(), s.root());
    }

    #[test]
    fn root_changes_when_value_changes() {
        let mut s = MemState::new();
        s.put(Subtree::Accounts, b"k", b"v1");
        let r1 = s.root();
        s.put(Subtree::Accounts, b"k", b"v2");
        let r2 = s.root();
        assert_ne!(r1, r2);
    }

    #[test]
    fn subtree_separation() {
        // Same key/value in two different subtrees must produce distinct roots —
        // that's what the subtree tag prefix is for.
        let mut a = MemState::new();
        a.put(Subtree::Accounts, b"k", b"v");
        let mut b = MemState::new();
        b.put(Subtree::Reflect, b"k", b"v");
        assert_ne!(a.root(), b.root());
    }
}
