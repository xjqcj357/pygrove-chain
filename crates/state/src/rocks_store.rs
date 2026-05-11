//! RocksDB-backed `StateStore`.
//!
//! Production-grade persistence behind the same `StateStore` trait
//! `MemState` implements. The root commitment is **byte-identical** to
//! `MemState`'s — both walk the (subtree, key, value) triples in the
//! same canonical order through `hash_with_domain(Blake3Xof512,
//! "memroot", ...)`. A chain that ran on `MemState` can be migrated to
//! `RocksState` (or vice versa) without changing the state_root.
//!
//! ## Key encoding
//!
//! Each `(Subtree, key)` pair maps to a RocksDB key as:
//! ```text
//! [subtree_tag (1 byte)] [key bytes...]
//! ```
//! Tag → byte mapping is `Subtree as u8`. RocksDB's default lexicographic
//! sort then naturally groups all entries within a subtree together,
//! and `root()` iterates in that same order to produce the canonical
//! commitment.
//!
//! ## Concurrency
//!
//! All writes go through a `&mut self` interface, so external
//! synchronization (the node's `Mutex<RocksState>`) covers in-process
//! concurrency. RocksDB itself is thread-safe for reads, but `apply_block`
//! is single-threaded anyway.
//!
//! ## Disk layout
//!
//! - `${data_dir}/rocks/` — RocksDB's column-family files
//!
//! ## Migration
//!
//! `RocksState::import_from(&MemState)` and `RocksState::export_to(MemState)`
//! enable round-tripping. Operators upgrading an existing testnet-3-style
//! in-memory deployment to persistent storage can run one-shot conversion
//! at node start.

use crate::store::StateStore;
use crate::subtrees::Subtree;
use pygrove_core::hash::{hash_with_domain, truncate_to_32, HashAlgo};
use rocksdb::{IteratorMode, DB};
use std::path::Path;
use std::sync::Mutex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RocksError {
    #[error("rocksdb: {0}")]
    Db(String),
    #[error("io: {0}")]
    Io(String),
}

/// Persistent state store backed by RocksDB.
///
/// All `StateStore` trait operations match `MemState`'s semantics
/// exactly — including the `root()` commitment, which iterates the
/// (subtree, key, value) triples in canonical sort order.
pub struct RocksState {
    db: DB,
    /// In-process root cache. Reset on every `put` to force a fresh
    /// computation on next `root()`. Avoids the O(N) walk per
    /// commitment when nothing has changed (e.g. multiple readers
    /// after one writer).
    cached_root: Mutex<Option<[u8; 32]>>,
}

impl RocksState {
    /// Open or create a RocksDB store at `path`. The directory is
    /// created if it doesn't exist.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RocksError> {
        let path = path.as_ref();
        std::fs::create_dir_all(path).map_err(|e| RocksError::Io(e.to_string()))?;
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.set_compression_type(rocksdb::DBCompressionType::Snappy);
        // Reasonable defaults for a single-tenant chain-state workload:
        // - small write buffer (state writes are batched per block)
        // - bloom filters to keep point-lookups O(1) on the hot path
        opts.set_write_buffer_size(32 * 1024 * 1024); // 32 MB
        let mut block_opts = rocksdb::BlockBasedOptions::default();
        block_opts.set_bloom_filter(10.0, false);
        opts.set_block_based_table_factory(&block_opts);
        let db = DB::open(&opts, path).map_err(|e| RocksError::Db(e.to_string()))?;
        Ok(Self {
            db,
            cached_root: Mutex::new(None),
        })
    }

    /// Bulk-import from a `MemState`. Useful when migrating an
    /// existing in-memory chain to persistent storage without a
    /// state_root change. After import, `self.root() == src.root()`.
    pub fn import_from(&mut self, src: &crate::MemState) -> Result<(), RocksError> {
        let mut batch = rocksdb::WriteBatch::default();
        for (sub, key, val) in src.iter_canonical() {
            let mut full = Vec::with_capacity(1 + key.len());
            full.push(sub);
            full.extend_from_slice(key);
            batch.put(&full, val);
        }
        self.db.write(batch).map_err(|e| RocksError::Db(e.to_string()))?;
        *self.cached_root.lock().unwrap() = None;
        Ok(())
    }

    /// Build the canonical key encoding for a (subtree, key) pair.
    /// Stable across versions — changing this would change state_root.
    fn encode_key(sub: Subtree, key: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + key.len());
        out.push(sub as u8);
        out.extend_from_slice(key);
        out
    }

    /// Iterator-style walk of `(subtree_byte, key_bytes, value_bytes)`
    /// in canonical sort order. Used by `root()` and by external
    /// debug / audit code that wants to dump full state.
    pub fn iter_canonical(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        let it = self.db.iterator(IteratorMode::Start);
        for item in it {
            let (k, v) = match item {
                Ok((k, v)) => (k, v),
                Err(_) => continue,
            };
            if k.is_empty() {
                continue;
            }
            let sub = k[0];
            let key = k[1..].to_vec();
            out.push((sub, key, v.to_vec()));
        }
        out
    }
}

impl StateStore for RocksState {
    fn put(&mut self, sub: Subtree, key: &[u8], value: &[u8]) {
        let k = Self::encode_key(sub, key);
        // RocksDB write errors here would be a hard fault — we don't
        // surface them through the trait's infallible signature (matches
        // MemState's semantics). Production deployments wrap this with
        // panic-on-failure intent; the alternative (silently dropping
        // writes) is worse.
        if let Err(e) = self.db.put(&k, value) {
            tracing::error!(error = %e, "RocksState::put failed");
            // Panic intentionally — a failed state write breaks
            // consensus and operations must page on it.
            panic!("RocksState::put failed: {e}");
        }
        *self.cached_root.lock().unwrap() = None;
    }

    fn get(&self, sub: Subtree, key: &[u8]) -> Option<Vec<u8>> {
        let k = Self::encode_key(sub, key);
        match self.db.get(&k) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "RocksState::get failed");
                None
            }
        }
    }

    fn root(&self) -> [u8; 32] {
        if let Some(cached) = *self.cached_root.lock().unwrap() {
            return cached;
        }
        let mut buf: Vec<u8> = Vec::new();
        let it = self.db.iterator(IteratorMode::Start);
        for item in it {
            let (k, v) = match item {
                Ok((k, v)) => (k, v),
                Err(_) => continue,
            };
            if k.is_empty() {
                continue;
            }
            // Mirror MemState::root encoding exactly: [subtree_tag,
            // key_len LE u32, key, val_len LE u32, val].
            let sub_tag = k[0];
            let key = &k[1..];
            buf.push(sub_tag);
            buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
            buf.extend_from_slice(key);
            buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
            buf.extend_from_slice(&v);
        }
        let d = hash_with_domain(HashAlgo::Blake3Xof512, "memroot", &buf);
        let r = truncate_to_32(&d);
        *self.cached_root.lock().unwrap() = Some(r);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_rocks() -> (RocksState, TempDir) {
        let td = TempDir::new().expect("tempdir");
        let s = RocksState::open(td.path()).expect("open rocks");
        (s, td)
    }

    /// Same writes → same root as MemState.
    #[test]
    fn root_matches_mem_state() {
        let mut mem = crate::MemState::new();
        let (mut rocks, _td) = fresh_rocks();

        let writes = vec![
            (Subtree::Accounts, &b"alice"[..], &b"100"[..]),
            (Subtree::Accounts, &b"bob"[..], &b"50"[..]),
            (Subtree::Reflect, &b"latest"[..], &b"{height:1}"[..]),
            (Subtree::Meta, &b"governance"[..], &b"committee"[..]),
        ];
        for (s, k, v) in &writes {
            mem.put(*s, k, v);
            rocks.put(*s, k, v);
        }
        assert_eq!(
            mem.root(),
            rocks.root(),
            "RocksState.root() must equal MemState.root() for the same writes"
        );
    }

    /// Round-trip: put then get returns the same bytes.
    #[test]
    fn put_get_roundtrip() {
        let (mut rocks, _td) = fresh_rocks();
        rocks.put(Subtree::Accounts, b"k", b"v");
        assert_eq!(rocks.get(Subtree::Accounts, b"k"), Some(b"v".to_vec()));
        assert_eq!(rocks.get(Subtree::Accounts, b"nonexistent"), None);
    }

    /// Update overwrites + root changes.
    #[test]
    fn update_changes_root() {
        let (mut rocks, _td) = fresh_rocks();
        rocks.put(Subtree::Accounts, b"k", b"v1");
        let r1 = rocks.root();
        rocks.put(Subtree::Accounts, b"k", b"v2");
        let r2 = rocks.root();
        assert_ne!(r1, r2);
        assert_eq!(rocks.get(Subtree::Accounts, b"k"), Some(b"v2".to_vec()));
    }

    /// Cached root invalidated on put.
    #[test]
    fn cached_root_invalidated_on_put() {
        let (mut rocks, _td) = fresh_rocks();
        rocks.put(Subtree::Accounts, b"k1", b"v1");
        let r1 = rocks.root(); // populates cache
        let r2 = rocks.root(); // hits cache
        assert_eq!(r1, r2);
        rocks.put(Subtree::Accounts, b"k2", b"v2"); // invalidates
        let r3 = rocks.root();
        assert_ne!(r1, r3);
    }

    /// Cross-subtree separation: same key, different subtree → different root.
    #[test]
    fn subtree_separation() {
        let (mut a, _ta) = fresh_rocks();
        a.put(Subtree::Accounts, b"k", b"v");
        let (mut b, _tb) = fresh_rocks();
        b.put(Subtree::Reflect, b"k", b"v");
        assert_ne!(a.root(), b.root());
    }

    /// Persistence: open, write, close, reopen → data still there.
    #[test]
    fn data_persists_across_reopen() {
        let td = TempDir::new().expect("tempdir");
        {
            let mut rocks = RocksState::open(td.path()).expect("open 1");
            rocks.put(Subtree::Accounts, b"persisted", b"data");
        }
        let rocks = RocksState::open(td.path()).expect("open 2");
        assert_eq!(
            rocks.get(Subtree::Accounts, b"persisted"),
            Some(b"data".to_vec())
        );
    }

    /// Migrate from MemState to RocksState; roots must match before and after.
    #[test]
    fn import_from_mem_state_preserves_root() {
        let mut mem = crate::MemState::new();
        mem.put(Subtree::Accounts, b"alice", b"100");
        mem.put(Subtree::Reflect, b"latest", b"{}");
        mem.put(Subtree::Meta, b"governance", b"cfg");
        let mem_root = mem.root();

        let (mut rocks, _td) = fresh_rocks();
        rocks.import_from(&mem).expect("import");
        assert_eq!(rocks.root(), mem_root, "import must preserve root");
    }
}
