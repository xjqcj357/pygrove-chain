//! Append-only block log. v0.1 persistence layer — one file, length-prefixed CBOR blocks.
//!
//! GroveDB lands in v1.0 proper. This is intentionally the simplest thing that survives a
//! restart so the miner client has a real chain to attach to.
//!
//! ## Hot-path caching (v0.1.1)
//!
//! `tip()` and `height()` were O(chain length) in the original v0.1 — every RPC call
//! re-read the full chain log from disk and CBOR-decoded every block. That made
//! `submit_block`, `get_info`, and `get_template` an unauthenticated-DoS amplification
//! primitive: one TCP stream pinned the node at 100% CPU.
//!
//! This file adds an in-memory tip + height cache, kept consistent with disk by holding
//! the same mutex that guards `append`. Reads are O(1); only `recent`, `get_by_height`,
//! and `load_all` still cost O(n), and only the first two are ever called from RPC.

use pygrove_core::Block;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Default)]
struct CacheState {
    /// Most recent block, materialised once at open and updated on append. `None` until
    /// the first block is read or appended.
    tip: Option<Block>,
    /// Number of blocks in the log. Authoritative — always equals what's on disk.
    count: u64,
    /// Set true once `open()` has reconciled the in-memory cache with disk.
    primed: bool,
}

pub struct ChainStore {
    path: PathBuf,
    lock: Mutex<CacheState>,
}

impl ChainStore {
    pub fn open(data_dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        let dir = data_dir.as_ref();
        std::fs::create_dir_all(dir)?;
        let path = dir.join("chain.log");
        let store = Self {
            path,
            lock: Mutex::new(CacheState::default()),
        };
        // Prime the cache from disk once. Subsequent reads are O(1).
        store.prime()?;
        Ok(store)
    }

    fn prime(&self) -> anyhow::Result<()> {
        let blocks = read_all_from_disk(&self.path)?;
        let mut g = self.lock.lock().unwrap();
        g.count = blocks.len() as u64;
        g.tip = blocks.into_iter().last();
        g.primed = true;
        Ok(())
    }

    pub fn append(&self, block: &Block) -> anyhow::Result<()> {
        let mut g = self.lock.lock().unwrap();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(block, &mut buf)?;
        let len = (buf.len() as u32).to_le_bytes();
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(&len)?;
        f.write_all(&buf)?;
        f.flush()?;
        // Disk and cache are now in sync (still under the same mutex).
        g.count += 1;
        g.tip = Some(block.clone());
        Ok(())
    }

    pub fn load_all(&self) -> anyhow::Result<Vec<Block>> {
        // Bypass the cache: callers (`recent`, `get_by_height`) need every block.
        // The lock still serialises reads against `append` so we never see a torn write.
        let _g = self.lock.lock().unwrap();
        read_all_from_disk(&self.path)
    }

    pub fn tip(&self) -> anyhow::Result<Option<Block>> {
        let g = self.lock.lock().unwrap();
        Ok(g.tip.clone())
    }

    pub fn height(&self) -> anyhow::Result<u64> {
        let g = self.lock.lock().unwrap();
        Ok(g.tip.as_ref().map(|b| b.header.height).unwrap_or(0))
    }

    pub fn len(&self) -> anyhow::Result<u64> {
        let g = self.lock.lock().unwrap();
        Ok(g.count)
    }

    /// Most recent `n` blocks, newest first. Still O(n) — GroveDB replaces this in v1.0.
    pub fn recent(&self, n: usize) -> anyhow::Result<Vec<Block>> {
        let all = self.load_all()?;
        let start = all.len().saturating_sub(n);
        Ok(all.into_iter().skip(start).rev().collect())
    }

    pub fn get_by_height(&self, height: u64) -> anyhow::Result<Option<Block>> {
        let all = self.load_all()?;
        Ok(all.into_iter().find(|b| b.header.height == height))
    }
}

fn read_all_from_disk(path: &Path) -> anyhow::Result<Vec<Block>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let mut f = BufReader::new(File::open(path)?);
    let mut out = Vec::new();
    let mut len_buf = [0u8; 4];
    loop {
        match f.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        f.read_exact(&mut body)?;
        let block: Block = ciborium::de::from_reader(&body[..])?;
        out.push(block);
    }
    Ok(out)
}
