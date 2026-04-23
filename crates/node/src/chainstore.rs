//! Append-only block log. v0.1 persistence layer — one file, length-prefixed CBOR blocks.
//!
//! GroveDB lands in v1.0 proper. This is intentionally the simplest thing that survives a
//! restart so the miner client has a real chain to attach to.

use pygrove_core::Block;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct ChainStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl ChainStore {
    pub fn open(data_dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        let dir = data_dir.as_ref();
        std::fs::create_dir_all(dir)?;
        let path = dir.join("chain.log");
        Ok(Self {
            path,
            lock: Mutex::new(()),
        })
    }

    pub fn append(&self, block: &Block) -> anyhow::Result<()> {
        let _g = self.lock.lock().unwrap();
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
        Ok(())
    }

    pub fn load_all(&self) -> anyhow::Result<Vec<Block>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let mut f = BufReader::new(File::open(&self.path)?);
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

    pub fn tip(&self) -> anyhow::Result<Option<Block>> {
        Ok(self.load_all()?.into_iter().last())
    }

    pub fn height(&self) -> anyhow::Result<u64> {
        Ok(self.tip()?.map(|b| b.header.height).unwrap_or(0))
    }

    pub fn len(&self) -> anyhow::Result<u64> {
        Ok(self.load_all()?.len() as u64)
    }

    /// Most recent `n` blocks, newest first. Cheap-ish for v0.1 since the whole
    /// log is in memory anyway; GroveDB replaces this in v1.0.
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
