//! In-process mempool. Pending transactions submitted via JSON-RPC live here
//! until a miner picks them up for the next block.
//!
//! v0.1: a single `Mutex<BTreeMap<TxHash, PendingTx>>`. Good enough for a
//! testnet receiving a few transactions per second from a wallet. Ordering
//! at pull time is by `(fee_per_byte_desc, tx_hash_asc)` so deterministic
//! across miner restarts.

use pygrove_core::{TxBody, Witness};
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct PendingTx {
    pub body: TxBody,
    pub witness: Witness,
    /// Wall-clock time of arrival, used for FIFO eviction at the cap.
    pub received_ms: u64,
}

#[derive(Debug, Default)]
pub struct Mempool {
    inner: Mutex<BTreeMap<[u8; 32], PendingTx>>,
    cap: usize,
}

impl Mempool {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(BTreeMap::new()),
            cap,
        }
    }

    /// Add a transaction. Returns `Ok(tx_body_hash)` on insert, `Err(reason)` on
    /// reject. Cheap pre-checks only — apply-time validation lives in
    /// `pygrove_state::apply_block`.
    pub fn submit(&self, body: TxBody, witness: Witness) -> Result<[u8; 32], MempoolError> {
        if body.witness_hash != witness.hash() {
            return Err(MempoolError::WitnessHashMismatch);
        }
        let body_hash = body.body_hash();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut inner = self.inner.lock().unwrap();
        if inner.contains_key(&body_hash) {
            return Err(MempoolError::Duplicate);
        }
        if inner.len() >= self.cap {
            // Evict the oldest pending tx. Simple FIFO; v0.2 swaps to
            // fee-priority eviction.
            if let Some((oldest_hash, _)) = inner
                .iter()
                .min_by_key(|(_, t)| t.received_ms)
                .map(|(h, t)| (*h, t.clone()))
            {
                inner.remove(&oldest_hash);
            }
        }
        inner.insert(
            body_hash,
            PendingTx {
                body,
                witness,
                received_ms: now,
            },
        );
        Ok(body_hash)
    }

    /// Pull up to `max` transactions for the next block, ordered by descending
    /// fee-per-byte. Does *not* remove them — the miner only commits when the
    /// block is accepted. Use `confirm` after a block lands.
    pub fn pull_for_block(&self, max: usize) -> Vec<PendingTx> {
        let inner = self.inner.lock().unwrap();
        let mut all: Vec<PendingTx> = inner.values().cloned().collect();
        all.sort_by(|a, b| {
            let ka = a.body.fee_sat;
            let kb = b.body.fee_sat;
            kb.cmp(&ka).then_with(|| a.body.body_hash().cmp(&b.body.body_hash()))
        });
        all.truncate(max);
        all
    }

    /// Drop every tx that landed in `block_hashes`. Called after a block is
    /// committed so the mempool reflects the new chain state.
    pub fn confirm(&self, block_hashes: &[[u8; 32]]) {
        let mut inner = self.inner.lock().unwrap();
        for h in block_hashes {
            inner.remove(h);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    pub fn pending_hashes(&self) -> Vec<String> {
        self.inner
            .lock()
            .unwrap()
            .keys()
            .map(hex::encode)
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("witness hash does not match TxBody.witness_hash")]
    WitnessHashMismatch,
    #[error("transaction already in mempool")]
    Duplicate,
}
