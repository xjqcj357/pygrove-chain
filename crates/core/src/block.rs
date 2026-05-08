//! Block and header types. The header is the only thing that enters the PoW hash.

use serde::{Deserialize, Serialize};
use crate::tx::{vec_root, TxBody, Witness};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub height: u64,
    pub parent: [u8; 32],
    pub timestamp_ms: u64,
    pub bits: u32,
    pub nonce: u64,
    pub tx_root: [u8; 32],
    pub witness_root: [u8; 32],
    pub state_root: [u8; 32],
    pub reflect_root: [u8; 32],
    pub coinbase: [u8; 32],
    pub sig_algo: u8,
    pub hash_algo: u8,
}

/// Block body carries transactions plus their witnesses parallel-by-index.
/// A miner that publishes `body.txs[i]` must publish `body.witnesses[i]` —
/// the consensus check requires `Witness::hash() == TxBody.witness_hash`.
///
/// In v0.2 the witnesses move to a separate body type that can be pruned
/// from archival nodes; the header's `witness_root` already commits to them
/// so consensus survives without storing them locally.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockBody {
    pub txs: Vec<TxBody>,
    #[serde(default)]
    pub witnesses: Vec<Witness>,
}

impl BlockBody {
    /// Domain-tagged root of all `TxBody.body_hash()` values, in tx order.
    pub fn tx_root(&self) -> [u8; 32] {
        let leaves: Vec<[u8; 32]> = self.txs.iter().map(TxBody::body_hash).collect();
        vec_root(b"PGtxroot\x00", &leaves)
    }

    /// Domain-tagged root of all `Witness::hash()` values, in tx order.
    pub fn witness_root(&self) -> [u8; 32] {
        let leaves: Vec<[u8; 32]> = self.witnesses.iter().map(Witness::hash).collect();
        vec_root(b"PGwitroot\x00", &leaves)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
}
