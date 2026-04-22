//! Block and header types. The header is the only thing that enters the PoW hash.

use serde::{Deserialize, Serialize};
use crate::tx::TxBody;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockBody {
    pub txs: Vec<TxBody>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
}
