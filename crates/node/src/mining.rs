//! Block template builder + local mine-to-completion helper.
//!
//! Remote miners (`pygrove-gui` Mining tab) drive production in practice; this module
//! exists so `pygrove-node init` can mine the genesis block inline and so `--mine` can
//! self-mine in a background thread when no remote miner is attached.

use pygrove_consensus::pow::{hash_header, meets_target, target_from_bits};
use pygrove_core::{Block, BlockBody, BlockHeader};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build a non-mined (nonce = 0) header for a given tip.
pub fn template_from_parent(
    parent_hash: [u8; 32],
    parent_height: u64,
    bits: u32,
    coinbase: [u8; 32],
    sig_algo: u8,
    hash_algo: u8,
    timestamp_ms: u64,
) -> BlockHeader {
    BlockHeader {
        version: 1,
        height: parent_height + 1,
        parent: parent_hash,
        timestamp_ms,
        bits,
        nonce: 0,
        tx_root: [0; 32],
        witness_root: [0; 32],
        state_root: [0; 32],
        reflect_root: [0; 32],
        coinbase,
        sig_algo,
        hash_algo,
    }
}

/// Mine a header to completion on the current thread. Used for genesis only.
pub fn mine_inline(mut header: BlockHeader) -> Block {
    let target = target_from_bits(header.bits);
    loop {
        let h = hash_header(&header);
        if meets_target(&h, &target) {
            break;
        }
        header.nonce = header.nonce.wrapping_add(1);
    }
    Block {
        header,
        body: BlockBody { txs: vec![] },
    }
}
