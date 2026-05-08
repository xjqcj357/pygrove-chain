//! Wallet-side RPC helpers — separate from `miner::rpc_*` so the wallet path
//! and the mining path don't fight over imports. Both ultimately hit the same
//! tiny_http endpoint on the node.

use anyhow::{anyhow, Context};
use pygrove_core::AccountId;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct AccountInfo {
    pub balance_sat: u128,
    pub nonce: u64,
    pub has_pubkey: bool,
}

/// Look up an account's balance + nonce + has-pubkey state.
pub fn get_account(url: &str, address: &AccountId) -> anyhow::Result<AccountInfo> {
    let resp = ureq::post(&format!("{url}/rpc"))
        .timeout(Duration::from_secs(5))
        .send_json(serde_json::json!({
            "method": "get_account",
            "params": { "address": address.to_bech32() }
        }))
        .context("rpc get_account")?;
    let v: serde_json::Value = resp.into_json()?;
    let r = v.get("result").context("no result")?;
    Ok(AccountInfo {
        balance_sat: r["balance_sat"].as_u64().unwrap_or(0) as u128, // u64 fits Phase A balances
        nonce: r["nonce"].as_u64().unwrap_or(0),
        has_pubkey: r["has_pubkey"].as_bool().unwrap_or(false),
    })
}

/// Submit a serialized (TxBody, Witness) pair to the node mempool.
pub fn submit_tx(url: &str, tx_cbor_hex: &str, witness_cbor_hex: &str) -> anyhow::Result<String> {
    let resp = ureq::post(&format!("{url}/rpc"))
        .timeout(Duration::from_secs(5))
        .send_json(serde_json::json!({
            "method": "submit_tx",
            "params": {
                "tx_cbor_hex": tx_cbor_hex,
                "witness_cbor_hex": witness_cbor_hex,
            }
        }))
        .context("rpc submit_tx")?;
    let v: serde_json::Value = resp.into_json()?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        return Err(anyhow!("node rejected tx: {err}"));
    }
    let r = v.get("result").context("no result")?;
    let hash = r["tx_hash"].as_str().context("no tx_hash")?;
    Ok(hash.to_string())
}
