//! Multi-threaded CPU miner. Same RPC protocol as the node-side mining tab; thread count
//! is the "intensity" knob. GPU path (v0.2) replaces the inner hash loop with an OpenCL
//! kernel and shares the counters.

use anyhow::Context;
use pygrove_consensus::pow::{hash_header, meets_target};
use pygrove_core::BlockHeader;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderJson {
    pub version: u32,
    pub height: u64,
    pub parent: String,
    pub timestamp_ms: u64,
    pub bits: u32,
    pub nonce: u64,
    pub tx_root: String,
    pub witness_root: String,
    pub state_root: String,
    pub reflect_root: String,
    pub coinbase: String,
    pub sig_algo: u8,
    pub hash_algo: u8,
}

impl TryFrom<&HeaderJson> for BlockHeader {
    type Error = anyhow::Error;
    fn try_from(j: &HeaderJson) -> anyhow::Result<Self> {
        fn h32(s: &str) -> anyhow::Result<[u8; 32]> {
            let v = hex::decode(s)?;
            if v.len() != 32 {
                anyhow::bail!("expected 32 bytes, got {}", v.len());
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            Ok(a)
        }
        Ok(BlockHeader {
            version: j.version,
            height: j.height,
            parent: h32(&j.parent)?,
            timestamp_ms: j.timestamp_ms,
            bits: j.bits,
            nonce: j.nonce,
            tx_root: h32(&j.tx_root)?,
            witness_root: h32(&j.witness_root)?,
            state_root: h32(&j.state_root)?,
            reflect_root: h32(&j.reflect_root)?,
            coinbase: h32(&j.coinbase)?,
            sig_algo: j.sig_algo,
            hash_algo: j.hash_algo,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub chain_id: String,
    pub tip_hash: String,
    pub height: u64,
    pub target_hex: String,
}

pub fn rpc_get_info(url: &str) -> anyhow::Result<NodeInfo> {
    let resp = ureq::post(&format!("{url}/rpc"))
        .timeout(Duration::from_secs(5))
        .send_json(serde_json::json!({ "method": "get_info" }))
        .context("rpc call")?;
    let v: serde_json::Value = resp.into_json()?;
    let r = v.get("result").context("no result")?;
    Ok(NodeInfo {
        chain_id: r["chain_id"].as_str().unwrap_or("").into(),
        tip_hash: r["tip_hash"].as_str().unwrap_or("").into(),
        height: r["height"].as_u64().unwrap_or(0),
        target_hex: r["target"].as_str().unwrap_or("").into(),
    })
}

fn rpc_get_template(url: &str) -> anyhow::Result<(HeaderJson, [u8; 32])> {
    let resp = ureq::post(&format!("{url}/rpc"))
        .timeout(Duration::from_secs(5))
        .send_json(serde_json::json!({ "method": "get_template" }))?;
    let v: serde_json::Value = resp.into_json()?;
    let r = v.get("result").context("no result")?;
    let header: HeaderJson = serde_json::from_value(r["header"].clone())?;
    let target_bytes = hex::decode(r["target"].as_str().unwrap_or(""))?;
    if target_bytes.len() != 32 {
        anyhow::bail!("bad target length");
    }
    let mut target = [0u8; 32];
    target.copy_from_slice(&target_bytes);
    Ok((header, target))
}

fn rpc_submit_block(url: &str, header: &HeaderJson) -> anyhow::Result<bool> {
    let resp = ureq::post(&format!("{url}/rpc"))
        .timeout(Duration::from_secs(5))
        .send_json(serde_json::json!({
            "method": "submit_block",
            "params": { "header": header }
        }))?;
    let v: serde_json::Value = resp.into_json()?;
    Ok(v.get("result").and_then(|r| r["ok"].as_bool()).unwrap_or(false))
}

pub struct MinerHandle {
    pub stop: Arc<AtomicBool>,
    pub hashes: Arc<AtomicU64>,
    pub accepted: Arc<AtomicU64>,
    pub rejected: Arc<AtomicU64>,
}

pub fn num_cpus() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

pub fn start(url: String, threads: usize) -> MinerHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let hashes = Arc::new(AtomicU64::new(0));
    let accepted = Arc::new(AtomicU64::new(0));
    let rejected = Arc::new(AtomicU64::new(0));
    let handle = MinerHandle {
        stop: stop.clone(),
        hashes: hashes.clone(),
        accepted: accepted.clone(),
        rejected: rejected.clone(),
    };
    let n = threads.max(1);
    for t in 0..n {
        let url = url.clone();
        let stop = stop.clone();
        let hashes = hashes.clone();
        let accepted = accepted.clone();
        let rejected = rejected.clone();
        thread::Builder::new()
            .name(format!("pg-miner-{t}"))
            .spawn(move || worker(t as u64, n as u64, url, stop, hashes, accepted, rejected))
            .expect("spawn miner thread");
    }
    handle
}

fn worker(
    thread_id: u64,
    stride: u64,
    url: String,
    stop: Arc<AtomicBool>,
    hashes: Arc<AtomicU64>,
    accepted: Arc<AtomicU64>,
    rejected: Arc<AtomicU64>,
) {
    while !stop.load(Ordering::Relaxed) {
        let (mut tmpl, target) = match rpc_get_template(&url) {
            Ok(t) => t,
            Err(_) => {
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        // Spread nonces across threads: thread t starts at `t`, strides by `n`.
        tmpl.nonce = thread_id;
        let refresh_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            for _ in 0..4_096 {
                let hdr: BlockHeader = match (&tmpl).try_into() {
                    Ok(h) => h,
                    Err(_) => break,
                };
                let h = hash_header(&hdr);
                hashes.fetch_add(1, Ordering::Relaxed);
                if meets_target(&h, &target) {
                    match rpc_submit_block(&url, &tmpl) {
                        Ok(true) => accepted.fetch_add(1, Ordering::Relaxed),
                        _ => rejected.fetch_add(1, Ordering::Relaxed),
                    };
                    break;
                }
                tmpl.nonce = tmpl.nonce.wrapping_add(stride);
            }
            if Instant::now() >= refresh_deadline {
                break;
            }
        }
    }
}
