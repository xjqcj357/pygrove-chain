//! Minimal HTTP JSON-RPC for miner clients + an embedded block explorer.
//!
//! Methods:
//!   get_info       -> { height, tip_hash, bits, target, chain_id, sig_algo, hash_algo }
//!   get_template   -> { header, target, target_hex }
//!   submit_block   -> { ok, height, hash }  |  { error }
//!   list_blocks    -> [{ height, hash, timestamp_ms, nonce, tx_count }]
//!   get_block      -> { header, tx_count, hash }
//!
//! HTTP GET /  serves the bundled explorer (dark-theme HTML, polls /rpc).
//!
//! One thread per connection (tiny_http default). Sync. State is a shared `Arc<NodeState>`.

use crate::chainstore::ChainStore;
use crate::mining::{now_ms, template_from_parent};
use pygrove_consensus::pow::{hash_header, meets_target, target_from_bits};
use pygrove_core::{Block, BlockBody, BlockHeader};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tiny_http::{Header, Method, Response, Server};

pub struct NodeState {
    pub store: ChainStore,
    pub chain_id: String,
    pub bits: u32,
    pub coinbase: [u8; 32],
    pub sig_algo: u8,
    pub hash_algo: u8,
}

#[derive(Debug, Deserialize)]
struct RpcReq {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct RpcOk<T: Serialize> {
    result: T,
}

#[derive(Debug, Serialize)]
struct RpcErr {
    error: String,
}

#[derive(Debug, Serialize)]
struct InfoResp {
    chain_id: String,
    height: u64,
    tip_hash: String,
    bits: u32,
    target: String,
    sig_algo: u8,
    hash_algo: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

impl From<&BlockHeader> for HeaderJson {
    fn from(h: &BlockHeader) -> Self {
        HeaderJson {
            version: h.version,
            height: h.height,
            parent: hex::encode(h.parent),
            timestamp_ms: h.timestamp_ms,
            bits: h.bits,
            nonce: h.nonce,
            tx_root: hex::encode(h.tx_root),
            witness_root: hex::encode(h.witness_root),
            state_root: hex::encode(h.state_root),
            reflect_root: hex::encode(h.reflect_root),
            coinbase: hex::encode(h.coinbase),
            sig_algo: h.sig_algo,
            hash_algo: h.hash_algo,
        }
    }
}

fn hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    let v = hex::decode(s)?;
    if v.len() != 32 {
        anyhow::bail!("expected 32-byte hex, got {}", v.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

impl TryFrom<HeaderJson> for BlockHeader {
    type Error = anyhow::Error;
    fn try_from(j: HeaderJson) -> Result<Self, Self::Error> {
        Ok(BlockHeader {
            version: j.version,
            height: j.height,
            parent: hex32(&j.parent)?,
            timestamp_ms: j.timestamp_ms,
            bits: j.bits,
            nonce: j.nonce,
            tx_root: hex32(&j.tx_root)?,
            witness_root: hex32(&j.witness_root)?,
            state_root: hex32(&j.state_root)?,
            reflect_root: hex32(&j.reflect_root)?,
            coinbase: hex32(&j.coinbase)?,
            sig_algo: j.sig_algo,
            hash_algo: j.hash_algo,
        })
    }
}

#[derive(Debug, Serialize)]
struct TemplateResp {
    header: HeaderJson,
    target: String,
}

#[derive(Debug, Deserialize)]
struct SubmitReq {
    header: HeaderJson,
}

#[derive(Debug, Serialize)]
struct SubmitResp {
    ok: bool,
    height: u64,
    hash: String,
}

#[derive(Debug, Deserialize)]
struct ListReq {
    #[serde(default = "default_list_limit")]
    limit: usize,
}
fn default_list_limit() -> usize {
    50
}

#[derive(Debug, Serialize)]
struct BlockSummary {
    height: u64,
    hash: String,
    timestamp_ms: u64,
    nonce: u64,
    tx_count: usize,
}

#[derive(Debug, Deserialize)]
struct GetBlockReq {
    height: u64,
}

#[derive(Debug, Serialize)]
struct BlockDetail {
    hash: String,
    tx_count: usize,
    header: HeaderJson,
}

const EXPLORER_HTML: &str = include_str!("explorer.html");

pub fn serve(bind: &str, state: Arc<NodeState>) -> anyhow::Result<()> {
    let server = Server::http(bind).map_err(|e| anyhow::anyhow!("bind {bind}: {e}"))?;
    tracing::info!(bind, "rpc listening");
    for mut req in server.incoming_requests() {
        let resp = match (req.method(), req.url()) {
            (Method::Post, "/rpc") => match std::io::read_to_string(req.as_reader()) {
                Err(_) => json_err(400, "read body"),
                Ok(body) => match serde_json::from_str::<RpcReq>(&body) {
                    Ok(rpc) => dispatch(rpc, &state),
                    Err(e) => json_err(400, &format!("bad request: {e}")),
                },
            },
            (Method::Get, "/") | (Method::Get, "/index.html") => html_ok(EXPLORER_HTML),
            (Method::Get, "/healthz") => json_ok(200, &serde_json::json!({ "pygrove": "v0.1" })),
            _ => json_err(404, "not found"),
        };
        let _ = req.respond(resp);
    }
    Ok(())
}

fn json_ok<T: Serialize>(code: u16, body: &T) -> Response<std::io::Cursor<Vec<u8>>> {
    let s = serde_json::to_string(body).unwrap_or_else(|_| "{}".into());
    let h: Header = "Content-Type: application/json".parse().unwrap();
    Response::from_string(s)
        .with_status_code(code)
        .with_header(h)
}

fn json_err(code: u16, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    json_ok(code, &RpcErr { error: msg.into() })
}

fn html_ok(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let h: Header = "Content-Type: text/html; charset=utf-8".parse().unwrap();
    Response::from_string(body.to_string())
        .with_status_code(200)
        .with_header(h)
}

fn dispatch(rpc: RpcReq, st: &NodeState) -> Response<std::io::Cursor<Vec<u8>>> {
    match rpc.method.as_str() {
        "get_info" => match info(st) {
            Ok(v) => json_ok(200, &RpcOk { result: v }),
            Err(e) => json_err(500, &e.to_string()),
        },
        "get_template" => match template(st) {
            Ok(v) => json_ok(200, &RpcOk { result: v }),
            Err(e) => json_err(500, &e.to_string()),
        },
        "submit_block" => match serde_json::from_value::<SubmitReq>(rpc.params) {
            Ok(req) => match submit(st, req) {
                Ok(v) => json_ok(200, &RpcOk { result: v }),
                Err(e) => json_err(400, &e.to_string()),
            },
            Err(e) => json_err(400, &format!("bad params: {e}")),
        },
        "list_blocks" => {
            let req: ListReq = serde_json::from_value(rpc.params).unwrap_or(ListReq { limit: 50 });
            match list_blocks(st, req.limit.min(500)) {
                Ok(v) => json_ok(200, &RpcOk { result: v }),
                Err(e) => json_err(500, &e.to_string()),
            }
        }
        "get_block" => match serde_json::from_value::<GetBlockReq>(rpc.params) {
            Ok(req) => match get_block(st, req.height) {
                Ok(Some(v)) => json_ok(200, &RpcOk { result: v }),
                Ok(None) => json_err(404, "block not found"),
                Err(e) => json_err(500, &e.to_string()),
            },
            Err(e) => json_err(400, &format!("bad params: {e}")),
        },
        m => json_err(400, &format!("unknown method: {m}")),
    }
}

fn list_blocks(st: &NodeState, limit: usize) -> anyhow::Result<Vec<BlockSummary>> {
    let recent = st.store.recent(limit)?;
    Ok(recent
        .into_iter()
        .map(|b| BlockSummary {
            height: b.header.height,
            hash: hex::encode(hash_header(&b.header)),
            timestamp_ms: b.header.timestamp_ms,
            nonce: b.header.nonce,
            tx_count: b.body.txs.len(),
        })
        .collect())
}

fn get_block(st: &NodeState, height: u64) -> anyhow::Result<Option<BlockDetail>> {
    Ok(st.store.get_by_height(height)?.map(|b| BlockDetail {
        hash: hex::encode(hash_header(&b.header)),
        tx_count: b.body.txs.len(),
        header: HeaderJson::from(&b.header),
    }))
}

fn info(st: &NodeState) -> anyhow::Result<InfoResp> {
    let tip = st.store.tip()?;
    let (height, tip_hash) = match tip {
        Some(b) => (b.header.height, hex::encode(hash_header(&b.header))),
        None => (0, hex::encode([0u8; 32])),
    };
    Ok(InfoResp {
        chain_id: st.chain_id.clone(),
        height,
        tip_hash,
        bits: st.bits,
        target: hex::encode(target_from_bits(st.bits)),
        sig_algo: st.sig_algo,
        hash_algo: st.hash_algo,
    })
}

fn template(st: &NodeState) -> anyhow::Result<TemplateResp> {
    let tip = st.store.tip()?;
    let (parent_hash, parent_height) = match tip {
        Some(b) => (hash_header(&b.header), b.header.height),
        None => ([0u8; 32], 0),
    };
    let hdr = template_from_parent(
        parent_hash,
        parent_height,
        st.bits,
        st.coinbase,
        st.sig_algo,
        st.hash_algo,
        now_ms(),
    );
    Ok(TemplateResp {
        header: HeaderJson::from(&hdr),
        target: hex::encode(target_from_bits(st.bits)),
    })
}

fn submit(st: &NodeState, req: SubmitReq) -> anyhow::Result<SubmitResp> {
    let hdr: BlockHeader = req.header.try_into()?;
    let tip = st.store.tip()?;
    let (expected_parent, expected_height) = match tip {
        Some(b) => (hash_header(&b.header), b.header.height + 1),
        None => ([0u8; 32], 0),
    };
    if hdr.parent != expected_parent {
        anyhow::bail!("stale parent");
    }
    if hdr.height != expected_height {
        anyhow::bail!("wrong height: got {} expected {}", hdr.height, expected_height);
    }
    if hdr.bits != st.bits {
        anyhow::bail!("wrong bits");
    }
    let target = target_from_bits(hdr.bits);
    let h = hash_header(&hdr);
    if !meets_target(&h, &target) {
        anyhow::bail!("hash does not meet target");
    }
    let block = Block {
        header: hdr,
        body: BlockBody { txs: vec![] },
    };
    st.store.append(&block)?;
    Ok(SubmitResp {
        ok: true,
        height: block.header.height,
        hash: hex::encode(h),
    })
}
