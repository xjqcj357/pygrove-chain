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
use crate::mempool::Mempool;
use crate::mining::now_ms;
use pygrove_consensus::pow::{hash_header, meets_target, target_from_bits};
use pygrove_core::{AccountId, Block, BlockBody, BlockHeader, TxBody, Witness};
use pygrove_state::{accounts as state_accounts, MemState};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Response, Server};

/// Maximum JSON-RPC request body size. A submit_block payload is ~1 KB header JSON;
/// 64 KB is generous and small enough that a flood cannot OOM the node. Anything
/// larger is rejected before it touches `serde_json`.
const MAX_RPC_BODY_BYTES: u64 = 64 * 1024;

pub struct NodeState {
    pub store: ChainStore,
    pub chain_id: String,
    pub bits: u32,
    pub coinbase: [u8; 32],
    pub sig_algo: u8,
    pub hash_algo: u8,
    /// Wall-clock milliseconds at which the chain accepts block 1+ submissions.
    /// Before this, `submit_block` returns "pre-genesis: launch in Ns".
    pub genesis_time_ms: u64,
    /// In-memory account/witness state, rebuilt at startup by replaying every
    /// block from the chain log. v0.2 swaps to GroveDB-backed persistence.
    pub state: Mutex<MemState>,
    pub mempool: Arc<Mempool>,
    /// Per-block coinbase reward in satoshi. Constant in Phase A; the accordion
    /// + halving schedule kick in once we have retargets working.
    pub block_reward_sat: u128,
}

/// Bitcoin's clock-skew tolerance — a header timestamp may be at most this
/// far in the future relative to the node's wall clock.
const FUTURE_TIME_TOLERANCE_MS: u64 = 2 * 60 * 60 * 1000; // 2 hours

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
    genesis_time_ms: u64,
    /// `now_ms - genesis_time_ms`. Negative means pre-genesis (chain frozen).
    genesis_offset_ms: i64,
    mempool_size: usize,
    block_reward_sat: u128,
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
    /// Hex CBOR of each TxBody the miner should include in `body.txs`,
    /// parallel to `witnesses_cbor_hex`. Pre-baked into `header.tx_root`.
    txs_cbor_hex: Vec<String>,
    witnesses_cbor_hex: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SubmitReq {
    header: HeaderJson,
    /// Hex-encoded canonical CBOR of `pygrove_core::TxBody`, parallel to
    /// `witnesses_cbor_hex`. Empty for blocks that include no user transactions.
    #[serde(default)]
    txs_cbor_hex: Vec<String>,
    /// Hex-encoded canonical CBOR of `pygrove_core::Witness`, same length as `txs_cbor_hex`.
    #[serde(default)]
    witnesses_cbor_hex: Vec<String>,
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
    txs: Vec<TxSummary>,
}

#[derive(Debug, Serialize)]
struct TxSummary {
    hash: String,
    from: String,
    to: String,
    amount_sat: u128,
    fee_sat: u64,
    nonce: u64,
}

#[derive(Debug, Deserialize)]
struct SubmitTxReq {
    /// Hex-encoded canonical CBOR of `pygrove_core::TxBody`.
    tx_cbor_hex: String,
    /// Hex-encoded canonical CBOR of `pygrove_core::Witness`.
    witness_cbor_hex: String,
}

#[derive(Debug, Serialize)]
struct SubmitTxResp {
    ok: bool,
    tx_hash: String,
}

#[derive(Debug, Deserialize)]
struct AddrReq {
    /// bech32m `pyg1...` address.
    address: String,
}

#[derive(Debug, Serialize)]
struct BalanceResp {
    address: String,
    balance_sat: u128,
    nonce: u64,
}

#[derive(Debug, Serialize)]
struct AccountResp {
    address: String,
    balance_sat: u128,
    nonce: u64,
    has_pubkey: bool,
    sig_algo: u8,
}

#[derive(Debug, Serialize)]
struct MempoolResp {
    size: usize,
    hashes: Vec<String>,
}

const EXPLORER_HTML: &str = include_str!("explorer.html");

pub fn serve(bind: &str, state: Arc<NodeState>) -> anyhow::Result<()> {
    let server = Server::http(bind).map_err(|e| anyhow::anyhow!("bind {bind}: {e}"))?;
    tracing::info!(bind, "rpc listening");
    for mut req in server.incoming_requests() {
        let resp = match (req.method(), req.url()) {
            (Method::Post, "/rpc") => match read_bounded_body(&mut req, MAX_RPC_BODY_BYTES) {
                Err(e) => json_err(413, &e),
                Ok(body) => match serde_json::from_slice::<RpcReq>(&body) {
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

/// Read at most `max` bytes from the request body, rejecting anything larger.
/// Prevents an attacker from POSTing a multi-GB payload to OOM the node.
fn read_bounded_body(req: &mut tiny_http::Request, max: u64) -> Result<Vec<u8>, String> {
    if let Some(len) = req.body_length() {
        if len as u64 > max {
            return Err(format!("body too large: {len} > {max}"));
        }
    }
    let mut buf = Vec::new();
    let mut limited = req.as_reader().take(max + 1);
    limited
        .read_to_end(&mut buf)
        .map_err(|e| format!("read body: {e}"))?;
    if buf.len() as u64 > max {
        return Err(format!("body too large: > {max}"));
    }
    Ok(buf)
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
        "submit_tx" => match serde_json::from_value::<SubmitTxReq>(rpc.params) {
            Ok(req) => match submit_tx(st, req) {
                Ok(v) => json_ok(200, &RpcOk { result: v }),
                Err(e) => json_err(400, &e.to_string()),
            },
            Err(e) => json_err(400, &format!("bad params: {e}")),
        },
        "get_balance" => match serde_json::from_value::<AddrReq>(rpc.params) {
            Ok(req) => match get_balance(st, &req.address) {
                Ok(v) => json_ok(200, &RpcOk { result: v }),
                Err(e) => json_err(400, &e.to_string()),
            },
            Err(e) => json_err(400, &format!("bad params: {e}")),
        },
        "get_account" => match serde_json::from_value::<AddrReq>(rpc.params) {
            Ok(req) => match get_account(st, &req.address) {
                Ok(v) => json_ok(200, &RpcOk { result: v }),
                Err(e) => json_err(400, &e.to_string()),
            },
            Err(e) => json_err(400, &format!("bad params: {e}")),
        },
        "get_mempool" => json_ok(
            200,
            &RpcOk {
                result: MempoolResp {
                    size: st.mempool.len(),
                    hashes: st.mempool.pending_hashes(),
                },
            },
        ),
        m => json_err(400, &format!("unknown method: {m}")),
    }
}

fn submit_tx(st: &NodeState, req: SubmitTxReq) -> anyhow::Result<SubmitTxResp> {
    let tx_bytes = hex::decode(&req.tx_cbor_hex)
        .map_err(|e| anyhow::anyhow!("tx_cbor_hex decode: {e}"))?;
    let witness_bytes = hex::decode(&req.witness_cbor_hex)
        .map_err(|e| anyhow::anyhow!("witness_cbor_hex decode: {e}"))?;
    let body: TxBody = ciborium::de::from_reader(&tx_bytes[..])
        .map_err(|e| anyhow::anyhow!("tx CBOR parse: {e}"))?;
    let witness: Witness = ciborium::de::from_reader(&witness_bytes[..])
        .map_err(|e| anyhow::anyhow!("witness CBOR parse: {e}"))?;
    let hash = st
        .mempool
        .submit(body, witness)
        .map_err(|e| anyhow::anyhow!("mempool reject: {e}"))?;
    tracing::info!(tx_hash = %hex::encode(hash), "tx accepted into mempool");
    Ok(SubmitTxResp {
        ok: true,
        tx_hash: hex::encode(hash),
    })
}

fn parse_address(s: &str) -> anyhow::Result<AccountId> {
    AccountId::from_bech32(s).map_err(|e| anyhow::anyhow!("address: {e}"))
}

fn get_balance(st: &NodeState, address: &str) -> anyhow::Result<BalanceResp> {
    let id = parse_address(address)?;
    let state = st.state.lock().unwrap();
    let acct = state_accounts::load_or_default(&*state, &id);
    Ok(BalanceResp {
        address: address.to_string(),
        balance_sat: acct.balance,
        nonce: acct.nonce,
    })
}

fn get_account(st: &NodeState, address: &str) -> anyhow::Result<AccountResp> {
    let id = parse_address(address)?;
    let state = st.state.lock().unwrap();
    let acct = state_accounts::load_or_default(&*state, &id);
    Ok(AccountResp {
        address: address.to_string(),
        balance_sat: acct.balance,
        nonce: acct.nonce,
        has_pubkey: !acct.pubkey.is_empty(),
        sig_algo: acct.sig_algo,
    })
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
    Ok(st.store.get_by_height(height)?.map(|b| {
        let txs: Vec<TxSummary> = b
            .body
            .txs
            .iter()
            .map(|tx| {
                let (to_addr, amount) = match &tx.call {
                    pygrove_core::TxCall::Transfer { to, amount } => {
                        (to.to_string(), *amount)
                    }
                    _ => ("(non-transfer)".into(), 0u128),
                };
                TxSummary {
                    hash: hex::encode(tx.body_hash()),
                    from: tx.from_account.to_string(),
                    to: to_addr,
                    amount_sat: amount,
                    fee_sat: tx.fee_sat,
                    nonce: tx.nonce,
                }
            })
            .collect();
        BlockDetail {
            hash: hex::encode(hash_header(&b.header)),
            tx_count: b.body.txs.len(),
            header: HeaderJson::from(&b.header),
            txs,
        }
    }))
}

fn info(st: &NodeState) -> anyhow::Result<InfoResp> {
    let tip = st.store.tip()?;
    let (height, tip_hash) = match tip {
        Some(b) => (b.header.height, hex::encode(hash_header(&b.header))),
        None => (0, hex::encode([0u8; 32])),
    };
    let now = crate::mining::now_ms();
    let offset = now as i64 - st.genesis_time_ms as i64;
    Ok(InfoResp {
        chain_id: st.chain_id.clone(),
        height,
        tip_hash,
        bits: st.bits,
        target: hex::encode(target_from_bits(st.bits)),
        sig_algo: st.sig_algo,
        hash_algo: st.hash_algo,
        genesis_time_ms: st.genesis_time_ms,
        genesis_offset_ms: offset,
        mempool_size: st.mempool.len(),
        block_reward_sat: st.block_reward_sat,
    })
}

fn template(st: &NodeState) -> anyhow::Result<TemplateResp> {
    let tip = st.store.tip()?;
    let (parent_hash, parent_height) = match tip {
        Some(b) => (hash_header(&b.header), b.header.height),
        None => ([0u8; 32], 0),
    };
    let pending = st.mempool.pull_for_block(256);
    let txs: Vec<TxBody> = pending.iter().map(|p| p.body.clone()).collect();
    let witnesses: Vec<Witness> = pending.iter().map(|p| p.witness.clone()).collect();
    let body = BlockBody {
        txs: txs.clone(),
        witnesses: witnesses.clone(),
    };
    let hdr = crate::mining::template_from_parent_with_body(
        parent_hash,
        parent_height,
        st.bits,
        st.coinbase,
        st.sig_algo,
        st.hash_algo,
        now_ms(),
        &body,
    );
    let mut tx_hex = Vec::with_capacity(txs.len());
    for tx in &txs {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(tx, &mut buf)
            .map_err(|e| anyhow::anyhow!("tx encode: {e}"))?;
        tx_hex.push(hex::encode(buf));
    }
    let mut wit_hex = Vec::with_capacity(witnesses.len());
    for w in &witnesses {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(w, &mut buf)
            .map_err(|e| anyhow::anyhow!("witness encode: {e}"))?;
        wit_hex.push(hex::encode(buf));
    }
    Ok(TemplateResp {
        header: HeaderJson::from(&hdr),
        target: hex::encode(target_from_bits(st.bits)),
        txs_cbor_hex: tx_hex,
        witnesses_cbor_hex: wit_hex,
    })
}

fn submit(st: &NodeState, req: SubmitReq) -> anyhow::Result<SubmitResp> {
    let hdr: BlockHeader = req.header.try_into()?;
    if req.txs_cbor_hex.len() != req.witnesses_cbor_hex.len() {
        anyhow::bail!(
            "txs/witnesses length mismatch: {} txs, {} witnesses",
            req.txs_cbor_hex.len(),
            req.witnesses_cbor_hex.len()
        );
    }
    let mut txs = Vec::with_capacity(req.txs_cbor_hex.len());
    for (i, s) in req.txs_cbor_hex.iter().enumerate() {
        let bytes = hex::decode(s).map_err(|e| anyhow::anyhow!("tx[{i}] hex: {e}"))?;
        let tx: TxBody = ciborium::de::from_reader(&bytes[..])
            .map_err(|e| anyhow::anyhow!("tx[{i}] cbor: {e}"))?;
        txs.push(tx);
    }
    let mut witnesses = Vec::with_capacity(req.witnesses_cbor_hex.len());
    for (i, s) in req.witnesses_cbor_hex.iter().enumerate() {
        let bytes = hex::decode(s).map_err(|e| anyhow::anyhow!("witness[{i}] hex: {e}"))?;
        let w: Witness = ciborium::de::from_reader(&bytes[..])
            .map_err(|e| anyhow::anyhow!("witness[{i}] cbor: {e}"))?;
        witnesses.push(w);
    }
    let block = Block {
        header: hdr.clone(),
        body: BlockBody { txs, witnesses },
    };
    try_apply_block(st, &block)?;
    Ok(SubmitResp {
        ok: true,
        height: hdr.height,
        hash: hex::encode(hash_header(&hdr)),
    })
}

/// Single source of truth for "is this block acceptable right now?". Both the
/// JSON-RPC `submit_block` and the in-process self-miner go through this. Any
/// rule that gates fair launch must live here; otherwise the self-miner can
/// quietly bypass it.
pub fn try_apply_block(st: &NodeState, block: &Block) -> anyhow::Result<()> {
    let now = crate::mining::now_ms();
    // 1. Fair-launch hard gate.
    if now < st.genesis_time_ms {
        let secs = (st.genesis_time_ms - now) / 1000;
        anyhow::bail!(
            "pre-genesis: launch in {}s (genesis_time_ms={}, now_ms={})",
            secs,
            st.genesis_time_ms,
            now
        );
    }

    let hdr = &block.header;
    let tip = st.store.tip()?;
    let (expected_parent, expected_height, parent_ts) = match tip {
        Some(b) => (
            hash_header(&b.header),
            b.header.height + 1,
            b.header.timestamp_ms,
        ),
        None => ([0u8; 32], 0, 0),
    };
    if hdr.parent != expected_parent {
        anyhow::bail!("stale parent");
    }
    if hdr.height != expected_height {
        anyhow::bail!(
            "wrong height: got {} expected {}",
            hdr.height,
            expected_height
        );
    }
    if hdr.bits != st.bits {
        anyhow::bail!("wrong bits");
    }
    // 2. Monotonic time: a block may not be timestamped before its parent.
    if hdr.timestamp_ms < parent_ts {
        anyhow::bail!(
            "non-monotonic timestamp: {} < parent {}",
            hdr.timestamp_ms,
            parent_ts
        );
    }
    // 3. Bitcoin-style 2-hour clock-skew tolerance.
    if hdr.timestamp_ms > now + FUTURE_TIME_TOLERANCE_MS {
        anyhow::bail!(
            "timestamp too far in future: {} > now+2h ({})",
            hdr.timestamp_ms,
            now + FUTURE_TIME_TOLERANCE_MS
        );
    }
    // 4. PoW.
    let target = target_from_bits(hdr.bits);
    let h = hash_header(hdr);
    if !meets_target(&h, &target) {
        anyhow::bail!("hash does not meet target");
    }
    // 5. Body roots: header.tx_root and header.witness_root must commit to
    //    the body the miner is publishing.
    let computed_tx_root = block.body.tx_root();
    if hdr.tx_root != computed_tx_root {
        anyhow::bail!(
            "tx_root mismatch: header={} body={}",
            hex::encode(hdr.tx_root),
            hex::encode(computed_tx_root)
        );
    }
    let computed_witness_root = block.body.witness_root();
    if hdr.witness_root != computed_witness_root {
        anyhow::bail!(
            "witness_root mismatch: header={} body={}",
            hex::encode(hdr.witness_root),
            hex::encode(computed_witness_root)
        );
    }
    // 6. Apply state transitions. Genesis (height 0) doesn't pay block reward —
    //    it would mint to the headline-derived address, which nobody owns.
    let reward = if hdr.height == 0 {
        0
    } else {
        st.block_reward_sat
    };
    let mut state = st.state.lock().unwrap();
    let out = pygrove_state::apply_block(&mut *state, block, reward)
        .map_err(|e| anyhow::anyhow!("apply_block: {e}"))?;
    drop(state);
    // 7. Drop confirmed txs from the mempool. Computed *after* apply because
    //    apply uses tx_body_hash, and only after success do we want to evict.
    let confirmed: Vec<[u8; 32]> = block.body.txs.iter().map(|t| t.body_hash()).collect();
    st.mempool.confirm(&confirmed);
    // 8. Persist to chain log.
    st.store.append(block)?;
    tracing::debug!(
        height = hdr.height,
        txs = out.txs_applied,
        fees = %out.fees_collected_sat,
        "block applied"
    );
    Ok(())
}
