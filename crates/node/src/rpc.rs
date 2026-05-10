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
    /// Initial per-block reward in satoshi (`initial_reward_sat` from genesis).
    /// Pre-halving-1; later epochs derive via `>> epoch`.
    pub block_reward_sat: u128,
    /// Bitcoin's 10-minute target. Used to compute the "planned" emission
    /// curve the explorer / info page draws against the actual one.
    pub target_block_time_ms: u64,
    /// Halving interval in blocks. Reflected to the client so the planned
    /// curve out to year 127 is properly halving-aware (not linear).
    pub halving_interval_base: u64,
    /// Calendar-emission params (seconds-per-halving etc). Drives the
    /// `current_reward()` computation in `try_apply_block`.
    pub emission: pygrove_consensus::emission::EmissionParams,
    /// Cumulative supply minted so far. Updated atomically with chainstore
    /// on each successful `try_apply_block`. Used as input to the next
    /// block's reward computation.
    pub minted_so_far: Mutex<u128>,
    /// Last applied block's reward (sat). Used by the slew-rate limiter so
    /// per-block emission cannot change by more than
    /// `emission.max_reward_pct_change_per_block` percent across consecutive
    /// blocks. `None` until the first non-genesis block lands.
    pub prev_reward_sat: Mutex<Option<u128>>,
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
struct EmissionSeriesReq {
    /// Time horizon to sample, in seconds. The server returns points covering
    /// `[tip_timestamp - window_seconds, tip_timestamp]`.
    window_seconds: u64,
    /// Approximate number of samples to return (sparsely sampled if the window
    /// contains more blocks than this). Hard cap at 500.
    #[serde(default = "default_emission_points")]
    points: usize,
}
fn default_emission_points() -> usize {
    240
}

#[derive(Debug, Serialize)]
struct EmissionPoint {
    height: u64,
    timestamp_ms: u64,
    /// Cumulative supply minted up to and including this block, in sat.
    minted_sat: u128,
}

#[derive(Debug, Serialize)]
struct EmissionSeriesResp {
    /// Samples newest-last so the chart can append directly.
    samples: Vec<EmissionPoint>,
    /// Wall-clock timestamp of the genesis block — anchor for the planned curve.
    genesis_time_ms: u64,
    /// Per-block reward at the **current** halving epoch. The planned curve has
    /// to apply halvings to this; v0.1 testnet hasn't halved yet so this is
    /// also the launch reward.
    block_reward_sat: u128,
    /// Mainnet target block time (`target_block_time_ms` from genesis.toml).
    /// Planned blocks per second = `1000 / target_block_time_ms`.
    target_block_time_ms: u64,
    /// Halving interval in blocks (`halving_interval_base` from genesis.toml).
    /// Lets the client draw the full halving schedule out to the design
    /// horizon — e.g. 127 years.
    halving_interval_base: u64,
}

/// Mobile / browser wallet path. Same effect as `submit_tx` but the wallet
/// only needs ed25519 + blake3 + bech32 client-side — the server handles
/// CBOR. The wallet computes `signing_hash` itself, so the server can't
/// trick it into signing different fields than the user filled in: any
/// mismatch makes the verify step fail.
#[derive(Debug, Deserialize)]
struct SubmitTransferReq {
    /// bech32m `pyg1...` of the sender. Must derive from `pubkey_hex`.
    from_address: String,
    /// bech32m `pyg1...` of the recipient.
    to_address: String,
    amount_sat: u128,
    fee_sat: u64,
    /// Sender's current account nonce. Wallet fetched it via `get_account`.
    nonce: u64,
    /// Sender's pubkey. 32 bytes (Ed25519). hex.
    pubkey_hex: String,
    /// Ed25519 signature over `signing_hash`. 64 bytes. hex.
    sig_hex: String,
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
        "submit_transfer" => match serde_json::from_value::<SubmitTransferReq>(rpc.params) {
            Ok(req) => match submit_transfer(st, req) {
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
        "emission_series" => match serde_json::from_value::<EmissionSeriesReq>(rpc.params) {
            Ok(req) => match emission_series(st, req) {
                Ok(v) => json_ok(200, &RpcOk { result: v }),
                Err(e) => json_err(500, &e.to_string()),
            },
            Err(e) => json_err(400, &format!("bad params: {e}")),
        },
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

fn emission_series(
    st: &NodeState,
    req: EmissionSeriesReq,
) -> anyhow::Result<EmissionSeriesResp> {
    let points = req.points.clamp(2, 500);
    let all = st.store.load_all()?;
    if all.is_empty() {
        return Ok(EmissionSeriesResp {
            samples: vec![],
            genesis_time_ms: st.genesis_time_ms,
            block_reward_sat: st.block_reward_sat,
            target_block_time_ms: st.target_block_time_ms,
            halving_interval_base: st.halving_interval_base,
        });
    }
    // Anchor at the latest block in the chain log so the chart's right edge
    // is always "now according to the chain", not wall-clock.
    let tip_ts = all.last().unwrap().header.timestamp_ms;
    let cutoff_ms = tip_ts.saturating_sub(req.window_seconds.saturating_mul(1000));
    let in_window: Vec<_> = all
        .iter()
        .filter(|b| b.header.timestamp_ms >= cutoff_ms)
        .collect();
    if in_window.is_empty() {
        return Ok(EmissionSeriesResp {
            samples: vec![],
            genesis_time_ms: st.genesis_time_ms,
            block_reward_sat: st.block_reward_sat,
            target_block_time_ms: st.target_block_time_ms,
            halving_interval_base: st.halving_interval_base,
        });
    }
    // Replay calendar rewards over the entire chain to get correct cumulative
    // values, with the same bootstrap-cap + slew-rate path the live node
    // applies, so the chart matches what's actually on-chain.
    let mut cumulative_by_height: std::collections::HashMap<u64, u128> =
        std::collections::HashMap::new();
    let mut running: u128 = 0;
    let mut prev_reward: Option<u128> = None;
    cumulative_by_height.insert(0, 0);
    for i in 1..all.len() {
        let b = &all[i];
        let parent_ts = all[i - 1].header.timestamp_ms;
        let reward = pygrove_consensus::emission::current_reward_with_height(
            &st.emission,
            st.genesis_time_ms,
            b.header.timestamp_ms,
            parent_ts,
            running,
            b.header.height,
            prev_reward,
        );
        running = running.saturating_add(reward);
        prev_reward = Some(reward);
        cumulative_by_height.insert(b.header.height, running);
    }
    // Stride so we return ~`points` samples evenly across the window.
    let stride = (in_window.len() / points).max(1);
    let mut samples = Vec::with_capacity(points + 2);
    for (i, b) in in_window.iter().enumerate() {
        if i % stride == 0 {
            let minted = *cumulative_by_height.get(&b.header.height).unwrap_or(&0);
            samples.push(EmissionPoint {
                height: b.header.height,
                timestamp_ms: b.header.timestamp_ms,
                minted_sat: minted,
            });
        }
    }
    let last = in_window.last().unwrap();
    let last_h = last.header.height;
    if samples.last().map(|s| s.height) != Some(last_h) {
        samples.push(EmissionPoint {
            height: last_h,
            timestamp_ms: last.header.timestamp_ms,
            minted_sat: *cumulative_by_height.get(&last_h).unwrap_or(&0),
        });
    }
    Ok(EmissionSeriesResp {
        samples,
        genesis_time_ms: st.genesis_time_ms,
        block_reward_sat: st.block_reward_sat,
        target_block_time_ms: st.target_block_time_ms,
        halving_interval_base: st.halving_interval_base,
    })
}

fn submit_transfer(st: &NodeState, req: SubmitTransferReq) -> anyhow::Result<SubmitTxResp> {
    use pygrove_core::{PubKeyRef, TxCall};
    let from = parse_address(&req.from_address)?;
    let to = parse_address(&req.to_address)?;
    let pubkey =
        hex::decode(&req.pubkey_hex).map_err(|e| anyhow::anyhow!("pubkey hex: {e}"))?;
    let sig = hex::decode(&req.sig_hex).map_err(|e| anyhow::anyhow!("sig hex: {e}"))?;
    // Defence in depth: the sender's claimed address must match the pubkey
    // they're using. Catches mistakes before we waste a sig-verify cycle.
    let derived = AccountId::from_pubkey(&pubkey);
    if derived != from {
        anyhow::bail!(
            "from_address does not derive from pubkey: claimed={}, derived={}",
            from,
            derived
        );
    }
    // Build the canonical TxBody. witness_hash is filled in after we know
    // the witness shape (Inline vs Known); signing_hash excludes it anyway.
    let mut tx = TxBody {
        nonce: req.nonce,
        from_account: from,
        call: TxCall::Transfer {
            to,
            amount: req.amount_sat,
        },
        fee_sat: req.fee_sat,
        gas_limit: 21_000,
        witness_hash: [0u8; 32],
    };
    let signing_hash = tx.signing_hash();
    // Phase A bringup signature: Ed25519 (sig_algo = 3).
    pygrove_crypto::verify(3, &pubkey, &sig, &signing_hash)
        .map_err(|e| anyhow::anyhow!("signature: {e}"))?;
    // Pubkey shape: Inline if this account hasn't signed before, Known
    // (cheaper) if its key is already committed to state.
    let pubkey_ref = {
        let state = st.state.lock().unwrap();
        let acct = pygrove_state::accounts::load_or_default(&*state, &from);
        if acct.pubkey.is_empty() {
            PubKeyRef::Inline(pubkey)
        } else {
            PubKeyRef::Known(from)
        }
    };
    let witness = pygrove_core::Witness {
        sig_algo: 3,
        sig,
        pubkey: pubkey_ref,
    };
    tx.witness_hash = witness.hash();
    let hash = st
        .mempool
        .submit(tx, witness)
        .map_err(|e| anyhow::anyhow!("mempool reject: {e}"))?;
    tracing::info!(
        from = %from,
        to_addr = %req.to_address,
        amount = req.amount_sat,
        tx_hash = %hex::encode(hash),
        "submit_transfer accepted"
    );
    Ok(SubmitTxResp {
        ok: true,
        tx_hash: hex::encode(hash),
    })
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
    // 6. Apply state transitions. Reward is calendar-anchored: a block's
    //    coinbase pays the delta between scheduled supply at its timestamp
    //    and what's already been minted, capped per-block. Genesis (height 0)
    //    earns zero by construction (block_timestamp_ms == genesis_time_ms).
    let parent_ts = match st.store.tip()? {
        Some(b) => b.header.timestamp_ms,
        None => st.genesis_time_ms,
    };
    let minted = *st.minted_so_far.lock().unwrap();
    let prev_reward = *st.prev_reward_sat.lock().unwrap();
    let reward = pygrove_consensus::emission::current_reward_with_height(
        &st.emission,
        st.genesis_time_ms,
        hdr.timestamp_ms,
        parent_ts,
        minted,
        hdr.height,
        prev_reward,
    );
    let mut state = st.state.lock().unwrap();
    let out = pygrove_state::apply_block(&mut *state, block, reward)
        .map_err(|e| anyhow::anyhow!("apply_block: {e}"))?;
    drop(state);
    // Track cumulative emission + last-block reward. Order matters: only
    // after apply_block returns Ok do we credit the counters.
    *st.minted_so_far.lock().unwrap() = minted.saturating_add(reward);
    *st.prev_reward_sat.lock().unwrap() = Some(reward);
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
