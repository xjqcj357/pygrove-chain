//! `pygrove-cli` — JSON-RPC client for a running `pygrove-node`.
//!
//! All commands POST to `--rpc <url>` (default `http://localhost:8545/rpc`).
//! Output is human-readable; pass `--json` to get raw JSON for scripting.

use clap::{Parser, Subcommand};
use serde::Deserialize;
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(
    name = "pygrove-cli",
    version,
    about = "PyGrove Chain RPC client",
    long_about = "Query a running pygrove-node over JSON-RPC. Default endpoint is \
                  http://localhost:8545/rpc. Pass --rpc to point elsewhere \
                  (e.g. https://str4w.com/api/testnet/rpc)."
)]
struct Cli {
    /// RPC endpoint. Defaults to the local node at port 8545.
    #[arg(long, default_value = "http://localhost:8545/rpc", global = true)]
    rpc: String,

    /// Emit raw JSON instead of human-readable formatting.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Chain identity, tip, current bits, lockout status, mempool size.
    GetInfo,

    /// Show block at a given height (header + tx summaries).
    ShowBlock {
        /// Block height. Use 0 for genesis.
        height: u64,
    },

    /// List the N most recent blocks (default 10).
    ListBlocks {
        #[arg(long, default_value = "10")]
        limit: usize,
    },

    /// Balance for a `pyg1...` address.
    GetBalance {
        /// Bech32 address.
        address: String,
    },

    /// Full account state: balance, nonce, registered pubkey, sig_algo.
    GetAccount {
        /// Bech32 address.
        address: String,
    },

    /// Submit a signed transaction. Pass `--tx-cbor-hex` and `--witness-cbor-hex`
    /// (both produced by an external signer). Use `submit-transfer` instead for
    /// the convenience path that signs locally from a secret-key file.
    SubmitTx {
        /// Hex of canonical CBOR for the TxBody.
        #[arg(long)]
        tx_cbor_hex: String,
        /// Hex of canonical CBOR for the Witness (sig + pubkey).
        #[arg(long)]
        witness_cbor_hex: String,
    },

    /// Mempool size + tx hashes.
    GetMempool,

    /// Emit cumulative supply (`minted_so_far_sat`) sampled at block heights
    /// `[from, to]` step `step`. Used by the info-page chart.
    EmissionSeries {
        #[arg(long, default_value = "0")]
        from: u64,
        #[arg(long)]
        to: Option<u64>,
        #[arg(long, default_value = "1")]
        step: u64,
    },

    /// `state_root` of the current tip (32-byte hex). Convenience for proof
    /// witnesses and audit scripts.
    StateRoot,

    /// Liveness probe — checks `GET /healthz`.
    Health,
}

#[derive(Debug, Deserialize)]
struct RpcEnvelope {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
}

fn main() {
    let cli = Cli::parse();

    let result = run(&cli);

    match result {
        Ok(value) => {
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
            } else {
                pretty_print(&cli.cmd, &value);
            }
        }
        Err(e) => {
            eprintln!("pygrove-cli error: {e}");
            std::process::exit(1);
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<Value> {
    match &cli.cmd {
        Cmd::GetInfo => rpc(&cli.rpc, "get_info", &serde_json::json!({})),
        Cmd::ShowBlock { height } => {
            rpc(&cli.rpc, "get_block", &serde_json::json!({ "height": height }))
        }
        Cmd::ListBlocks { limit } => rpc(
            &cli.rpc,
            "list_blocks",
            &serde_json::json!({ "limit": limit }),
        ),
        Cmd::GetBalance { address } => rpc(
            &cli.rpc,
            "get_balance",
            &serde_json::json!({ "address": address }),
        ),
        Cmd::GetAccount { address } => rpc(
            &cli.rpc,
            "get_account",
            &serde_json::json!({ "address": address }),
        ),
        Cmd::SubmitTx {
            tx_cbor_hex,
            witness_cbor_hex,
        } => rpc(
            &cli.rpc,
            "submit_tx",
            &serde_json::json!({
                "tx_cbor_hex": tx_cbor_hex,
                "witness_cbor_hex": witness_cbor_hex,
            }),
        ),
        Cmd::GetMempool => rpc(&cli.rpc, "get_mempool", &serde_json::json!({})),
        Cmd::EmissionSeries { from, to, step } => rpc(
            &cli.rpc,
            "emission_series",
            &serde_json::json!({ "from": from, "to": to, "step": step }),
        ),
        Cmd::StateRoot => {
            let info = rpc(&cli.rpc, "get_info", &serde_json::json!({}))?;
            // The node doesn't expose state_root in get_info; fetch the tip
            // block header instead.
            let height = info
                .get("height")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow::anyhow!("malformed get_info"))?;
            let block = rpc(&cli.rpc, "get_block", &serde_json::json!({ "height": height }))?;
            let state_root = block
                .pointer("/header/state_root")
                .ok_or_else(|| anyhow::anyhow!("no state_root in block header"))?
                .clone();
            Ok(state_root)
        }
        Cmd::Health => {
            // /healthz is a plain GET, not /rpc.
            let url = cli.rpc.trim_end_matches("/rpc").trim_end_matches('/');
            let resp = ureq::get(&format!("{url}/healthz"))
                .call()
                .map_err(|e| anyhow::anyhow!("healthz: {e}"))?;
            let body: Value = resp
                .into_json()
                .map_err(|e| anyhow::anyhow!("healthz body: {e}"))?;
            Ok(body)
        }
    }
}

fn rpc(endpoint: &str, method: &str, params: &Value) -> anyhow::Result<Value> {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let resp = ureq::post(endpoint)
        .set("content-type", "application/json")
        .send_json(req)
        .map_err(|e| anyhow::anyhow!("rpc {method}: {e}"))?;
    let env: RpcEnvelope = resp
        .into_json()
        .map_err(|e| anyhow::anyhow!("rpc {method} body: {e}"))?;
    if let Some(err) = env.error {
        anyhow::bail!("rpc {method} error: {err}");
    }
    env.result
        .ok_or_else(|| anyhow::anyhow!("rpc {method}: empty result"))
}

fn pretty_print(cmd: &Cmd, v: &Value) {
    match cmd {
        Cmd::GetInfo => {
            println!("chain:           {}", v["chain_id"].as_str().unwrap_or("?"));
            println!("height:          {}", v["height"]);
            println!("tip_hash:        {}", v["tip_hash"].as_str().unwrap_or("?"));
            println!("bits:            0x{:08x}", v["bits"].as_u64().unwrap_or(0));
            let off = v["genesis_offset_ms"].as_i64().unwrap_or(0);
            if off < 0 {
                let s = -off / 1000;
                let h = s / 3600;
                let m = (s % 3600) / 60;
                println!("lockout:         T-{}h {}m (pre-genesis)", h, m);
            } else {
                let s = off / 1000;
                let h = s / 3600;
                let m = (s % 3600) / 60;
                println!("uptime:          {}h {}m past genesis", h, m);
            }
            println!("mempool_size:    {}", v["mempool_size"]);
            println!(
                "block_reward:    {} sat",
                v["block_reward_sat"].as_u64().unwrap_or(0)
            );
            println!(
                "sig_algo={}  hash_algo={}",
                v["sig_algo"], v["hash_algo"]
            );
        }
        Cmd::ShowBlock { height } => {
            println!("block {height}");
            if let Some(h) = v.get("hash").and_then(Value::as_str) {
                println!("  hash:      {h}");
            }
            if let Some(hdr) = v.get("header") {
                println!("  timestamp: {} ms", hdr["timestamp_ms"]);
                println!("  parent:    {}", hdr["parent"].as_str().unwrap_or("?"));
                println!("  tx_root:   {}", hdr["tx_root"].as_str().unwrap_or("?"));
                println!(
                    "  state_root:   {}",
                    hdr["state_root"].as_str().unwrap_or("?")
                );
                println!(
                    "  reflect_root: {}",
                    hdr["reflect_root"].as_str().unwrap_or("?")
                );
            }
            if let Some(txs) = v.get("txs").and_then(Value::as_array) {
                println!("  txs ({}):", txs.len());
                for tx in txs {
                    println!(
                        "    {} -> {}  amount={} fee={} nonce={}",
                        tx["from"].as_str().unwrap_or("?"),
                        tx["to"].as_str().unwrap_or("?"),
                        tx["amount_sat"],
                        tx["fee_sat"],
                        tx["nonce"],
                    );
                }
            }
        }
        Cmd::ListBlocks { .. } => {
            if let Some(arr) = v.as_array() {
                println!("{:>6}  {:<64}  {:>20}  tx", "height", "hash", "timestamp_ms");
                for b in arr {
                    println!(
                        "{:>6}  {:<64}  {:>20}  {}",
                        b["height"],
                        b["hash"].as_str().unwrap_or("?"),
                        b["timestamp_ms"],
                        b["tx_count"],
                    );
                }
            } else {
                println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
            }
        }
        Cmd::GetBalance { address } => {
            println!(
                "{} balance = {} sat",
                address,
                v["balance"].as_u64().unwrap_or(0)
            );
        }
        Cmd::GetAccount { address } => {
            println!(
                "{}\n  balance:  {}\n  nonce:    {}\n  sig_algo: {}",
                address,
                v["balance"],
                v["nonce"],
                v["sig_algo"]
            );
            if let Some(pk) = v.get("pubkey_hex").and_then(Value::as_str) {
                let prefix: String = pk.chars().take(16).collect();
                println!("  pubkey:   {prefix}…");
            }
        }
        Cmd::GetMempool => {
            println!("mempool size: {}", v["size"]);
            if let Some(hashes) = v.get("hashes").and_then(Value::as_array) {
                for h in hashes {
                    println!("  {}", h.as_str().unwrap_or("?"));
                }
            }
        }
        Cmd::SubmitTx { .. } => {
            println!("submitted: {}", serde_json::to_string(v).unwrap_or_default());
        }
        Cmd::EmissionSeries { .. } => {
            println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
        }
        Cmd::StateRoot => {
            println!("{}", v.as_str().unwrap_or("?"));
        }
        Cmd::Health => {
            println!("{}", serde_json::to_string(v).unwrap_or_default());
        }
    }
}
