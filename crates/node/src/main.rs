//! pygrove-node — the chain daemon.

mod chainstore;
mod genesis;
mod mining;
mod rpc;

use anyhow::Context;
use chainstore::ChainStore;
use clap::{Parser, Subcommand};
use genesis::Genesis;
use mining::{mine_inline, now_ms, template_from_parent};
use pygrove_consensus::pow::{hash_header, meets_target, target_from_bits};
use rpc::NodeState;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "pygrove-node", version, about = "PyGrove Chain node daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Initialize a new data dir from genesis.toml — mines the genesis block inline.
    Init {
        #[arg(long, default_value = "genesis.toml")]
        genesis: String,
        #[arg(long, default_value = "./data")]
        data_dir: String,
        #[arg(long, default_value = "miner.key")]
        key: String,
    },
    /// Run the node. Serves miner RPC; `--mine` also runs a background self-miner.
    Run {
        #[arg(long)]
        mine: bool,
        #[arg(long, default_value = "./data")]
        data_dir: String,
        #[arg(long, default_value = "genesis.toml")]
        genesis: String,
        #[arg(long, default_value = "0.0.0.0:8545")]
        rpc_bind: String,
    },
    /// Show current tip, height, reward.
    ShowEmission {
        #[arg(long, default_value = "./data")]
        data_dir: String,
        #[arg(long, default_value = "genesis.toml")]
        genesis: String,
    },
    /// Dump the reflection subtree (v0.1 stub — prints block count).
    ShowReflect {
        #[arg(long, default_value = "./data")]
        data_dir: String,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init {
            genesis,
            data_dir,
            key,
        } => cmd_init(&genesis, &data_dir, &key),
        Cmd::Run {
            mine,
            data_dir,
            genesis,
            rpc_bind,
        } => cmd_run(&genesis, &data_dir, &rpc_bind, mine),
        Cmd::ShowEmission { data_dir, genesis } => cmd_show_emission(&genesis, &data_dir),
        Cmd::ShowReflect { data_dir } => cmd_show_reflect(&data_dir),
    }
}

fn cmd_init(genesis_path: &str, data_dir: &str, _key: &str) -> anyhow::Result<()> {
    let g = Genesis::load(genesis_path).context("load genesis")?;
    let store = ChainStore::open(data_dir)?;
    if store.height()? > 0 || store.tip()?.is_some() {
        anyhow::bail!("data dir {data_dir} already initialized");
    }
    tracing::info!(
        chain = %g.chain_id,
        genesis_time_ms = g.genesis_time_ms,
        headline = %g.genesis_headline_hex,
        "mining genesis block at bits={:#010x}",
        g.initial_bits
    );
    // Genesis coinbase = headline bytes (proof of no prior knowledge).
    // Post-genesis blocks use coinbase = miner account ID.
    let coinbase = g.headline_bytes();
    let hdr = template_from_parent(
        [0u8; 32],
        0_u64.wrapping_sub(1),
        g.initial_bits,
        coinbase,
        g.sig_algo,
        g.hash_algo,
        g.genesis_time_ms,
    );
    // parent_height + 1 above wraps to 0 for height=0 (genesis). Force it explicitly.
    let mut hdr = hdr;
    hdr.height = 0;
    let block = mine_inline(hdr);
    let h = hash_header(&block.header);
    store.append(&block)?;
    tracing::info!(hash = %hex::encode(h), nonce = block.header.nonce, "genesis mined");
    println!("genesis: height=0 nonce={} hash={}", block.header.nonce, hex::encode(h));
    Ok(())
}

fn cmd_run(genesis_path: &str, data_dir: &str, rpc_bind: &str, self_mine: bool) -> anyhow::Result<()> {
    let g = Genesis::load(genesis_path).context("load genesis")?;
    let store = ChainStore::open(data_dir)?;
    if store.tip()?.is_none() {
        anyhow::bail!("data dir {data_dir} empty — run `pygrove-node init` first");
    }
    let state = Arc::new(NodeState {
        store,
        chain_id: g.chain_id.clone(),
        bits: g.initial_bits,
        coinbase: [0u8; 32],
        sig_algo: g.sig_algo,
        hash_algo: g.hash_algo,
        genesis_time_ms: g.genesis_time_ms,
    });
    let now = mining::now_ms();
    if now < g.genesis_time_ms {
        let secs = (g.genesis_time_ms - now) / 1000;
        tracing::info!(
            secs_until_genesis = secs,
            "PRE-GENESIS: submit_block locked until {}",
            g.genesis_time_ms
        );
    } else {
        tracing::info!("post-genesis: accepting block submissions");
    }

    if self_mine {
        let st = state.clone();
        thread::spawn(move || self_miner_loop(st));
    }

    rpc::serve(rpc_bind, state)
}

fn self_miner_loop(st: Arc<NodeState>) {
    let target = target_from_bits(st.bits);
    loop {
        let tip = match st.store.tip() {
            Ok(Some(b)) => b,
            _ => {
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        let parent_hash = hash_header(&tip.header);
        let mut hdr = template_from_parent(
            parent_hash,
            tip.header.height,
            st.bits,
            st.coinbase,
            st.sig_algo,
            st.hash_algo,
            now_ms(),
        );
        let start = std::time::Instant::now();
        loop {
            let h = hash_header(&hdr);
            if meets_target(&h, &target) {
                let block = pygrove_core::Block {
                    header: hdr.clone(),
                    body: pygrove_core::BlockBody { txs: vec![] },
                };
                if let Err(e) = st.store.append(&block) {
                    tracing::warn!(%e, "self-mine append failed");
                    break;
                }
                tracing::info!(
                    height = block.header.height,
                    nonce = block.header.nonce,
                    elapsed_ms = start.elapsed().as_millis() as u64,
                    "self-mined block"
                );
                break;
            }
            hdr.nonce = hdr.nonce.wrapping_add(1);
            // Refresh tip every ~2M nonces in case a remote miner accepted first.
            if hdr.nonce & 0x001f_ffff == 0 {
                if let Ok(Some(cur)) = st.store.tip() {
                    if cur.header.height > tip.header.height {
                        break;
                    }
                }
            }
        }
    }
}

fn cmd_show_emission(genesis_path: &str, data_dir: &str) -> anyhow::Result<()> {
    let g = Genesis::load(genesis_path)?;
    let store = ChainStore::open(data_dir)?;
    let height = store.height()?;
    let halvings = (height / g.halving_interval_base).min(63) as u32;
    let reward = if halvings >= 63 {
        0
    } else {
        g.initial_reward_sat >> halvings
    };
    println!("height={height}  halvings={halvings}  reward_sat={reward}");
    Ok(())
}

fn cmd_show_reflect(data_dir: &str) -> anyhow::Result<()> {
    let store = ChainStore::open(data_dir)?;
    println!("block_count={}", store.len()?);
    Ok(())
}
