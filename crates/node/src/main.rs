//! pygrove-node — the chain daemon.

mod chainstore;
mod genesis;
mod mempool;
mod mining;
mod rpc;

use anyhow::Context;
use chainstore::ChainStore;
use clap::{Parser, Subcommand};
use genesis::Genesis;
use mempool::Mempool;
use mining::{mine_inline, now_ms, template_from_parent_with_body};
use pygrove_consensus::pow::{hash_header, meets_target, target_from_bits};
use pygrove_core::{AccountId, BlockBody, TxBody, Witness};
use pygrove_state::MemState;
use rpc::NodeState;
use std::sync::{Arc, Mutex};
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
        /// Sleep between hash attempts in the self-miner. 0 = full speed.
        /// 20 ≈ 50 H/s on commodity CPU — slow enough that any laptop wins races.
        #[arg(long, default_value_t = 0)]
        mine_throttle_ms: u64,
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
            mine_throttle_ms,
            data_dir,
            genesis,
            rpc_bind,
        } => cmd_run(&genesis, &data_dir, &rpc_bind, mine, mine_throttle_ms),
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
    let hdr = mining::template_from_parent(
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

fn cmd_run(
    genesis_path: &str,
    data_dir: &str,
    rpc_bind: &str,
    self_mine: bool,
    mine_throttle_ms: u64,
) -> anyhow::Result<()> {
    let g = Genesis::load(genesis_path).context("load genesis")?;
    let store = ChainStore::open(data_dir)?;
    if store.tip()?.is_none() {
        anyhow::bail!("data dir {data_dir} empty — run `pygrove-node init` first");
    }

    // Reconstruct in-memory state by replaying every block from the chain log
    // through apply_block. v0.2 swaps to GroveDB persistence so this O(N)
    // startup cost goes away.
    //
    // Calendar-emission accounting: per-block reward is computed via
    // `emission::current_reward(...)`, anchored at `genesis_time_ms`, with
    // `minted_so_far` tracked across the replay. Genesis (height 0) earns 0;
    // each subsequent block earns the delta between scheduled supply at its
    // timestamp and what's already been minted, capped per-block.
    let blocks = store.load_all()?;
    let block_reward_sat: u128 = g.initial_reward_sat as u128;
    let emission_params = pygrove_consensus::emission::EmissionParams {
        initial_reward_sat: block_reward_sat,
        seconds_per_halving: g.seconds_per_halving,
        target_block_time_ms: g.target_block_time_ms,
        supply_cap_sat: 21_000_000 * 100_000_000,
        max_reward_pct_change_per_block: g.max_reward_pct_change_per_block,
        bootstrap_height: g.bootstrap_height,
        bootstrap_reward_pct: g.bootstrap_reward_pct,
    };
    let mut mem = MemState::new();
    let mut minted_so_far: u128 = 0;
    let mut prev_reward: Option<u128> = None;
    for b in &blocks {
        let parent_ts = if b.header.height == 0 {
            g.genesis_time_ms
        } else {
            blocks
                .get((b.header.height - 1) as usize)
                .map(|p| p.header.timestamp_ms)
                .unwrap_or(g.genesis_time_ms)
        };
        let reward = pygrove_consensus::emission::current_reward_with_height(
            &emission_params,
            g.genesis_time_ms,
            b.header.timestamp_ms,
            parent_ts,
            minted_so_far,
            b.header.height,
            prev_reward,
        );
        pygrove_state::apply_block(&mut mem, b, reward)
            .map_err(|e| anyhow::anyhow!("replay height {}: {e}", b.header.height))?;
        minted_so_far = minted_so_far.saturating_add(reward);
        prev_reward = Some(reward);
    }
    tracing::info!(
        replayed = blocks.len(),
        minted_so_far_sat = %minted_so_far,
        seconds_per_halving = g.seconds_per_halving,
        "state replayed; entering live mode (calendar emission)"
    );

    // Optional treasury address — env override sets where the throttled
    // self-miner mints coinbase. Default is the headline-derived address
    // (effectively burned, since nobody owns the secret key for it).
    let coinbase = if let Ok(addr) = std::env::var("PYGROVE_TREASURY_ADDRESS") {
        match AccountId::from_bech32(&addr) {
            Ok(id) => {
                tracing::info!(address = %id, "coinbase = treasury (env override)");
                id.pad_to_32()
            }
            Err(e) => {
                tracing::warn!(%e, "PYGROVE_TREASURY_ADDRESS invalid; falling back to headline");
                let mut c = [0u8; 32];
                c[..20].copy_from_slice(&g.headline_bytes()[..20]);
                c
            }
        }
    } else {
        let mut c = [0u8; 32];
        c[..20].copy_from_slice(&g.headline_bytes()[..20]);
        c
    };

    let state = Arc::new(NodeState {
        store,
        chain_id: g.chain_id.clone(),
        bits: g.initial_bits,
        coinbase,
        sig_algo: g.sig_algo,
        hash_algo: g.hash_algo,
        genesis_time_ms: g.genesis_time_ms,
        state: Mutex::new(mem),
        mempool: Arc::new(Mempool::new(10_000)),
        block_reward_sat,
        target_block_time_ms: g.target_block_time_ms,
        halving_interval_base: g.halving_interval_base,
        emission: emission_params,
        minted_so_far: Mutex::new(minted_so_far),
        prev_reward_sat: Mutex::new(prev_reward),
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
        tracing::info!(
            mine_throttle_ms,
            "self-miner enabled (throttle = {}ms / hash, ~{} H/s)",
            mine_throttle_ms,
            if mine_throttle_ms == 0 { 0 } else { 1000 / mine_throttle_ms.max(1) }
        );
        let st = state.clone();
        thread::spawn(move || self_miner_loop(st, mine_throttle_ms));
    }

    rpc::serve(rpc_bind, state)
}

fn self_miner_loop(st: Arc<NodeState>, throttle_ms: u64) {
    let target = target_from_bits(st.bits);
    loop {
        // Hard gate: don't even build templates while pre-genesis. Saves CPU
        // and keeps the log quiet during the lockout window.
        let now = now_ms();
        if now < st.genesis_time_ms {
            thread::sleep(Duration::from_secs(30));
            continue;
        }
        let tip = match st.store.tip() {
            Ok(Some(b)) => b,
            _ => {
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        let parent_hash = hash_header(&tip.header);

        // Snapshot mempool for this mining attempt. If the mempool changes
        // mid-mine, we'll just keep mining the snapshot and the freshly-arrived
        // txs go into the *next* block. That's fine and matches Bitcoin.
        let pending = st.mempool.pull_for_block(256);
        let txs: Vec<TxBody> = pending.iter().map(|p| p.body.clone()).collect();
        let witnesses: Vec<Witness> = pending.iter().map(|p| p.witness.clone()).collect();
        let body = BlockBody { txs, witnesses };
        let mut hdr = template_from_parent_with_body(
            parent_hash,
            tip.header.height,
            st.bits,
            st.coinbase,
            st.sig_algo,
            st.hash_algo,
            now_ms(),
            &body,
        );
        let start = std::time::Instant::now();
        loop {
            let h = hash_header(&hdr);
            if meets_target(&h, &target) {
                let block = pygrove_core::Block {
                    header: hdr.clone(),
                    body: body.clone(),
                };
                // Go through the same gate as JSON-RPC submit_block — if a
                // remote miner won the race a moment ago, we'll see "stale
                // parent" here and quietly drop our find.
                if let Err(e) = rpc::try_apply_block(&st, &block) {
                    tracing::debug!(%e, "self-mine apply rejected");
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
            // Throttle: sleep between hash attempts so external miners
            // dominate. Default 0 = full speed (legacy / dev convenience).
            if throttle_ms > 0 {
                thread::sleep(Duration::from_millis(throttle_ms));
            }
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
