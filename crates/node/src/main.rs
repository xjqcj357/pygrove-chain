//! pygrove-node — the chain daemon.
//!
//! v0.1: subcommand skeleton. The miner loop and genesis bring-up wire in once the
//! state store and signature crate are past stubs.

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "pygrove-node", version, about = "PyGrove Chain node daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Initialize a new data dir from genesis.toml, mine the genesis block.
    Init {
        #[arg(long, default_value = "genesis.toml")]
        genesis: String,
        #[arg(long, default_value = "./data")]
        data_dir: String,
        #[arg(long, default_value = "miner.key")]
        key: String,
    },
    /// Run the node.
    Run {
        #[arg(long)]
        mine: bool,
        #[arg(long, default_value = "./data")]
        data_dir: String,
    },
    /// Show current emission state (reward, halving progress, regime).
    ShowEmission {
        #[arg(long, default_value = "./data")]
        data_dir: String,
    },
    /// Dump the reflection subtree.
    ShowReflect {
        #[arg(long, default_value = "./data")]
        data_dir: String,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { genesis, data_dir, key } => {
            tracing::info!(?genesis, ?data_dir, ?key, "init not yet wired — v0.1 scaffold");
        }
        Cmd::Run { mine, data_dir } => {
            tracing::info!(?mine, ?data_dir, "run not yet wired — v0.1 scaffold");
        }
        Cmd::ShowEmission { .. } | Cmd::ShowReflect { .. } => {
            tracing::info!("introspection not yet wired — v0.1 scaffold");
        }
    }
    Ok(())
}
