//! pygrove-cli — RPC / introspection client. v0.1: skeleton only.

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "pygrove-cli", version, about = "PyGrove Chain RPC client")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    GetState { path: String },
    GetProof { path: String },
    ShowBlock { height: u64 },
    SubmitTx { tx_file: String },
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::GetState { path } => println!("get-state {path} (stub)"),
        Cmd::GetProof { path } => println!("get-proof {path} (stub)"),
        Cmd::ShowBlock { height } => println!("show-block {height} (stub)"),
        Cmd::SubmitTx { tx_file } => println!("submit-tx {tx_file} (stub)"),
    }
}
