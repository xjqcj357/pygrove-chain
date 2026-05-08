//! pygrove-gui — wallet + miner GUI shell (Slint).

mod miner;
mod rpc_client;
mod wallet;

use miner::MinerHandle;
use pygrove_core::{AccountId, PubKeyRef, TxBody, TxCall, Witness};
use slint::ComponentHandle;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::Instant;
use wallet::Wallet;

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let cores = miner::num_cpus();
    ui.set_balance_sat("0".into());
    ui.set_block_height("0".into());
    ui.set_regime("equilibrium".into());
    ui.set_halving_progress("0 / 210000".into());
    ui.set_reward_sat("5000000000".into());
    ui.set_cpu_cores(cores as i32);
    ui.set_intensity(((cores / 2).max(1)) as f32);

    // Load (or create) the local wallet on startup. Phase A is plaintext on
    // disk — fine for a testnet whose coins have no value. Phase B encrypts.
    let wallet_path = Wallet::default_path();
    let wallet = match Wallet::load_or_create(&wallet_path) {
        Ok(w) => {
            ui.set_wallet_address(w.address.to_bech32().into());
            ui.set_wallet_pubkey(hex::encode(&w.public_key).into());
            ui.set_send_status(format!("wallet: {}", wallet_path.display()).into());
            Some(w)
        }
        Err(e) => {
            ui.set_wallet_address("(no wallet)".into());
            ui.set_send_status(format!("wallet load failed: {e}").into());
            None
        }
    };
    let wallet = Rc::new(wallet);

    let miner_slot: Rc<RefCell<Option<MinerHandle>>> = Rc::new(RefCell::new(None));
    let last_sample: Rc<RefCell<(Instant, u64)>> = Rc::new(RefCell::new((Instant::now(), 0)));

    let weak = ui.as_weak();
    ui.on_connect_clicked({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                let url = ui.get_rpc_url().to_string();
                match miner::rpc_get_info(&url) {
                    Ok(info) => {
                        ui.set_node_chain_id(info.chain_id.into());
                        ui.set_node_tip_hash(info.tip_hash.into());
                        ui.set_block_height(info.height.to_string().into());
                        ui.set_current_target(info.target_hex.into());
                        ui.set_mine_status("connected".into());
                    }
                    Err(e) => {
                        ui.set_mine_status(format!("err: {e}").into());
                    }
                }
            }
        }
    });

    ui.on_mine_toggle({
        let weak = weak.clone();
        let slot = miner_slot.clone();
        let wallet = wallet.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                let mut s = slot.borrow_mut();
                if let Some(handle) = s.take() {
                    handle.stop.store(true, Ordering::Relaxed);
                    ui.set_mining_on(false);
                    ui.set_mine_status("stopped".into());
                } else {
                    // Device 0 = CPU, device 1+ reserved for GPUs (v0.2).
                    let device = ui.get_device_index();
                    if device != 0 {
                        ui.set_mine_status("GPU mining lands in v0.2".into());
                        return;
                    }
                    let url = ui.get_rpc_url().to_string();
                    let threads = ui.get_intensity().round().max(1.0) as usize;
                    // Mining rewards go to whatever AccountId the block's
                    // coinbase[..20] decodes to. Without a wallet loaded we
                    // fall back to all-zeros (effectively burned).
                    let coinbase = match wallet.as_ref() {
                        Some(w) => w.address.pad_to_32(),
                        None => [0u8; 32],
                    };
                    let handle = miner::start(url, threads, coinbase);
                    *s = Some(handle);
                    ui.set_mining_on(true);
                    ui.set_mine_status(format!("mining ({threads} threads) → wallet").into());
                }
            }
        }
    });

    // Send tx: build the tx, sign with the local wallet, submit_tx via RPC.
    ui.on_send_clicked({
        let weak = weak.clone();
        let wallet = wallet.clone();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            let Some(w) = wallet.as_ref() else {
                ui.set_send_status("no wallet loaded".into());
                return;
            };
            let url = ui.get_rpc_url().to_string();
            let to_str = ui.get_send_to().to_string();
            let amount_str = ui.get_send_amount().to_string();
            let fee_str = ui.get_send_fee().to_string();
            match build_and_submit_tx(&url, w, &to_str, &amount_str, &fee_str) {
                Ok(hash) => {
                    ui.set_send_status(format!("submitted: {}", hash).into());
                    ui.set_send_amount("".into());
                    ui.set_send_to("".into());
                }
                Err(e) => {
                    ui.set_send_status(format!("error: {e}").into());
                }
            }
        }
    });

    // Poll the miner counters AND the wallet balance ~4 Hz.
    let weak_tick = weak.clone();
    let slot_tick = miner_slot.clone();
    let sample_tick = last_sample.clone();
    let wallet_tick = wallet.clone();
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(250),
        move || {
            let Some(ui) = weak_tick.upgrade() else { return };
            // Miner counters
            if let Some(handle) = slot_tick.borrow().as_ref() {
                let hashes = handle.hashes.load(Ordering::Relaxed);
                let accepted = handle.accepted.load(Ordering::Relaxed);
                let rejected = handle.rejected.load(Ordering::Relaxed);
                let (prev_t, prev_h) = *sample_tick.borrow();
                let now = Instant::now();
                let dt = now.duration_since(prev_t).as_secs_f64().max(0.001);
                let rate = (hashes.saturating_sub(prev_h)) as f64 / dt;
                *sample_tick.borrow_mut() = (now, hashes);
                ui.set_hashrate(format_rate(rate).into());
                ui.set_accepted(accepted.to_string().into());
                ui.set_rejected(rejected.to_string().into());
            }
        },
    );

    // Slower poll for wallet balance — every 3s.
    let weak_balance = weak.clone();
    let wallet_balance = wallet_tick.clone();
    let balance_timer = slint::Timer::default();
    balance_timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_secs(3),
        move || {
            let Some(ui) = weak_balance.upgrade() else { return };
            let Some(w) = wallet_balance.as_ref() else { return };
            let url = ui.get_rpc_url().to_string();
            if let Ok(info) = rpc_client::get_account(&url, &w.address) {
                ui.set_balance_sat(info.balance_sat.to_string().into());
                ui.set_wallet_nonce(info.nonce.to_string().into());
            }
        },
    );

    ui.run()
}

/// Build a Transfer tx from the wallet to `to_str`, sign it, submit_tx.
fn build_and_submit_tx(
    url: &str,
    wallet: &Wallet,
    to_str: &str,
    amount_str: &str,
    fee_str: &str,
) -> anyhow::Result<String> {
    let to = AccountId::from_bech32(to_str.trim())
        .map_err(|e| anyhow::anyhow!("bad recipient: {e}"))?;
    let amount: u128 = amount_str.trim().parse().map_err(|e| anyhow::anyhow!("bad amount: {e}"))?;
    let fee: u64 = fee_str.trim().parse().map_err(|e| anyhow::anyhow!("bad fee: {e}"))?;

    // Pull current account state for the right nonce. If the account has never
    // signed, nonce starts at 0 and we publish the pubkey inline so the node
    // can commit it on apply.
    let info = rpc_client::get_account(url, &wallet.address)?;
    let pubkey_ref = if info.has_pubkey {
        PubKeyRef::Known(wallet.address)
    } else {
        PubKeyRef::Inline(wallet.public_key.clone())
    };

    let mut tx = TxBody {
        nonce: info.nonce,
        from_account: wallet.address,
        call: TxCall::Transfer { to, amount },
        fee_sat: fee,
        gas_limit: 21_000,
        witness_hash: [0u8; 32],
    };
    let signing_hash = tx.signing_hash();
    let sig = wallet.sign(&signing_hash)?;
    let witness = Witness {
        sig_algo: wallet.sig_algo,
        sig,
        pubkey: pubkey_ref,
    };
    tx.witness_hash = witness.hash();

    // CBOR-encode both, hex-encode, ship.
    let mut tx_buf = Vec::new();
    ciborium::ser::into_writer(&tx, &mut tx_buf)
        .map_err(|e| anyhow::anyhow!("encode tx: {e}"))?;
    let mut wit_buf = Vec::new();
    ciborium::ser::into_writer(&witness, &mut wit_buf)
        .map_err(|e| anyhow::anyhow!("encode witness: {e}"))?;
    rpc_client::submit_tx(url, &hex::encode(tx_buf), &hex::encode(wit_buf))
}

fn format_rate(hps: f64) -> String {
    if hps >= 1e9 {
        format!("{:.2} GH/s", hps / 1e9)
    } else if hps >= 1e6 {
        format!("{:.2} MH/s", hps / 1e6)
    } else if hps >= 1e3 {
        format!("{:.2} kH/s", hps / 1e3)
    } else {
        format!("{hps:.0} H/s")
    }
}
