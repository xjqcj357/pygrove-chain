//! pygrove-gui — wallet + miner GUI shell (Slint).

mod miner;

use miner::MinerHandle;
use slint::ComponentHandle;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::Instant;

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
                    let handle = miner::start(url, threads);
                    *s = Some(handle);
                    ui.set_mining_on(true);
                    ui.set_mine_status(format!("mining ({threads} threads)").into());
                }
            }
        }
    });

    // Poll the miner counters ~4 Hz so the UI stays alive.
    let weak_tick = weak.clone();
    let slot_tick = miner_slot.clone();
    let sample_tick = last_sample.clone();
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(250),
        move || {
            if let Some(ui) = weak_tick.upgrade() {
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
            }
        },
    );

    ui.run()
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
