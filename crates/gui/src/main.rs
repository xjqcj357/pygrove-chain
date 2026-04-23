//! pygrove-gui — wallet GUI shell (Slint).
//!
//! The node RPC client isn't wired yet; the window renders with placeholder state so the
//! release pipeline has a real GUI artifact from v0.1 onward.

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    ui.set_balance_sat("0".into());
    ui.set_block_height("0".into());
    ui.set_regime("equilibrium".into());
    ui.set_halving_progress("0 / 210000".into());
    ui.set_reward_sat("5000000000".into());
    ui.run()
}
