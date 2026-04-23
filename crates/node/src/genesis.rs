//! Genesis config — parsed from `genesis.toml`, fed into init and consulted at run.

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Genesis {
    pub chain_id: String,
    pub genesis_time_ms: u64,
    pub initial_bits: u32,
    pub target_block_time_ms: u64,
    pub retarget_interval: u64,
    pub halving_interval_base: u64,
    pub initial_reward_sat: u64,
    pub accordion_epsilon: f64,
    pub accordion_beta_h: f64,
    pub accordion_beta_a: f64,
    pub accordion_beta_s: f64,
    pub stability_window_blocks: u64,
    pub sybil_dust_floor_sat: u64,
    pub sybil_min_age_blocks: u64,
    pub sybil_require_paid_fee: bool,
    pub sig_algo: u8,
    pub hash_algo: u8,
    #[serde(default)]
    pub governance_pubkey_hex: String,
    #[serde(default)]
    pub initial_accounts: Vec<String>,
}

impl Genesis {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path.as_ref())?;
        Ok(toml::from_str(&s)?)
    }
}
