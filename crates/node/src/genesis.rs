//! Genesis config — parsed from `genesis.toml`, fed into init and consulted at run.

use serde::Deserialize;
use std::path::Path;

fn default_seconds_per_halving() -> u64 {
    210_000 * 600
}

#[allow(dead_code)] // many fields plumb through later — accordion eval, sybil guard, etc.
#[derive(Debug, Clone, Deserialize)]
pub struct Genesis {
    pub chain_id: String,
    pub genesis_time_ms: u64,
    pub initial_bits: u32,
    pub target_block_time_ms: u64,
    pub retarget_interval: u64,
    pub halving_interval_base: u64,
    /// Calendar duration of one halving epoch, in seconds. Drives the
    /// new calendar-emission schedule (testnet-3+). For Bitcoin-equivalent
    /// params: `halving_interval_base × target_block_time_ms / 1000`
    /// = 210000 × 600 = 126_000_000 (≈ 4 years).
    #[serde(default = "default_seconds_per_halving")]
    pub seconds_per_halving: u64,
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
    /// 32-byte hex string baked into the genesis coinbase as proof-of-no-prior-
    /// knowledge. Conventionally a fresh Bitcoin block hash — anyone can verify
    /// it didn't exist before its own block timestamp.
    #[serde(default)]
    pub genesis_headline_hex: String,
    #[serde(default)]
    pub initial_accounts: Vec<String>,
}

impl Genesis {
    /// Decode the headline hex into a 32-byte coinbase slot. Returns zeros if
    /// the field is empty (legacy / dev configs).
    pub fn headline_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        if self.genesis_headline_hex.is_empty() {
            return out;
        }
        if let Ok(bytes) = hex::decode(&self.genesis_headline_hex) {
            if bytes.len() == 32 {
                out.copy_from_slice(&bytes);
            }
        }
        out
    }
}

impl Genesis {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path.as_ref())?;
        Ok(toml::from_str(&s)?)
    }
}
