//! Genesis config — parsed from `genesis.toml`, fed into init and consulted at run.

use serde::Deserialize;
use std::path::Path;

fn default_seconds_per_halving() -> u64 {
    210_000 * 600
}
fn default_asert_tau() -> u64 {
    2 * 24 * 60 * 60 * 1000
}
fn default_bootstrap_asert_tau() -> u64 {
    60 * 60 * 1000
}
fn default_bootstrap_height() -> u64 {
    2016
}
fn default_bootstrap_reward_pct() -> u32 {
    50
}
fn default_max_reward_pct_change_per_block() -> u32 {
    25
}
fn default_max_bits_pct_change_per_block() -> u32 {
    8
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
    /// ASERT half-life (post-bootstrap). Default 2 days.
    #[serde(default = "default_asert_tau")]
    pub asert_tau_ms: u64,
    /// ASERT half-life during bootstrap (faster convergence). Default 1 hour.
    #[serde(default = "default_bootstrap_asert_tau")]
    pub bootstrap_asert_tau_ms: u64,
    /// Below this height, the chain runs in bootstrap mode: tighter ASERT,
    /// capped rewards, accordion bellows defaulted (no short-window noise).
    #[serde(default = "default_bootstrap_height")]
    pub bootstrap_height: u64,
    /// During bootstrap, per-block reward is additionally capped at
    /// `bootstrap_reward_pct × epoch_reward / 100`. Default 50.
    #[serde(default = "default_bootstrap_reward_pct")]
    pub bootstrap_reward_pct: u32,
    /// Slew-rate limit on emission delta across consecutive blocks.
    /// Default 25 (i.e., reward can change by at most ±25% per block).
    #[serde(default = "default_max_reward_pct_change_per_block")]
    pub max_reward_pct_change_per_block: u32,
    /// Hard ±N% clamp on per-block ASERT bits change. Defensive belt around
    /// the closed-form math for pathological timestamp inputs. Default 8.
    #[serde(default = "default_max_bits_pct_change_per_block")]
    pub max_bits_pct_change_per_block: u32,
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
    /// Optional BFT finality committee committed to chain state at init.
    /// When present, `pygrove-node init` writes a `GovernanceConfig` to
    /// `Subtree::Meta` so the chain launches with a known committee
    /// instead of bootstrap (anyone-can-sign) mode.
    ///
    /// Each entry is `[signer_id_hex, sig_algo, pubkey_hex]` — 64-char
    /// hex for the 32-byte signer id, the algorithm tag byte, and the
    /// algo-appropriate hex pubkey (e.g. 64-char for Ed25519).
    /// `genesis_committee_threshold` must be ≤ `genesis_committee.len()`.
    ///
    /// Mainnet usage: pre-commit the 5-of-5 trusted committee (or
    /// 2-of-3 governance committee) so the chain doesn't ship with an
    /// open governance surface. Testnet usage: leave empty for
    /// bootstrap mode.
    #[serde(default)]
    pub genesis_committee: Vec<GenesisCommitteeMember>,
    #[serde(default)]
    pub genesis_committee_threshold: u32,
    #[serde(default)]
    pub genesis_committee_epoch: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GenesisCommitteeMember {
    pub signer_id_hex: String,
    pub sig_algo: u8,
    pub pubkey_hex: String,
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
