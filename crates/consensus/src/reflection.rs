//! The Reflection: rolling chain stats committed to a dedicated state subtree so the
//! chain can read its own past. v0.1 defines the shape; the state crate writes and
//! commits it inside `apply_block`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReflectWindow {
    Short,  // 144 blocks
    Long,   // 2016 blocks
    Epoch,  // 210000 blocks
}

impl ReflectWindow {
    pub fn blocks(self) -> u64 {
        match self {
            Self::Short => 144,
            Self::Long => 2016,
            Self::Epoch => 210_000,
        }
    }
    pub fn path_tag(self) -> &'static str {
        match self {
            Self::Short => "window_short",
            Self::Long => "window_long",
            Self::Epoch => "window_epoch",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Reflection {
    /// Work done (cumulative difficulty) in this window.
    pub hashrate_proxy: u128,
    /// Sybil-guarded unique active addresses touched.
    pub active_addresses: u64,
    /// Sum of fees paid in this window.
    pub fee_sum: u128,
    /// Emission rate: coin minted in this window.
    pub emission: u128,
    /// Last computed accordion ratios and bias, for consumer introspection.
    pub r_h_q64: i128,
    pub r_a_q64: i128,
    pub stability_bias: i8,
}
