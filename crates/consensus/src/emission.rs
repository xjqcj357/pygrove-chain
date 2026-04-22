//! Emission schedule driven by the halving accumulator.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EmissionParams {
    pub initial_reward_sat: u128,
    pub halving_interval_base: u64,
    pub supply_cap_sat: u128,
}

impl EmissionParams {
    pub fn bitcoin_like() -> Self {
        Self {
            initial_reward_sat: 5_000_000_000,
            halving_interval_base: 210_000,
            supply_cap_sat: 21_000_000 * 100_000_000,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Emission {
    /// Halving-progress accumulator. Integer part = blocks-equivalent already minted.
    pub halving_progress_q64: u128,
    /// Cumulative supply actually minted. Consensus enforces this never exceeds the cap.
    pub minted_sat: u128,
}

impl Emission {
    pub fn halvings_completed(&self, params: &EmissionParams) -> u32 {
        let base = params.halving_interval_base as u128;
        if base == 0 { return 0; }
        // halving_progress_q64 is Q64.64 — integer part is the high 64 bits.
        let int_part = self.halving_progress_q64 >> 64;
        (int_part / base) as u32
    }

    pub fn current_reward(&self, params: &EmissionParams) -> u128 {
        let h = self.halvings_completed(params);
        if h >= 64 { 0 } else { params.initial_reward_sat >> h }
    }
}
