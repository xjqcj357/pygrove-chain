//! Emission schedule.
//!
//! As of `feat/calendar-emission` (the testnet-3 fix), the schedule is **calendar-
//! driven**, not block-counted. The whitepaper §1.1 explicitly criticises Bitcoin
//! for issuance that is "blind to demand" and claims PyGrove's halving is
//! "calendar-driven, not user-driven" — but the testnet-2 implementation
//! perpetuated Bitcoin's block-counted mechanism. That mismatch is the
//! premine-optics bug we observed: when blocks land at 100× target rate, the
//! economic loop emits ~100× the calendar's intended supply before the security
//! loop (difficulty retarget) closes.
//!
//! The fix: scheduled cumulative supply at any wall-clock time `t` is
//!
//!     S(t) = ∑_{i=0}^{epoch-1} R_0/2^i × blocks_per_halving
//!          + R_0/2^epoch × blocks_in_partial_epoch(t)
//!
//! where `epoch = floor(t / T_h)`, `T_h = seconds_per_halving`, and
//! `blocks_per_halving = T_h / target_block_time`. Per-block reward becomes
//! a delta against the schedule, capped by the current epoch's per-block max
//! and a stall-attack proportional cap. Specifics in `current_reward()` below.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EmissionParams {
    pub initial_reward_sat: u128,
    /// Calendar duration of one halving epoch (≈ 4 years for Bitcoin params).
    /// Blocks per halving = `seconds_per_halving × 1000 / target_block_time_ms`.
    pub seconds_per_halving: u64,
    pub target_block_time_ms: u64,
    pub supply_cap_sat: u128,
}

impl EmissionParams {
    /// Bitcoin-style defaults: 50 PYG, 4-year halving, 10-min target, 21M cap.
    pub fn bitcoin_like() -> Self {
        Self {
            initial_reward_sat: 5_000_000_000,
            seconds_per_halving: 210_000 * 600, // 4 years exactly under target cadence
            target_block_time_ms: 600_000,
            supply_cap_sat: 21_000_000 * 100_000_000,
        }
    }
}

/// Scheduled cumulative supply at elapsed milliseconds since genesis.
/// Asymptotes to `supply_cap_sat` as `t → ∞`.
///
/// This is what the chain *intends* to have minted by time `t`. Per-block
/// reward is the delta between this and what's actually been minted, clamped
/// by the per-block caps in `current_reward`.
pub fn scheduled_supply_at(t_ms_since_genesis: u64, p: &EmissionParams) -> u128 {
    if t_ms_since_genesis == 0 {
        return 0;
    }
    let t_h_ms: u128 = (p.seconds_per_halving as u128) * 1000;
    let target_ms: u128 = p.target_block_time_ms as u128;
    if t_h_ms == 0 || target_ms == 0 {
        return 0;
    }
    let blocks_per_halving: u128 = t_h_ms / target_ms;
    let t_ms = t_ms_since_genesis as u128;
    let epoch_u128 = t_ms / t_h_ms;
    // After 64 halvings the right-shift truncates reward to zero; we've
    // converged to the geometric-series limit (= cap, modulo discretization).
    if epoch_u128 >= 64 {
        return p.supply_cap_sat;
    }
    let epoch = epoch_u128 as u32;

    let mut cumulative: u128 = 0;
    let mut current_reward = p.initial_reward_sat;
    for _ in 0..epoch {
        cumulative = cumulative.saturating_add(current_reward.saturating_mul(blocks_per_halving));
        current_reward >>= 1;
    }
    // Partial blocks earned within the current epoch.
    let elapsed_in_epoch = t_ms - (epoch_u128 * t_h_ms);
    let partial_blocks = elapsed_in_epoch.saturating_mul(blocks_per_halving) / t_h_ms;
    cumulative = cumulative.saturating_add(current_reward.saturating_mul(partial_blocks));
    cumulative.min(p.supply_cap_sat)
}

/// Per-block reward at a given block. Three caps, take the minimum:
///
///   1. **Calendar tracking.** `S(t) − minted_so_far`. Block doesn't pay more
///      than what the schedule says is owed. If the chain is over-emitted
///      relative to schedule, this clamps to 0 — block is valid but earns
///      no reward.
///   2. **Per-block max.** `R_0 / 2^epoch`. Floor of the current halving era.
///      Means a single block can never mint more than the era's nominal reward.
///   3. **Stall-attack proportional cap.** `epoch_reward × elapsed_since_parent
///      / target_block_time`. Bounds catch-up after a stall: a block timestamped
///      one hour after its parent earns at most 6× the per-block reward,
///      regardless of what the calendar says is "owed".
///
/// All inputs are absolute Unix milliseconds. Genesis (block_timestamp ==
/// genesis_time) earns zero — first paid block is height 1.
pub fn current_reward(
    p: &EmissionParams,
    genesis_time_ms: u64,
    block_timestamp_ms: u64,
    parent_timestamp_ms: u64,
    minted_so_far_sat: u128,
) -> u128 {
    if block_timestamp_ms <= genesis_time_ms {
        return 0;
    }
    let t_ms = block_timestamp_ms - genesis_time_ms;
    let scheduled = scheduled_supply_at(t_ms, p);
    let calendar_remaining = scheduled.saturating_sub(minted_so_far_sat);

    let t_h_ms: u128 = (p.seconds_per_halving as u128) * 1000;
    let epoch_u128 = (t_ms as u128) / t_h_ms.max(1);
    let epoch_reward: u128 = if epoch_u128 >= 64 {
        0
    } else {
        p.initial_reward_sat >> (epoch_u128 as u32)
    };

    // Stall-attack mitigation. If parent is in the future (clock-skew weirdness)
    // or at the same instant, treat elapsed as one target interval — a block
    // can always earn its nominal share.
    let elapsed_ms = block_timestamp_ms.saturating_sub(parent_timestamp_ms);
    let elapsed_for_cap = elapsed_ms.max(1) as u128;
    let proportional_cap = epoch_reward
        .saturating_mul(elapsed_for_cap)
        / (p.target_block_time_ms as u128).max(1);

    calendar_remaining.min(epoch_reward).min(proportional_cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> EmissionParams {
        EmissionParams::bitcoin_like()
    }

    #[test]
    fn scheduled_at_genesis_is_zero() {
        assert_eq!(scheduled_supply_at(0, &p()), 0);
    }

    #[test]
    fn scheduled_at_one_target_interval_is_one_reward() {
        let p = p();
        // Bit of slack: the per-block partial granularity may round one block down.
        let s = scheduled_supply_at(p.target_block_time_ms, &p);
        assert!(s <= p.initial_reward_sat);
        assert!(s >= p.initial_reward_sat - 1); // ≥ 1 sat off floor
    }

    #[test]
    fn scheduled_after_one_halving_is_half_supply_minus_change() {
        let p = p();
        let t = p.seconds_per_halving * 1000;
        let s = scheduled_supply_at(t, &p);
        // After exactly one halving, total minted should be R0 × blocks_per_halving
        // = 50 × 210000 × 1e8 = 10.5M PYG = half the supply (Bitcoin invariant).
        let expected = p.initial_reward_sat * (p.seconds_per_halving as u128 * 1000 / p.target_block_time_ms as u128);
        assert_eq!(s, expected);
        assert_eq!(s, p.supply_cap_sat / 2);
    }

    #[test]
    fn asymptote_is_supply_cap() {
        // 100 halving epochs in: well past truncation to zero reward.
        let t = 100u64 * p().seconds_per_halving * 1000;
        assert_eq!(scheduled_supply_at(t, &p()), p().supply_cap_sat);
    }

    #[test]
    fn current_reward_at_genesis_is_zero() {
        let p = p();
        let g = 1_000_000_000_000;
        assert_eq!(current_reward(&p, g, g, g, 0), 0);
    }

    #[test]
    fn current_reward_at_target_pays_full_reward() {
        let p = p();
        let g = 1_000_000_000_000u64;
        // First post-genesis block, exactly one target interval after genesis.
        let r = current_reward(&p, g, g + p.target_block_time_ms, g, 0);
        assert_eq!(r, p.initial_reward_sat);
    }

    #[test]
    fn fast_blocks_get_proportionally_smaller_reward() {
        let p = p();
        let g = 1_000_000_000_000u64;
        // 100 blocks in 6 seconds (way faster than target). Nothing minted yet.
        // Elapsed since parent = 60ms. Proportional cap = R0 × 60 / 600000 = R0 / 10000.
        let r = current_reward(&p, g, g + 60, g, 0);
        let expected_cap = p.initial_reward_sat / 10000;
        assert_eq!(r, expected_cap);
    }

    #[test]
    fn over_emitted_chain_cannot_double_dip() {
        let p = p();
        let g = 1_000_000_000_000u64;
        // Suppose minted_so_far is already AT the schedule: calendar_remaining = 0.
        let t_offset = 60_000; // 1 minute past genesis
        let scheduled = scheduled_supply_at(t_offset, &p);
        let r = current_reward(&p, g, g + t_offset, g, scheduled);
        assert_eq!(r, 0);
    }

    #[test]
    fn stall_then_resume_does_not_overpay() {
        // Adversary stalls for one full halving epoch then mines.
        // Calendar says half the supply is owed; per-block cap blocks it.
        let p = p();
        let g = 1_000_000_000_000u64;
        let t_long = p.seconds_per_halving * 1000;
        let r = current_reward(&p, g, g + t_long, g, 0);
        // proportional_cap = R0 × t_long / target_block = R0 × blocks_per_halving
        // = half the supply. But epoch_reward (post-halving = R0/2) clamps it.
        // Calendar_remaining = half the supply. Min of (half_supply, R0/2, half_supply)
        // = R0/2. So one block earns one halved reward — not the whole half-supply.
        assert_eq!(r, p.initial_reward_sat / 2);
    }
}
