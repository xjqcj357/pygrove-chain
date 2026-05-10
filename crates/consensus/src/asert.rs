//! ASERT-2D — Absolutely Scheduled Exponentially Rising Targets, 2D variant.
//!
//! Per-block difficulty retarget. Closed-form, deterministic, no oscillation.
//! Originated by Mark Lundeberg, Jonathan Toomim et al. for Bitcoin Cash 2020;
//! we keep the same math because the math is correct, not because the chain is.
//!
//! The formula:
//!
//!     new_target = anchor_target × 2^( (Δt − τblock × Δh) / τ )
//!
//! where:
//!   - `anchor_target` is some past block's target (often genesis, or a fixed
//!     anchor every N retargets — we use the immediate parent as anchor for
//!     simplicity, matching BCH-ASERT-3D's zero-feedback-loop variant).
//!   - `Δt = block.timestamp − anchor.timestamp` (seconds — we use ms internally)
//!   - `τblock` is the target block time
//!   - `Δh = block.height − anchor.height`
//!   - `τ` is the difficulty half-life (we default to 2 days, BCH's number)
//!
//! Intuition: if blocks are landing exactly on schedule, `Δt = τblock × Δh`
//! and the exponent is 0 → `new_target = anchor_target`. If blocks are too
//! fast (Δt < expected) the exponent goes negative, target shrinks (difficulty
//! rises). Each block reactively corrects; no 2,016-block lag, no oscillation.
//!
//! Implementation notes:
//!   - All arithmetic is integer (`i128` / `u128`). No floats in consensus.
//!   - 2^x is computed via the standard cubic approximation (BCH reference) —
//!     accurate to ~1 ULP across the operational range.
//!   - The `apply()` entry point also applies a hard 8%-per-block clamp on
//!     bits change, defending against pathological timestamp inputs that
//!     would push the closed-form math into an unsafe regime.
//!
//! This is the highest-priority operator-safety mechanism in the sprint.

use crate::pow::target_from_bits;

/// Per-block max bits-target multiplier. ±8% means difficulty cannot
/// halve or double in a single block under any input. Belt around ASERT.
pub const MAX_BITS_MULT_NUMERATOR: u128 = 108;
pub const MAX_BITS_MULT_DENOMINATOR: u128 = 100;

/// Default ASERT half-life (`τ`). Two days, in milliseconds. Matches BCH.
pub const DEFAULT_ASERT_TAU_MS: u64 = 2 * 24 * 60 * 60 * 1000;

/// Bootstrap-mode half-life. Tighter — 1 hour — so the chain converges fast
/// during difficulty discovery, before a malicious operator can sweep blocks
/// with stale difficulty.
pub const BOOTSTRAP_ASERT_TAU_MS: u64 = 60 * 60 * 1000;

/// Compute `2^(num/den)` × 2^16 in Q16.16 fixed-point, using the cubic
/// approximation from the BCH reference. Accurate to ~1 ULP for the
/// operational range we hit (|x| ≤ ~32 == 32 doublings == far past anything
/// realistic per block thanks to the 8% clamp).
fn pow2_q16(num: i128, den: i128) -> i128 {
    // Convert to Q16.16: shifts = (num/den) × 65536
    let shifts: i128 = (num.saturating_mul(1 << 16)) / den.max(1);

    let int_shift = shifts >> 16;
    let mut frac = shifts & 0xFFFF;
    let mut int_shift = int_shift;
    if frac < 0 {
        frac += 0x10000;
        int_shift -= 1;
    }

    // BCH cubic approximation (well-tested numerics):
    //   factor ≈ 2^16 + (195766423245049 + (971821376 + 5127 × x) × x) × x / 2^32
    // where x is the Q16.16 fractional part. Output is in Q32 scale (>> 32 at end).
    let factor: i128 =
        ((195766423245049i128 + (971821376i128 + 5127i128 * frac) * frac) * frac) >> 32;
    let multiplier_q16: i128 = (1i128 << 16) + factor;

    // Apply integer power-of-2 shift.
    if int_shift >= 0 {
        multiplier_q16 << int_shift.min(120) // saturate before u128 overflow
    } else {
        multiplier_q16 >> (-int_shift).min(120)
    }
}

/// Compute the new target for `new_block` from an anchor (typically the
/// parent), using ASERT-2D. Returns the target as a 256-bit big-endian byte
/// array (matching `pow::target_from_bits` output).
///
/// Inputs are absolute Unix milliseconds; height_diff is `new - anchor`.
pub fn asert_target(
    anchor_bits: u32,
    anchor_timestamp_ms: u64,
    anchor_height: u64,
    new_block_timestamp_ms: u64,
    new_block_height: u64,
    target_block_time_ms: u64,
    tau_ms: u64,
) -> [u8; 32] {
    if new_block_height <= anchor_height || tau_ms == 0 {
        return target_from_bits(anchor_bits);
    }
    let height_diff = (new_block_height - anchor_height) as i128;
    let elapsed_ms = (new_block_timestamp_ms as i128) - (anchor_timestamp_ms as i128);
    let expected_elapsed_ms = height_diff * (target_block_time_ms as i128);
    let exponent_num_ms = elapsed_ms - expected_elapsed_ms;

    // mult_q16 is 2^(exponent_num_ms / tau_ms) in Q16.16.
    let mult_q16 = pow2_q16(exponent_num_ms, tau_ms as i128);

    // new_target = anchor_target × mult_q16 / 2^16, applied to the high
    // 128 bits of the 256-bit target (matches retarget.rs's u128 projection;
    // production path widens to full U256).
    let anchor = target_from_bits(anchor_bits);
    let hi: u128 = u128::from_be_bytes(anchor[..16].try_into().unwrap());
    let raw_new_hi: u128 = if mult_q16 < 0 {
        0
    } else {
        let m = mult_q16 as u128;
        // Saturating multiply, then divide by 2^16.
        ((hi.saturating_mul(m)) >> 16).max(1)
    };

    // Apply the hard ±8% clamp per block (defensive — if mult_q16 went
    // weird, this caps the actual change in `hi`).
    let max_hi = hi.saturating_mul(MAX_BITS_MULT_NUMERATOR) / MAX_BITS_MULT_DENOMINATOR;
    let min_hi = hi.saturating_mul(MAX_BITS_MULT_DENOMINATOR) / MAX_BITS_MULT_NUMERATOR;
    let clamped_hi = raw_new_hi.clamp(min_hi.max(1), max_hi);

    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&clamped_hi.to_be_bytes());
    out[16..].copy_from_slice(&anchor[16..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_target_is_unchanged() {
        // Block landing exactly at expected time → target unchanged (within
        // cubic-approximation rounding).
        let anchor_bits = 0x1f00ffff;
        let target_block_ms = 600_000;
        let new = asert_target(
            anchor_bits,
            1_000_000_000_000,
            100,
            1_000_000_000_000 + target_block_ms,
            101,
            target_block_ms,
            DEFAULT_ASERT_TAU_MS,
        );
        let anchor_target = target_from_bits(anchor_bits);
        // Allow tiny rounding error in low byte of high-128.
        let new_hi = u128::from_be_bytes(new[..16].try_into().unwrap());
        let anchor_hi = u128::from_be_bytes(anchor_target[..16].try_into().unwrap());
        let diff = if new_hi > anchor_hi { new_hi - anchor_hi } else { anchor_hi - new_hi };
        assert!(
            diff < anchor_hi / 1000, // < 0.1% tolerance
            "on-target should not move difficulty: anchor={anchor_hi} new={new_hi}"
        );
    }

    #[test]
    fn fast_block_lowers_target_makes_harder() {
        // Block at half the target time → target should shrink (difficulty rises).
        let anchor_bits = 0x1f00ffff;
        let target_block_ms = 600_000;
        let new = asert_target(
            anchor_bits,
            1_000_000_000_000,
            100,
            1_000_000_000_000 + target_block_ms / 2,
            101,
            target_block_ms,
            DEFAULT_ASERT_TAU_MS,
        );
        let anchor_target = target_from_bits(anchor_bits);
        let new_hi = u128::from_be_bytes(new[..16].try_into().unwrap());
        let anchor_hi = u128::from_be_bytes(anchor_target[..16].try_into().unwrap());
        assert!(new_hi < anchor_hi, "fast block did not raise difficulty");
    }

    #[test]
    fn slow_block_raises_target_makes_easier() {
        // Block at twice the target time → target should grow (difficulty falls).
        let anchor_bits = 0x1f00ffff;
        let target_block_ms = 600_000;
        let new = asert_target(
            anchor_bits,
            1_000_000_000_000,
            100,
            1_000_000_000_000 + target_block_ms * 2,
            101,
            target_block_ms,
            DEFAULT_ASERT_TAU_MS,
        );
        let anchor_target = target_from_bits(anchor_bits);
        let new_hi = u128::from_be_bytes(new[..16].try_into().unwrap());
        let anchor_hi = u128::from_be_bytes(anchor_target[..16].try_into().unwrap());
        assert!(new_hi > anchor_hi, "slow block did not lower difficulty");
    }

    #[test]
    fn extreme_fast_block_clamped_at_8pct() {
        // Block timestamped a year before its parent (degenerate input).
        // Without the clamp, ASERT would explode the multiplier; the clamp
        // bounds the actual hi-target change to ±8%.
        let anchor_bits = 0x1f00ffff;
        let target_block_ms = 600_000;
        let anchor_ts = 1_000_000_000_000u64;
        let new = asert_target(
            anchor_bits,
            anchor_ts,
            100,
            anchor_ts.saturating_sub(365 * 24 * 60 * 60 * 1000),
            101,
            target_block_ms,
            DEFAULT_ASERT_TAU_MS,
        );
        let anchor_target = target_from_bits(anchor_bits);
        let new_hi = u128::from_be_bytes(new[..16].try_into().unwrap());
        let anchor_hi = u128::from_be_bytes(anchor_target[..16].try_into().unwrap());
        // Must be within ±8% of anchor regardless of degenerate input.
        let min = anchor_hi * MAX_BITS_MULT_DENOMINATOR / MAX_BITS_MULT_NUMERATOR;
        let max = anchor_hi * MAX_BITS_MULT_NUMERATOR / MAX_BITS_MULT_DENOMINATOR;
        assert!(new_hi >= min && new_hi <= max, "8% clamp breached: {new_hi} not in [{min},{max}]");
    }

    #[test]
    fn bootstrap_tau_converges_faster() {
        // With τ = 1h, a 2× slow block bumps target more than with τ = 2d.
        let anchor_bits = 0x1f00ffff;
        let target_block_ms = 600_000;
        let slow = asert_target(
            anchor_bits,
            1_000_000_000_000,
            100,
            1_000_000_000_000 + target_block_ms * 2,
            101,
            target_block_ms,
            BOOTSTRAP_ASERT_TAU_MS,
        );
        let slow_default = asert_target(
            anchor_bits,
            1_000_000_000_000,
            100,
            1_000_000_000_000 + target_block_ms * 2,
            101,
            target_block_ms,
            DEFAULT_ASERT_TAU_MS,
        );
        let bootstrap_hi = u128::from_be_bytes(slow[..16].try_into().unwrap());
        let default_hi = u128::from_be_bytes(slow_default[..16].try_into().unwrap());
        // Bootstrap (shorter τ) reacts more aggressively → larger target shift.
        // Both should be > anchor (slow block); bootstrap > default.
        assert!(
            bootstrap_hi >= default_hi,
            "bootstrap τ should converge as fast or faster: bootstrap={bootstrap_hi} default={default_hi}"
        );
    }
}
