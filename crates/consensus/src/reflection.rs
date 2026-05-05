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

/// Compute the stability bias `s ∈ {-1, 0, +1}` from two consecutive long-window
/// reflections. `s` is the sign of `Δ(fee_sum / active)` — the change in fee per
/// qualifying active address over the long window.
///
/// Sign convention follows whitepaper §5: `s = +1` when fee-per-user is rising
/// (chain heating, accelerate halving), `s = -1` when falling, `s = 0` when stable
/// or when either window has no qualifying activity.
///
/// Inputs are integers; the comparison is done by cross-multiplying to avoid
/// introducing floating-point math into the consensus path.
pub fn compute_stability_bias(prev: &Reflection, curr: &Reflection) -> i8 {
    if prev.active_addresses == 0 || curr.active_addresses == 0 {
        return 0;
    }
    // Compare curr.fee_sum / curr.active vs prev.fee_sum / prev.active by
    // cross-multiplying as u128 → no division, no precision loss.
    let lhs = curr
        .fee_sum
        .saturating_mul(prev.active_addresses as u128);
    let rhs = prev
        .fee_sum
        .saturating_mul(curr.active_addresses as u128);
    if lhs > rhs {
        1
    } else if lhs < rhs {
        -1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refl(fee: u128, active: u64) -> Reflection {
        Reflection {
            fee_sum: fee,
            active_addresses: active,
            ..Default::default()
        }
    }

    #[test]
    fn equilibrium_is_zero() {
        // Same fee-per-active in both windows → s = 0.
        let p = refl(1000, 100);
        let c = refl(2000, 200);
        assert_eq!(compute_stability_bias(&p, &c), 0);
    }

    #[test]
    fn rising_fee_per_user_is_positive() {
        let p = refl(1000, 100);   // 10 per user
        let c = refl(3000, 200);   // 15 per user
        assert_eq!(compute_stability_bias(&p, &c), 1);
    }

    #[test]
    fn falling_fee_per_user_is_negative() {
        let p = refl(2000, 100);   // 20 per user
        let c = refl(2000, 200);   // 10 per user
        assert_eq!(compute_stability_bias(&p, &c), -1);
    }

    #[test]
    fn empty_window_is_zero() {
        let p = refl(0, 0);
        let c = refl(1000, 100);
        assert_eq!(compute_stability_bias(&p, &c), 0);
    }
}
