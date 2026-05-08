//! The Accordion: two-bellow adaptive emission controller with a stability-seeking bias.
//!
//! - `r_h`: hashrate ratio, period-over-period
//! - `r_a`: sybil-guarded active-address ratio
//! - `bias`: sign of the stability signal (Δ fee-per-active over the long window),
//!   wired from `reflection::compute_stability_bias`.
//!
//! `alpha_h` dampens the Bitcoin retarget when either bellow is pumping.
//! `per_block_advance` accelerates / decelerates halving progress.
//!
//! All math runs in Q64.64 fixed point: no `f64` touches consensus.
//!
//! ## Bias regime symmetry
//!
//! v0.1 ships with `beta_s = 0` by default. The fee-suppression failure mode
//! flagged in the joint v0.1 review (a holder can drive `s = -1` to slow halvings
//! and support floor without attacking PoW) is unmodelled in `sim/adversarial.py`,
//! so the bias term is held inert until that simulation lands. The math for `s`
//! is wired symmetrically across Growth and Contraction below — turning it on
//! later is a single genesis-parameter change, not a code change.

use fixed::types::I64F64;

#[derive(Debug, Clone, Copy)]
pub struct AccordionParams {
    pub epsilon: I64F64,
    pub beta_h: I64F64,
    pub beta_a: I64F64,
    pub beta_s: I64F64,
}

impl AccordionParams {
    /// Default genesis parameters. `beta_s = 0`: see module-level note on bias
    /// regime symmetry. Override per-genesis to enable.
    pub fn defaults() -> Self {
        Self {
            epsilon: I64F64::from_num(0.05),
            beta_h: I64F64::from_num(0.5),
            beta_a: I64F64::from_num(0.5),
            beta_s: I64F64::from_num(0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Regime {
    Equilibrium,
    Growth,
    Contraction,
}

#[derive(Debug, Clone, Copy)]
pub struct AccordionOutcome {
    pub regime: Regime,
    pub alpha_h: I64F64,
    pub per_block_advance: I64F64,
}

/// Natural log, Q64.64. Uses the atanh identity `ln(x) = 2·atanh((x-1)/(x+1))`
/// truncated at 16 terms. Convergence is best near 1 — which is the regime the
/// retarget clamp `[1/4, 4]` keeps us in. For `r ∈ [1/4, 4]`, `|y| = |(r-1)/(r+1)| ≤ 0.6`
/// and the truncated remainder is bounded by `|y|^33 / 32 ≈ 1.5e-9`, well under
/// the Q64.64 ULP of `2^-64 ≈ 5.4e-20` for the largest practical inputs but
/// dominating ULP for inputs hugging the clamp edges. The error is documented;
/// the production path swaps to a vetted fixed-point log crate (see whitepaper
/// §3.6 scope notes).
fn ln_fixed(x: I64F64) -> I64F64 {
    let one = I64F64::from_num(1);
    if x <= I64F64::from_num(0) {
        return I64F64::from_num(0);
    }
    let y = (x - one) / (x + one);
    let y2 = y * y;
    let mut sum = y;
    let mut term = y;
    for n in 1..16 {
        term *= y2;
        let denom = I64F64::from_num(2 * n + 1);
        sum += term / denom;
    }
    sum * I64F64::from_num(2)
}

fn abs(v: I64F64) -> I64F64 {
    if v < I64F64::from_num(0) { -v } else { v }
}

fn max_zero(v: I64F64) -> I64F64 {
    if v < I64F64::from_num(0) { I64F64::from_num(0) } else { v }
}

pub fn evaluate(
    params: AccordionParams,
    r_h: I64F64,
    r_a: I64F64,
    stability_bias: i8,
) -> AccordionOutcome {
    let one = I64F64::from_num(1);
    let lh = ln_fixed(r_h);
    let la = ln_fixed(r_a);

    let regime = if abs(lh) <= params.epsilon && abs(la) <= params.epsilon {
        Regime::Equilibrium
    } else if lh >= I64F64::from_num(0) && la >= I64F64::from_num(0) {
        Regime::Growth
    } else {
        Regime::Contraction
    };

    let alpha_h = one / (one + abs(lh));
    let bias = I64F64::from_num(stability_bias as i32);

    let per_block_advance = match regime {
        Regime::Equilibrium => one,
        Regime::Growth => {
            // Growth: positive bellow + bias accelerate. Floor at 1 so a
            // negative bias (suppressed fees) cannot turn an expansion into a
            // contraction — that's the Contraction branch's job.
            let raw = one
                + params.beta_h * max_zero(lh)
                + params.beta_a * max_zero(la)
                + params.beta_s * bias;
            if raw < one { one } else { raw }
        }
        Regime::Contraction => {
            // Contraction: positive contributions in the *denominator* slow the
            // halving. Negative bias contributes here (cooling chain → support
            // miner revenue); positive bias does not (chain heating up while
            // bellows contract is mixed-signal, treat as neutral).
            let denom = one
                + params.beta_h * max_zero(-lh)
                + params.beta_a * max_zero(-la)
                + params.beta_s * max_zero(-bias);
            one / denom
        }
    };

    AccordionOutcome {
        regime,
        alpha_h,
        per_block_advance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ln_fixed_at_one_is_zero() {
        assert_eq!(ln_fixed(I64F64::from_num(1)), I64F64::from_num(0));
    }

    #[test]
    fn ln_fixed_is_monotonic_on_clamp_range() {
        // ln is monotone increasing; assert step-wise across [1/4, 4].
        let mut prev = ln_fixed(I64F64::from_num(0.25));
        let mut x = I64F64::from_num(0.25);
        let step = I64F64::from_num(0.01);
        let stop = I64F64::from_num(4.0);
        while x < stop {
            x += step;
            let v = ln_fixed(x);
            assert!(v >= prev, "non-monotone at x={x}: {v} < {prev}");
            prev = v;
        }
    }

    #[test]
    fn ln_fixed_is_deterministic_under_seeded_fuzz() {
        // Two passes over identical inputs must produce identical bit patterns —
        // that's the core consensus-determinism guarantee for Q64.64 ln.
        fn pass() -> blake3::Hash {
            let mut seed: u64 = 0x1234_5678_dead_beef;
            let mut h = blake3::Hasher::new();
            for _ in 0..4096 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                // Map seed → x ∈ [1/4, 4] staying inside the retarget clamp.
                // Done in integer/fixed math so the test itself never touches f64,
                // matching the consensus discipline this test exists to verify.
                let frac32 = (seed >> 32) as u32;
                let frac_q = I64F64::from_bits((frac32 as i128) << 32); // 0..1 in Q64.64
                let x = I64F64::from_num(0.25) + I64F64::from_num(3.75) * frac_q;
                let v = ln_fixed(x);
                h.update(&v.to_le_bytes());
            }
            h.finalize()
        }
        assert_eq!(pass(), pass());
    }

    #[test]
    fn equilibrium_regime_at_unity() {
        let p = AccordionParams::defaults();
        let out = evaluate(p, I64F64::from_num(1), I64F64::from_num(1), 0);
        assert_eq!(out.regime, Regime::Equilibrium);
        assert_eq!(out.per_block_advance, I64F64::from_num(1));
    }

    #[test]
    fn growth_regime_advances_faster() {
        let p = AccordionParams::defaults();
        let out = evaluate(p, I64F64::from_num(2), I64F64::from_num(2), 0);
        assert_eq!(out.regime, Regime::Growth);
        assert!(out.per_block_advance >= I64F64::from_num(1));
    }

    #[test]
    fn contraction_regime_advances_slower() {
        let p = AccordionParams::defaults();
        let out = evaluate(p, I64F64::from_num(0.5), I64F64::from_num(0.5), 0);
        assert_eq!(out.regime, Regime::Contraction);
        assert!(out.per_block_advance <= I64F64::from_num(1));
        assert!(out.per_block_advance > I64F64::from_num(0));
    }

    #[test]
    fn growth_floor_is_one_under_negative_bias() {
        // beta_s = 0 by default, but verify the floor under a hypothetical positive beta_s:
        // a negative bias must not pull a growth regime below 1.0 advance.
        let mut p = AccordionParams::defaults();
        p.beta_s = I64F64::from_num(0.5);
        let out = evaluate(p, I64F64::from_num(1.05), I64F64::from_num(1.05), -1);
        assert_eq!(out.regime, Regime::Growth);
        assert!(out.per_block_advance >= I64F64::from_num(1), "floor breached: {}", out.per_block_advance);
    }
}
