//! The Accordion: two-bellow adaptive emission controller with a stability-seeking bias.
//!
//! - `r_h`: hashrate ratio, period-over-period
//! - `r_a`: sybil-guarded active-address ratio
//! - `bias`: sign of the stability signal (Δ fee-per-active over the long window)
//!
//! `alpha_h` dampens the Bitcoin retarget when either bellow is pumping.
//! `per_block_advance` accelerates / decelerates halving progress.
//!
//! All math runs in Q64.64 fixed point: no `f64` touches consensus.

use fixed::types::I64F64;

#[derive(Debug, Clone, Copy)]
pub struct AccordionParams {
    pub epsilon: I64F64,
    pub beta_h: I64F64,
    pub beta_a: I64F64,
    pub beta_s: I64F64,
}

impl AccordionParams {
    pub fn defaults() -> Self {
        Self {
            epsilon: I64F64::from_num(0.05),
            beta_h: I64F64::from_num(0.5),
            beta_a: I64F64::from_num(0.5),
            beta_s: I64F64::from_num(0.25),
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

/// Natural log, Q64.64. v0.1 uses a series expansion; production path can swap to a
/// vetted fixed-point log crate.
fn ln_fixed(x: I64F64) -> I64F64 {
    let one = I64F64::from_num(1);
    if x <= I64F64::from_num(0) {
        return I64F64::from_num(0);
    }
    // ln(x) = 2 * atanh((x-1)/(x+1)); good convergence near 1, which is the regime we care about.
    let y = (x - one) / (x + one);
    let y2 = y * y;
    let mut sum = y;
    let mut term = y;
    for n in 1..16 {
        term = term * y2;
        let denom = I64F64::from_num(2 * n + 1);
        sum = sum + term / denom;
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

    let advance_raw = one
        + params.beta_h * max_zero(lh)
        + params.beta_a * max_zero(la)
        + params.beta_s * bias;

    let per_block_advance = match regime {
        Regime::Equilibrium => one,
        Regime::Growth => advance_raw,
        Regime::Contraction => one / (one + params.beta_h * max_zero(-lh) + params.beta_a * max_zero(-la)),
    };

    AccordionOutcome {
        regime,
        alpha_h,
        per_block_advance,
    }
}
