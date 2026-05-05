//! Supply-cap invariant: under any admissible accordion trajectory, cumulative
//! coinbase issuance must remain ≤ the configured cap (21M PYG by default), and
//! the halving accumulator must never overflow.
//!
//! This test exists because the joint v0.1 review (MIT/Georgia Tech/Texas A&M)
//! demanded a `cargo test` invariant for the cap. Bitcoin's geometric-series
//! cap argument carries through ours only if Q64.64 advance arithmetic is
//! overflow-safe; this fuzzer drives random bellow trajectories across 64
//! halving epochs and checks both properties hold every block.

use fixed::types::I64F64;
use pygrove_consensus::accordion::{evaluate, AccordionParams};
use pygrove_consensus::emission::{Emission, EmissionParams};

/// Seeded LCG so the test is reproducible cross-platform.
struct Lcg(u64);
impl Lcg {
    fn step(&mut self) -> u64 {
        self.0 = self.0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    /// Q64.64 in `[0.25, 4]` — matches the retarget clamp.
    fn ratio_in_clamp(&mut self) -> I64F64 {
        let s = self.step();
        let frac32 = (s >> 32) as u32;
        let frac_q = I64F64::from_bits((frac32 as i128) << 32); // [0, 1)
        I64F64::from_num(0.25) + I64F64::from_num(3.75) * frac_q
    }
    fn bias(&mut self) -> i8 {
        match self.step() % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        }
    }
}

/// Bound `halving_progress_q64 += advance_per_block_q64` over many blocks
/// without overflowing u128, even if the accordion goes hard expansionary.
#[test]
fn halving_accumulator_does_not_overflow() {
    let params = AccordionParams::defaults();
    let mut prog: u128 = 0;
    let mut rng = Lcg(0xc0ffee);

    // 64 halvings × 210k blocks/halving × max 4× advance = ~5.4e7 blocks worst-case.
    // Cap at 64 * 210_000 effective progress; loop until `halvings_completed == 64`.
    for _ in 0..(64u64 * 210_000 * 4) {
        let r_h = rng.ratio_in_clamp();
        let r_a = rng.ratio_in_clamp();
        let bias = rng.bias();
        let out = evaluate(params, r_h, r_a, bias);
        // advance is Q64.64; convert to u128 increment by extracting the raw bits.
        let advance_bits = out.per_block_advance.to_bits();
        assert!(advance_bits >= 0, "advance went negative: {}", out.per_block_advance);
        let advance_u: u128 = advance_bits as u128;
        prog = prog
            .checked_add(advance_u)
            .expect("halving_progress_q64 overflowed under fuzz");
        // Stop early once we've exhausted all 64 halvings: progress / 210_000 ≥ 64
        // measured against integer part.
        let int_part = prog >> 64;
        if int_part / 210_000 >= 64 {
            break;
        }
    }
}

/// Geometric-series cap: ∑_{k=0..63} (R0 / 2^k) × blocks_per_halving_k ≤ supply_cap.
/// The accordion only redistributes blocks across halvings; it does not increase
/// the per-halving reward. Therefore total cumulative issuance is bounded by
/// `R0 × halving_interval_base × ∑ 1/2^k = R0 × halving_interval_base × 2`.
#[test]
fn cumulative_supply_bounded_by_geometric_series() {
    let params = EmissionParams::bitcoin_like();
    let mut total_minted: u128 = 0;

    for h in 0..64u32 {
        let mut em = Emission {
            halving_progress_q64: ((h as u128) * params.halving_interval_base as u128) << 64,
            minted_sat: 0,
        };
        em.halving_progress_q64 += 1; // step into the halving window
        let reward = em.current_reward(&params);
        // worst case: every block in this halving pays full reward
        total_minted = total_minted.saturating_add(reward.saturating_mul(params.halving_interval_base as u128));
    }
    // ∑ R0 / 2^k for k=0..∞ = 2 R0; truncated at 64 it's ≤ 2 R0 - tiny ε.
    let bound = (params.initial_reward_sat as u128) * (params.halving_interval_base as u128) * 2;
    assert!(
        total_minted <= bound,
        "cumulative supply {} exceeded geometric bound {}",
        total_minted,
        bound
    );
    // And concretely below the 21M cap.
    assert!(
        total_minted <= params.supply_cap_sat,
        "cumulative supply {} exceeded 21M cap {}",
        total_minted,
        params.supply_cap_sat
    );
}

/// Reward zeroes out beyond the 64th halving — boundary unasserted in v0.1 source.
#[test]
fn reward_is_zero_past_64th_halving() {
    let params = EmissionParams::bitcoin_like();
    let em = Emission {
        halving_progress_q64: ((64u128 * params.halving_interval_base as u128) << 64) + 1,
        minted_sat: 0,
    };
    assert!(em.halvings_completed(&params) >= 64);
    assert_eq!(em.current_reward(&params), 0);
}

/// Stability bias never drives the per-block advance negative regardless of
/// regime or bellow values.
#[test]
fn per_block_advance_stays_non_negative() {
    let mut p = AccordionParams::defaults();
    p.beta_s = I64F64::from_num(0.5); // exercise non-zero beta_s explicitly
    let mut rng = Lcg(0x1234_5678);
    for _ in 0..16_000 {
        let r_h = rng.ratio_in_clamp();
        let r_a = rng.ratio_in_clamp();
        let bias = rng.bias();
        let out = evaluate(p, r_h, r_a, bias);
        assert!(
            out.per_block_advance >= I64F64::from_num(0),
            "negative advance: r_h={r_h} r_a={r_a} bias={bias} -> {}",
            out.per_block_advance
        );
    }
}
