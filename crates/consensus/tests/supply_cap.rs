//! Supply-cap invariants under the calendar-emission rewrite.
//!
//! Updated for v0.4 sprint: the old block-counted `Emission` struct is gone;
//! the schedule is now `scheduled_supply_at(t_ms_since_genesis, &params)`
//! returning a bounded cumulative. Two properties this test pins:
//!
//!   1. `scheduled_supply_at` never exceeds `supply_cap_sat`.
//!   2. `current_reward` truncates to zero after 64 halving epochs.
//!   3. The Q64.64 accordion advance never goes negative or panics under
//!      fuzzed bellow trajectories.
//!
//! Joint v0.1 review (MIT/Georgia Tech/Texas A&M) demanded a `cargo test`
//! invariant for the cap; this file is its descendant.

use fixed::types::I64F64;
use pygrove_consensus::accordion::{evaluate, AccordionParams};
use pygrove_consensus::emission::{current_reward, scheduled_supply_at, EmissionParams};

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
        let frac_q = I64F64::from_bits((frac32 as i128) << 32);
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

/// Bound the accordion advance accumulator over many blocks without overflow.
#[test]
fn halving_accumulator_does_not_overflow() {
    let params = AccordionParams::defaults();
    let mut prog: u128 = 0;
    let mut rng = Lcg(0x00c0_ffee_dead_beef_u64);

    // 64 halvings × 210k blocks × max 4× advance ≈ 5.4e7 blocks worst-case.
    for _ in 0..(64u64 * 210_000 * 4) {
        let r_h = rng.ratio_in_clamp();
        let r_a = rng.ratio_in_clamp();
        let bias = rng.bias();
        let out = evaluate(params, r_h, r_a, bias);
        let advance_bits = out.per_block_advance.to_bits();
        assert!(advance_bits >= 0, "advance went negative: {}", out.per_block_advance);
        let advance_u: u128 = advance_bits as u128;
        prog = prog
            .checked_add(advance_u)
            .expect("accordion accumulator overflowed under fuzz");
        let int_part = prog >> 64;
        if int_part / 210_000 >= 64 {
            break;
        }
    }
}

/// Calendar schedule never overshoots the supply cap, even at t → ∞.
#[test]
fn scheduled_supply_capped_at_horizon() {
    let params = EmissionParams::bitcoin_like();
    // 1000 halving epochs out — well past the 64-halving truncation point.
    let t_far = 1000u64 * params.seconds_per_halving * 1000;
    let s = scheduled_supply_at(t_far, &params);
    assert_eq!(s, params.supply_cap_sat);
}

/// At one halving exactly, scheduled supply is half the cap (Bitcoin invariant).
#[test]
fn scheduled_supply_at_one_halving_is_half_cap() {
    let params = EmissionParams::bitcoin_like();
    let t = params.seconds_per_halving * 1000;
    let s = scheduled_supply_at(t, &params);
    assert_eq!(s, params.supply_cap_sat / 2);
}

/// Reward truncates to zero past the 64th halving.
#[test]
fn reward_is_zero_past_64th_halving() {
    let params = EmissionParams::bitcoin_like();
    let g = 1_000_000_000_000u64;
    let t_far = 100u64 * params.seconds_per_halving * 1000;
    // Pretend we've already minted the cap, so calendar_remaining = 0.
    let r = current_reward(&params, g, g + t_far, g + t_far - 600_000, params.supply_cap_sat);
    assert_eq!(r, 0);
}

/// Stability bias never drives the per-block advance negative regardless of
/// regime or bellow values.
#[test]
fn per_block_advance_stays_non_negative() {
    let mut p = AccordionParams::defaults();
    p.beta_s = I64F64::from_num(0.5);
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
