//! Bitcoin-style retarget math. The accordion layer consumes this output and dampens
//! it; keep this module pure so the dampening is testable against the raw curve.
//!
//! Targets are 256-bit unsigned integers expressed as `[u8; 32]` big-endian. The
//! retarget computes `new = old * actual / expected` over the full 256-bit width.

/// Clamp the ratio `actual / expected` to `[1/4, 4]` as Bitcoin does.
pub fn clamp_retarget(actual_timespan_ms: u64, expected_timespan_ms: u64) -> (u64, u64) {
    let min = expected_timespan_ms / 4;
    let max = expected_timespan_ms.saturating_mul(4);
    let actual = actual_timespan_ms.clamp(min, max);
    (actual, expected_timespan_ms)
}

/// Bitcoin retarget: `new = old * actual / expected`, with the `[/4, *4]` clamp on
/// the timespan ratio. Full 256-bit big-integer arithmetic, no truncation.
pub fn bitcoin_retarget(old_target: [u8; 32], actual_ms: u64, expected_ms: u64) -> [u8; 32] {
    let (actual, expected) = clamp_retarget(actual_ms, expected_ms);
    if expected == 0 {
        return old_target;
    }
    let prod = mul_u256_u64(&old_target, actual);
    let (quot, _) = div_u320_u64(&prod, expected);
    // `quot` is up to 320 bits across 5 u64 limbs (limb 0 high). If anything
    // sits in the high limb, the target overflowed past 2^256-1: saturate.
    if quot[0] != 0 {
        return [0xFFu8; 32];
    }
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&quot[1].to_be_bytes());
    out[8..16].copy_from_slice(&quot[2].to_be_bytes());
    out[16..24].copy_from_slice(&quot[3].to_be_bytes());
    out[24..32].copy_from_slice(&quot[4].to_be_bytes());
    out
}

/// `[u8; 32]` (big-endian, 4 limbs of u64) × u64 → 320-bit big-endian as `[u64; 5]`.
fn mul_u256_u64(a: &[u8; 32], b: u64) -> [u64; 5] {
    let limbs: [u64; 4] = [
        u64::from_be_bytes(a[0..8].try_into().unwrap()),
        u64::from_be_bytes(a[8..16].try_into().unwrap()),
        u64::from_be_bytes(a[16..24].try_into().unwrap()),
        u64::from_be_bytes(a[24..32].try_into().unwrap()),
    ];
    let mut out = [0u64; 5];
    let mut carry: u128 = 0;
    // Multiply low → high (limb index 3 is least significant).
    for i in (0..4).rev() {
        let p = (limbs[i] as u128) * (b as u128) + carry;
        out[i + 1] = p as u64;
        carry = p >> 64;
    }
    out[0] = carry as u64;
    out
}

/// 320-bit / u64 long division. Returns (quotient, remainder).
fn div_u320_u64(num: &[u64; 5], d: u64) -> ([u64; 5], u64) {
    debug_assert!(d != 0);
    let mut q = [0u64; 5];
    let mut rem: u128 = 0;
    for i in 0..5 {
        let acc = (rem << 64) | (num[i] as u128);
        q[i] = (acc / d as u128) as u64;
        rem = acc % d as u128;
    }
    (q, rem as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target_from_hex(hex_str: &str) -> [u8; 32] {
        let bytes = hex::decode(hex_str).unwrap();
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }

    #[test]
    fn identity_when_actual_equals_expected() {
        let t = target_from_hex("00000000ffff0000000000000000000000000000000000000000000000000000");
        assert_eq!(bitcoin_retarget(t, 1_209_600_000, 1_209_600_000), t);
    }

    #[test]
    fn clamp_floor_quarter() {
        // 1/16 of expected → clamped to 1/4 → target 1/4 of original.
        let t = target_from_hex("0000000080000000000000000000000000000000000000000000000000000000");
        let out = bitcoin_retarget(t, 1, 1_209_600_000);
        let expect = target_from_hex("0000000020000000000000000000000000000000000000000000000000000000");
        assert_eq!(out, expect);
    }

    #[test]
    fn clamp_ceiling_quadruple() {
        // 16x expected → clamped to 4x → target 4x of original.
        let t = target_from_hex("0000000010000000000000000000000000000000000000000000000000000000");
        let out = bitcoin_retarget(t, u64::MAX, 1_209_600_000);
        let expect = target_from_hex("0000000040000000000000000000000000000000000000000000000000000000");
        assert_eq!(out, expect);
    }

    #[test]
    fn full_width_no_truncation() {
        // A target with non-zero bits in the low 16 bytes — the v0.1 truncation
        // path discarded these; the U256 path must preserve them.
        let t = target_from_hex("00000000ffff000000000000000000000000000000000000000000000000beef");
        let out = bitcoin_retarget(t, 1_209_600_000 * 2, 1_209_600_000);
        // Doubling preserves the low bits modulo carries from neighbouring limbs.
        // Concretely: 0xbeef * 2 = 0x17dde — the low 16 bits of out[24..32] are 0x7dde.
        let low_u16 = u16::from_be_bytes(out[30..32].try_into().unwrap());
        assert_eq!(low_u16, 0x7dde);
    }

    #[test]
    fn saturates_on_overflow() {
        // Very high target × ratio that would push past 2^256.
        let t = [0xFFu8; 32];
        let out = bitcoin_retarget(t, 1_209_600_000 * 4, 1_209_600_000);
        assert_eq!(out, [0xFFu8; 32]);
    }

    #[test]
    fn zero_expected_returns_old() {
        let t = target_from_hex("00000000ffff0000000000000000000000000000000000000000000000000000");
        assert_eq!(bitcoin_retarget(t, 1, 0), t);
    }

    #[test]
    fn deterministic_under_seeded_fuzz() {
        // Seeded LCG: same seed → byte-identical digest, on every platform.
        // The point isn't randomness; it's determinism. Two passes must match.
        fn run() -> [u8; 32] {
            let mut seed: u64 = 0xc0ffee_dead_beefu64;
            let mut h = blake3::Hasher::new();
            for _ in 0..1024 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let mut t = [0u8; 32];
                for (i, byte) in t.iter_mut().enumerate() {
                    *byte = ((seed >> ((i * 7) & 63)) & 0xff) as u8;
                }
                let actual = (seed.wrapping_mul(31)) & 0x07_ffff_ffff;
                let expected = 1_209_600_000u64;
                let out = bitcoin_retarget(t, actual, expected);
                h.update(&out);
            }
            let mut d = [0u8; 32];
            d.copy_from_slice(h.finalize().as_bytes());
            d
        }
        let a = run();
        let b = run();
        assert_eq!(a, b, "retarget output drifted between identical runs");
    }
}
