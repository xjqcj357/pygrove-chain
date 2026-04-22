//! Bitcoin-style retarget math. The accordion layer consumes this output and dampens
//! it; keep this module pure so the dampening is testable against the raw curve.

/// Clamp the ratio `actual / expected` to `[1/4, 4]` as Bitcoin does.
pub fn clamp_retarget(actual_timespan_ms: u64, expected_timespan_ms: u64) -> (u64, u64) {
    let min = expected_timespan_ms / 4;
    let max = expected_timespan_ms.saturating_mul(4);
    let actual = actual_timespan_ms.clamp(min, max);
    (actual, expected_timespan_ms)
}

/// Raw Bitcoin retarget: `new = old * actual / expected`, with the `[/4, *4]` clamp.
///
/// Target arithmetic is done on a `u128` projection of the top 16 bytes — adequate for
/// v0.1 plumbing; the production path upgrades to full 256-bit big-integer math.
pub fn bitcoin_retarget(old_target: [u8; 32], actual_ms: u64, expected_ms: u64) -> [u8; 32] {
    let (actual, expected) = clamp_retarget(actual_ms, expected_ms);
    let hi = u128::from_be_bytes(old_target[..16].try_into().unwrap());
    // Avoid overflow by splitting the multiply.
    let num = hi as u128;
    let new_hi = num
        .saturating_mul(actual as u128)
        .checked_div(expected as u128)
        .unwrap_or(num);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&new_hi.to_be_bytes());
    out[16..].copy_from_slice(&old_target[16..]);
    out
}
