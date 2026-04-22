//! Proof-of-work target check and header hash.
//!
//! v0.1 uses Blake3-XOF-512 truncated to 32 bytes for the header PoW hash. The
//! production seal will be RandomX-lite + a class-group Wesolowski VDF finalizer; this
//! module is the slot those live in.

use blake3::Hasher;
use pygrove_core::BlockHeader;

/// Compact `bits` (Bitcoin nBits) → 256-bit target expressed as big-endian bytes.
pub fn target_from_bits(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    let mut target = [0u8; 32];
    if exponent == 0 || exponent > 32 {
        return target;
    }
    let m_bytes = mantissa.to_be_bytes();
    // Place mantissa's 3 low bytes at offset (32 - exponent)..(32 - exponent + 3).
    for (i, b) in m_bytes[1..4].iter().enumerate() {
        let idx = 32usize.saturating_sub(exponent).saturating_add(i);
        if idx < 32 {
            target[idx] = *b;
        }
    }
    target
}

/// Canonical header hash used by PoW. Serialized header bytes are hashed with a
/// chain-specific domain tag so no external Blake3 use ever collides with a block hash.
pub fn hash_header(header: &BlockHeader) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"PGhdr\x00");
    h.update(&header.version.to_le_bytes());
    h.update(&header.height.to_le_bytes());
    h.update(&header.parent);
    h.update(&header.timestamp_ms.to_le_bytes());
    h.update(&header.bits.to_le_bytes());
    h.update(&header.nonce.to_le_bytes());
    h.update(&header.tx_root);
    h.update(&header.witness_root);
    h.update(&header.state_root);
    h.update(&header.reflect_root);
    h.update(&header.coinbase);
    h.update(&[header.sig_algo, header.hash_algo]);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize().as_bytes()[..]);
    out
}

/// True iff `hash` is numerically ≤ `target` under big-endian byte ordering.
pub fn meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for (h, t) in hash.iter().zip(target.iter()) {
        if h < t {
            return true;
        }
        if h > t {
            return false;
        }
    }
    true
}
