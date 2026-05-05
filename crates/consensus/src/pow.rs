//! Proof-of-work target check and header hash.
//!
//! v0.1 uses Blake3-XOF-512 truncated to 32 bytes for the header PoW hash, routed
//! through [`pygrove_core::hash::hash_with_domain`] so the domain tag layout is
//! enforced in one place. The production seal will be RandomX-lite + a class-group
//! Wesolowski VDF finalizer (see whitepaper §6, scope: deferred to v1.1).
//!
//! No raw `blake3::Hasher` calls live in this module — every byte the header
//! contributes to the digest goes through the canonical `hash_with_domain` helper
//! so a future `UpgradeCrypto` rotation does not have to chase scattered call sites.

use pygrove_core::hash::{hash_with_domain, truncate_to_32, HashAlgo};
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

/// Canonical, deterministic header preimage. The bytes here, and only these bytes,
/// feed the PoW hash. Any new field on `BlockHeader` must be appended here.
fn header_preimage(header: &BlockHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 8 + 32 + 8 + 4 + 8 + 32 + 32 + 32 + 32 + 32 + 2);
    buf.extend_from_slice(&header.version.to_le_bytes());
    buf.extend_from_slice(&header.height.to_le_bytes());
    buf.extend_from_slice(&header.parent);
    buf.extend_from_slice(&header.timestamp_ms.to_le_bytes());
    buf.extend_from_slice(&header.bits.to_le_bytes());
    buf.extend_from_slice(&header.nonce.to_le_bytes());
    buf.extend_from_slice(&header.tx_root);
    buf.extend_from_slice(&header.witness_root);
    buf.extend_from_slice(&header.state_root);
    buf.extend_from_slice(&header.reflect_root);
    buf.extend_from_slice(&header.coinbase);
    buf.extend_from_slice(&[header.sig_algo, header.hash_algo]);
    buf
}

/// Canonical header hash used by PoW. Routes through `hash_with_domain` with the
/// `"hdr"` tag, then truncates the 64-byte XOF output to the 32 bytes that fit the
/// target. The domain tag is what stops a hash collision in another subtree (a
/// transaction body, an account leaf) from substituting for a block hash.
pub fn hash_header(header: &BlockHeader) -> [u8; 32] {
    let preimage = header_preimage(header);
    let d = hash_with_domain(HashAlgo::Blake3Xof512, "hdr", &preimage);
    truncate_to_32(&d)
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

#[cfg(test)]
mod tests {
    use super::*;
    use pygrove_core::BlockHeader;

    fn dummy_header(nonce: u64) -> BlockHeader {
        BlockHeader {
            version: 1,
            height: 7,
            parent: [0x11u8; 32],
            timestamp_ms: 1_700_000_000_000,
            bits: 0x1f00ffff,
            nonce,
            tx_root: [0x22u8; 32],
            witness_root: [0x33u8; 32],
            state_root: [0x44u8; 32],
            reflect_root: [0x55u8; 32],
            coinbase: [0x66u8; 32],
            sig_algo: 1,
            hash_algo: 1,
        }
    }

    #[test]
    fn header_hash_is_deterministic() {
        let h = dummy_header(42);
        assert_eq!(hash_header(&h), hash_header(&h));
    }

    #[test]
    fn nonce_change_flips_hash() {
        let a = hash_header(&dummy_header(0));
        let b = hash_header(&dummy_header(1));
        assert_ne!(a, b);
    }

    #[test]
    fn header_hash_uses_domain_tag() {
        // A raw blake3 of the same preimage MUST differ from hash_header — that's
        // the whole point of the domain tag. If this ever passes equal, the tag
        // got dropped.
        let h = dummy_header(0);
        let preimage = header_preimage(&h);
        let mut raw = blake3::Hasher::new();
        raw.update(&preimage);
        let mut raw_out = [0u8; 32];
        raw_out.copy_from_slice(raw.finalize().as_bytes());
        assert_ne!(hash_header(&h), raw_out);
    }
}
