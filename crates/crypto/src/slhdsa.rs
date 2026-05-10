//! SLH-DSA-128s dispatch (sig_algo = 2).
//!
//! Wired via `slh-dsa = "0.1"` (RustCrypto's pure-Rust port of FIPS 205).
//! Available in **all build profiles**, including FIPS — SLH-DSA-128s is the
//! cornerstone of `FIPS_ALLOWLIST_SIG`.
//!
//! ## Determinism
//!
//! Per FIPS 205 §10.2.1, SLH-DSA's `sign` operation is **byte-deterministic**:
//! given the same `(sk, msg)` pair, the signature is bit-identical, with no
//! RNG involvement. This makes SLH-DSA-128s ideal for cold governance keys —
//! a single canonical signature exists for any (key, message) pair, so a
//! `UpgradeCrypto` rotation announcement can be reproduced bit-exactly by
//! any auditor with the secret key shares.
//!
//! ## Sizes (Shake128s parameter set, FIPS 205 Level 1)
//!
//! - Verifying key: 32 bytes
//! - Signing key:   64 bytes
//! - Signature:     7,856 bytes
//!
//! The 7,856-byte signature is what makes SLH-DSA unsuitable as a hot-tx
//! algorithm — it would dominate block-size budgets — but appropriate for
//! cold governance: ~3 KB ÷ 7,856 ≈ governance txs are rare enough that the
//! size cost is negligible.

use crate::CryptoError;
use rand_core::{CryptoRng, RngCore};
use signature::{Signer, Verifier};
use slh_dsa::{Shake128s, Signature, SigningKey, VerifyingKey};

/// SLH-DSA-128s verifying-key size in bytes (= 32).
pub const SLHDSA128S_VK_LEN: usize = 32;
/// SLH-DSA-128s signing-key size in bytes (= 64).
pub const SLHDSA128S_SK_LEN: usize = 64;
/// SLH-DSA-128s signature size in bytes (= 7,856) per FIPS 205 §10.
pub const SLHDSA128S_SIG_LEN: usize = 7856;

/// Generate a fresh SLH-DSA-128s keypair. Returns `(signing_key, verifying_key)`.
///
/// `rng` is consumed for keygen seed only — signatures themselves are
/// deterministic. For test fixtures, supply a seeded `ChaCha20Rng`.
pub fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (Vec<u8>, Vec<u8>) {
    let sk: SigningKey<Shake128s> = SigningKey::new(rng);
    let vk: VerifyingKey<Shake128s> = sk.as_ref().clone();
    let sk_bytes = sk.to_bytes().to_vec();
    let vk_bytes = vk.to_bytes().to_vec();
    debug_assert_eq!(sk_bytes.len(), SLHDSA128S_SK_LEN);
    debug_assert_eq!(vk_bytes.len(), SLHDSA128S_VK_LEN);
    (sk_bytes, vk_bytes)
}

/// Sign `msg` with the given SLH-DSA-128s signing key. Output is `7,856` bytes
/// and **byte-deterministic** — two calls with the same `(sk, msg)` produce
/// the same bytes.
pub fn sign(sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sk_bytes.len() != SLHDSA128S_SK_LEN {
        return Err(CryptoError::Malformed);
    }
    let sk = SigningKey::<Shake128s>::try_from(sk_bytes).map_err(|_| CryptoError::Malformed)?;
    let sig: Signature<Shake128s> = sk.sign(msg);
    Ok(sig.to_bytes().to_vec())
}

/// Verify an SLH-DSA-128s signature.
pub fn verify(vk_bytes: &[u8], sig_bytes: &[u8], msg: &[u8]) -> Result<(), CryptoError> {
    if vk_bytes.len() != SLHDSA128S_VK_LEN {
        return Err(CryptoError::Malformed);
    }
    if sig_bytes.len() != SLHDSA128S_SIG_LEN {
        return Err(CryptoError::Malformed);
    }
    let vk = VerifyingKey::<Shake128s>::try_from(vk_bytes).map_err(|_| CryptoError::Malformed)?;
    let sig =
        Signature::<Shake128s>::try_from(sig_bytes).map_err(|_| CryptoError::Malformed)?;
    vk.verify(msg, &sig).map_err(|_| CryptoError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn slhdsa128s_keypair_sizes() {
        let mut rng = OsRng;
        let (sk, vk) = keypair(&mut rng);
        assert_eq!(sk.len(), SLHDSA128S_SK_LEN);
        assert_eq!(vk.len(), SLHDSA128S_VK_LEN);
    }

    #[test]
    fn slhdsa128s_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let (sk, vk) = keypair(&mut rng);
        let msg = b"governance: rotate sig_algo to 4 at height 1000000";
        let sig = sign(&sk, msg).expect("sign");
        assert_eq!(sig.len(), SLHDSA128S_SIG_LEN);
        verify(&vk, &sig, msg).expect("good sig verifies");
    }

    #[test]
    fn slhdsa128s_tampered_msg_fails() {
        let mut rng = OsRng;
        let (sk, vk) = keypair(&mut rng);
        let sig = sign(&sk, b"original").expect("sign");
        verify(&vk, &sig, b"tampered").expect_err("tampered msg fails");
    }

    #[test]
    fn slhdsa128s_two_sigs_for_same_msg_match() {
        // FIPS 205 §10.2.1: SLH-DSA sign is byte-deterministic.
        let mut rng = OsRng;
        let (sk, _vk) = keypair(&mut rng);
        let msg = b"sign me twice";
        let s1 = sign(&sk, msg).expect("first sign");
        let s2 = sign(&sk, msg).expect("second sign");
        assert_eq!(s1, s2, "SLH-DSA sigs must be byte-deterministic per spec");
    }

    #[test]
    fn slhdsa128s_rejects_wrong_lengths() {
        assert!(matches!(
            verify(&[0u8; 10], &[0u8; SLHDSA128S_SIG_LEN], b"x"),
            Err(CryptoError::Malformed)
        ));
        assert!(matches!(
            verify(&[0u8; SLHDSA128S_VK_LEN], &[0u8; 10], b"x"),
            Err(CryptoError::Malformed)
        ));
    }
}
