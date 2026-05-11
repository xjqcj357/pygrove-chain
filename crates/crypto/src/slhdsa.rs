//! SLH-DSA-128s (FIPS 205) dispatch (sig_algo = 2).
//!
//! Wired via [`fips205`](https://docs.rs/fips205) — integritychain's
//! pure-Rust port. **Live in all build profiles** including FIPS;
//! SLH-DSA-128s is the cornerstone of [`crate::FIPS_ALLOWLIST_SIG`].
//!
//! Pure-Rust, no_std-capable, no C compiler dependency, no
//! `signature` crate dep (which is what blocked the RustCrypto
//! `slh-dsa = 0.1` crate from coexisting with `ed25519-dalek`).
//!
//! ## Profile
//!
//! `slh_dsa_shake_128s` — FIPS 205 Level 1, SHAKE-based, "small"
//! parameter set. Trade-off: smaller signatures than `_128f`, slower
//! to sign. Cold-governance txs are rare enough that signing time
//! doesn't matter.
//!
//! ## Sizes
//!
//! - Verifying key: 32 bytes
//! - Signing key:   64 bytes
//! - Signature:     7,856 bytes
//!
//! ## Determinism
//!
//! `sign` here uses the **deterministic** (non-hedged) FIPS 205 mode:
//! given the same `(sk, msg)`, the signature is byte-identical.
//! Deterministic governance signatures let auditors reproduce
//! historical rotations bit-exactly without seeing the signers' RNG
//! state. The hedged mode is available via `fips205` directly if a
//! caller needs side-channel-hardened signing.

use crate::CryptoError;
use fips205::slh_dsa_shake_128s as slh;
use fips205::traits::{SerDes, Signer, Verifier};

/// SLH-DSA-128s verifying-key size in bytes (= 32).
pub const SLHDSA128S_VK_LEN: usize = slh::PK_LEN;
/// SLH-DSA-128s signing-key size in bytes (= 64).
pub const SLHDSA128S_SK_LEN: usize = slh::SK_LEN;
/// SLH-DSA-128s signature size in bytes (= 7,856) per FIPS 205 §10.
pub const SLHDSA128S_SIG_LEN: usize = slh::SIG_LEN;

const _: () = {
    assert!(SLHDSA128S_VK_LEN == 32);
    assert!(SLHDSA128S_SK_LEN == 64);
    assert!(SLHDSA128S_SIG_LEN == 7856);
};

/// Generate a fresh SLH-DSA-128s keypair. Returns `(signing_key, verifying_key)`.
///
/// `fips205` v0.4 builds keys from `OsRng` directly under the hood
/// (try_keygen_with_rng if you want to feed a custom RNG; we use the
/// default here for simplicity).
pub fn keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let (vk, sk) = slh::try_keygen().map_err(|_| CryptoError::Malformed)?;
    let sk_bytes = sk.into_bytes().to_vec();
    let vk_bytes = vk.into_bytes().to_vec();
    Ok((sk_bytes, vk_bytes))
}

/// Sign `msg` with the given SLH-DSA-128s signing key.
///
/// Uses the deterministic FIPS 205 mode (hedged = false). Output is
/// 7,856 bytes; identical for repeated `(sk, msg)`.
pub fn sign(sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sk_bytes.len() != SLHDSA128S_SK_LEN {
        return Err(CryptoError::Malformed);
    }
    let sk_arr: [u8; SLHDSA128S_SK_LEN] =
        sk_bytes.try_into().map_err(|_| CryptoError::Malformed)?;
    let sk = slh::PrivateKey::try_from_bytes(&sk_arr).map_err(|_| CryptoError::Malformed)?;
    // hedged = false → deterministic per FIPS 205 §10.2.1.
    // ctx = &[] → empty domain context (we domain-tag the message at
    // the caller).
    let sig = sk
        .try_sign(msg, &[], false)
        .map_err(|_| CryptoError::Malformed)?;
    Ok(sig.to_vec())
}

/// Verify an SLH-DSA-128s signature.
pub fn verify(vk_bytes: &[u8], sig_bytes: &[u8], msg: &[u8]) -> Result<(), CryptoError> {
    if vk_bytes.len() != SLHDSA128S_VK_LEN {
        return Err(CryptoError::Malformed);
    }
    if sig_bytes.len() != SLHDSA128S_SIG_LEN {
        return Err(CryptoError::Malformed);
    }
    let vk_arr: [u8; SLHDSA128S_VK_LEN] =
        vk_bytes.try_into().map_err(|_| CryptoError::Malformed)?;
    let vk = slh::PublicKey::try_from_bytes(&vk_arr).map_err(|_| CryptoError::Malformed)?;
    let sig_arr: [u8; SLHDSA128S_SIG_LEN] =
        sig_bytes.try_into().map_err(|_| CryptoError::Malformed)?;
    if vk.verify(msg, &sig_arr, &[]) {
        Ok(())
    } else {
        Err(CryptoError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slhdsa128s_keypair_sizes() {
        let (sk, vk) = keypair().expect("keygen");
        assert_eq!(sk.len(), SLHDSA128S_SK_LEN);
        assert_eq!(vk.len(), SLHDSA128S_VK_LEN);
    }

    #[test]
    fn slhdsa128s_sign_verify_roundtrip() {
        let (sk, vk) = keypair().expect("keygen");
        let msg = b"governance: rotate sig_algo to 4 at height 1000000";
        let sig = sign(&sk, msg).expect("sign");
        assert_eq!(sig.len(), SLHDSA128S_SIG_LEN);
        verify(&vk, &sig, msg).expect("good sig verifies");
    }

    #[test]
    fn slhdsa128s_tampered_msg_fails() {
        let (sk, vk) = keypair().expect("keygen");
        let sig = sign(&sk, b"original").expect("sign");
        verify(&vk, &sig, b"tampered").expect_err("tampered msg fails");
    }

    #[test]
    fn slhdsa128s_sign_is_deterministic() {
        // FIPS 205 §10.2.1: SLH-DSA's deterministic mode produces
        // byte-identical sigs for the same (sk, msg).
        let (sk, _) = keypair().expect("keygen");
        let msg = b"sign me twice";
        let s1 = sign(&sk, msg).expect("first sign");
        let s2 = sign(&sk, msg).expect("second sign");
        assert_eq!(s1, s2, "SLH-DSA deterministic mode must be byte-stable");
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
