//! Falcon-512 / FN-DSA dispatch (sig_algo = 1).
//!
//! Wired via `fn-dsa = "0.1"` (Thomas Pornin's pure-Rust port of the FALCON
//! reference + integer-arithmetic sampler). Available only in non-FIPS builds:
//! Falcon-512 is FIPS 206 (draft), not yet in [`crate::FIPS_ALLOWLIST_SIG`].
//!
//! ## Determinism
//!
//! Falcon is a *randomized* signature scheme by spec — `sign()` consumes RNG
//! and the same `(sk, msg)` pair produces a different signature every call.
//! That's by design: it's how Falcon sidesteps the side-channel issues of
//! deterministic lattice-Schnorr signing. Verifies are stable across
//! architectures.
//!
//! `fn-dsa` 0.1 uses the native `f64` sampler on x86_64 and aarch64; the
//! integer-emulator sampler is only forced on 32-bit targets. So even with
//! a fixed RNG seed, byte-identical output across architectures is not
//! guaranteed by this crate. PyGrove doesn't rely on that property — every
//! signed payload commits to the witness *hash*, not to the witness bytes,
//! so signers on different architectures produce different but equally
//! valid sigs.
//!
//! ## Sizes (logn = 9, Falcon-512)
//!
//! - Verifying key: 897 bytes
//! - Signing key:   1281 bytes
//! - Signature:     666 bytes

use crate::CryptoError;
use fn_dsa::{
    sign_key_size, signature_size, vrfy_key_size, KeyPairGenerator,
    KeyPairGeneratorStandard, SigningKey, SigningKeyStandard, VerifyingKey,
    VerifyingKeyStandard, DOMAIN_NONE, FN_DSA_LOGN_512, HASH_ID_RAW,
};
use rand_core::{CryptoRng, RngCore};

/// Falcon-512 verifying-key size in bytes (= 897).
pub const FALCON512_VK_LEN: usize = 897;
/// Falcon-512 signing-key size in bytes (= 1281).
pub const FALCON512_SK_LEN: usize = 1281;
/// Falcon-512 signature size in bytes (= 666).
pub const FALCON512_SIG_LEN: usize = 666;

const _: () = {
    assert!(vrfy_key_size(FN_DSA_LOGN_512) == FALCON512_VK_LEN);
    assert!(sign_key_size(FN_DSA_LOGN_512) == FALCON512_SK_LEN);
    assert!(signature_size(FN_DSA_LOGN_512) == FALCON512_SIG_LEN);
};

/// Generate a fresh Falcon-512 keypair. Returns `(signing_key, verifying_key)`.
///
/// `rng` is consumed; supply an `OsRng` (or any `CryptoRngCore`) for security.
/// For test fixtures, supply a seeded `ChaCha20Rng` — note that even with
/// a fixed seed, sig output is not guaranteed byte-identical across archs.
pub fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (Vec<u8>, Vec<u8>) {
    let mut kg = KeyPairGeneratorStandard::default();
    let mut sk = vec![0u8; FALCON512_SK_LEN];
    let mut vk = vec![0u8; FALCON512_VK_LEN];
    kg.keygen(FN_DSA_LOGN_512, rng, &mut sk, &mut vk);
    (sk, vk)
}

/// Sign `msg` with the given Falcon-512 signing key. Output is `666` bytes.
///
/// `rng` is consumed; signatures are randomized by spec, so two calls with
/// the same `(sk, msg)` produce different bytes.
pub fn sign<R: CryptoRng + RngCore>(
    sk_bytes: &[u8],
    msg: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, CryptoError> {
    if sk_bytes.len() != FALCON512_SK_LEN {
        return Err(CryptoError::Malformed);
    }
    let mut sk = SigningKeyStandard::decode(sk_bytes).ok_or(CryptoError::Malformed)?;
    let mut sig = vec![0u8; FALCON512_SIG_LEN];
    sk.sign(rng, &DOMAIN_NONE, &HASH_ID_RAW, msg, &mut sig);
    Ok(sig)
}

/// Verify a Falcon-512 signature. Stable across all architectures.
pub fn verify(vk_bytes: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), CryptoError> {
    if vk_bytes.len() != FALCON512_VK_LEN {
        return Err(CryptoError::Malformed);
    }
    if sig.len() != FALCON512_SIG_LEN {
        return Err(CryptoError::Malformed);
    }
    let vk = VerifyingKeyStandard::decode(vk_bytes).ok_or(CryptoError::Malformed)?;
    if vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, msg) {
        Ok(())
    } else {
        Err(CryptoError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn falcon512_keypair_sizes() {
        let mut rng = OsRng;
        let (sk, vk) = keypair(&mut rng);
        assert_eq!(sk.len(), FALCON512_SK_LEN);
        assert_eq!(vk.len(), FALCON512_VK_LEN);
    }

    #[test]
    fn falcon512_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let (sk, vk) = keypair(&mut rng);
        let msg = b"a self-reflective stability-seeking proof-of-work blockchain";
        let sig = sign(&sk, msg, &mut rng).expect("sign");
        assert_eq!(sig.len(), FALCON512_SIG_LEN);
        verify(&vk, &sig, msg).expect("good sig verifies");
    }

    #[test]
    fn falcon512_tampered_msg_fails() {
        let mut rng = OsRng;
        let (sk, vk) = keypair(&mut rng);
        let sig = sign(&sk, b"original", &mut rng).expect("sign");
        verify(&vk, &sig, b"tampered").expect_err("tampered msg fails");
    }

    #[test]
    fn falcon512_wrong_pubkey_fails() {
        let mut rng = OsRng;
        let (sk_a, _) = keypair(&mut rng);
        let (_, vk_b) = keypair(&mut rng);
        let msg = b"signed by A, verified against B's pubkey";
        let sig = sign(&sk_a, msg, &mut rng).expect("sign");
        verify(&vk_b, &sig, msg).expect_err("wrong pubkey fails");
    }

    #[test]
    fn falcon512_two_sigs_for_same_msg_differ() {
        // Falcon is randomized by spec.
        let mut rng = OsRng;
        let (sk, _vk) = keypair(&mut rng);
        let msg = b"sign me twice";
        let s1 = sign(&sk, msg, &mut rng).expect("first sign");
        let s2 = sign(&sk, msg, &mut rng).expect("second sign");
        assert_ne!(s1, s2, "Falcon sigs are randomized");
    }

    #[test]
    fn falcon512_rejects_wrong_lengths() {
        assert!(matches!(
            verify(&[0u8; 10], &[0u8; FALCON512_SIG_LEN], b"x"),
            Err(CryptoError::Malformed)
        ));
        assert!(matches!(
            verify(&[0u8; FALCON512_VK_LEN], &[0u8; 10], b"x"),
            Err(CryptoError::Malformed)
        ));
    }
}
