//! Post-quantum signature dispatch.
//!
//! The public surface is `sign(algo, sk, msg)` and `verify(algo, pk, sig, msg)`. All
//! callers go through these; no algorithm-specific import should leak outside this
//! crate. That discipline is what lets `UpgradeCrypto` swap primitives without
//! touching consensus code.
//!
//! - `algo = 1` (Falcon-512 / FN-DSA, integer sampler) — Phase B, not yet wired.
//! - `algo = 2` (SLH-DSA-128s) — cold governance, not yet wired.
//! - `algo = 3` (Ed25519)      — Phase A bringup. Live now.

use ed25519_dalek::{
    Signature as EdSignature, Signer, SigningKey as EdSigningKey, Verifier,
    VerifyingKey as EdVerifyingKey, SECRET_KEY_LENGTH as ED_SK_LEN,
    SIGNATURE_LENGTH as ED_SIG_LEN,
};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("unknown or disabled signature algorithm: {0}")]
    UnknownAlgo(u8),
    #[error("signature verification failed")]
    BadSignature,
    #[error("malformed key or signature bytes")]
    Malformed,
    #[error("algorithm not yet wired in this build")]
    NotWired,
}

/// Sign a message under the given algorithm tag.
pub fn sign(algo: u8, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match algo {
        1 | 2 | 4 => Err(CryptoError::NotWired), // Falcon-512, SLH-DSA-128s, ML-DSA-65
        3 => ed25519_sign(sk, msg),
        _ => Err(CryptoError::UnknownAlgo(algo)),
    }
}

/// Verify a signature under the given algorithm tag.
pub fn verify(algo: u8, pk: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), CryptoError> {
    match algo {
        1 | 2 | 4 => Err(CryptoError::NotWired),
        3 => ed25519_verify(pk, sig, msg),
        _ => Err(CryptoError::UnknownAlgo(algo)),
    }
}

/// Declared (pubkey, signature) sizes in bytes for each algo. Used for block-size
/// accounting and sanity checks before deserializing witness bytes.
pub fn sizes(algo: u8) -> Option<(usize, usize)> {
    match algo {
        1 => Some((897, 666)),       // Falcon-512 / FN-DSA
        2 => Some((32, 7856)),       // SLH-DSA-128s
        3 => Some((32, ED_SIG_LEN)), // Ed25519: 32-byte pk, 64-byte sig
        4 => Some((1952, 3309)),     // ML-DSA-65 (FIPS 204) — sizes per spec
        _ => None,
    }
}

/// Algorithms approved for FIPS-profile builds (i.e., in `cargo build --features fips`).
/// Used by `UpgradeCrypto` validation: a governance tx that tries to rotate
/// to a non-allowlisted algo is rejected at apply time on a FIPS-profile node.
pub const FIPS_ALLOWLIST_SIG: &[u8] = &[2, 4]; // SLH-DSA-128s, ML-DSA-65
pub const FIPS_ALLOWLIST_HASH: &[u8] = &[3];   // SHA3-512

/// Algorithms approved on the default (testnet) build. Wider — includes
/// the Phase A bringup primitives.
pub const DEFAULT_ALLOWLIST_SIG: &[u8] = &[1, 2, 3, 4];
pub const DEFAULT_ALLOWLIST_HASH: &[u8] = &[1, 2, 3];

/// Generate a fresh Ed25519 keypair. Returns `(secret_key_32, public_key_32)`.
pub fn ed25519_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ([u8; 32], [u8; 32]) {
    let sk = EdSigningKey::generate(rng);
    let pk = sk.verifying_key();
    let mut sk_bytes = [0u8; ED_SK_LEN];
    sk_bytes.copy_from_slice(sk.as_bytes());
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(pk.as_bytes());
    (sk_bytes, pk_bytes)
}

/// Derive the Ed25519 public key from a 32-byte secret seed without touching an RNG.
pub fn ed25519_pubkey_from_secret(sk: &[u8; 32]) -> [u8; 32] {
    let signing = EdSigningKey::from_bytes(sk);
    let mut out = [0u8; 32];
    out.copy_from_slice(signing.verifying_key().as_bytes());
    out
}

fn ed25519_sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sk.len() != ED_SK_LEN {
        return Err(CryptoError::Malformed);
    }
    let mut sk_arr = [0u8; ED_SK_LEN];
    sk_arr.copy_from_slice(sk);
    let signing = EdSigningKey::from_bytes(&sk_arr);
    let sig = signing.sign(msg);
    Ok(sig.to_bytes().to_vec())
}

fn ed25519_verify(pk: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), CryptoError> {
    if pk.len() != 32 {
        return Err(CryptoError::Malformed);
    }
    if sig.len() != ED_SIG_LEN {
        return Err(CryptoError::Malformed);
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(pk);
    let verifying = EdVerifyingKey::from_bytes(&pk_arr).map_err(|_| CryptoError::Malformed)?;
    let mut sig_arr = [0u8; ED_SIG_LEN];
    sig_arr.copy_from_slice(sig);
    let signature = EdSignature::from_bytes(&sig_arr);
    verifying
        .verify(msg, &signature)
        .map_err(|_| CryptoError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn ed25519_roundtrip() {
        let mut rng = OsRng;
        let (sk, pk) = ed25519_keypair(&mut rng);
        let msg = b"a self-reflective stability-seeking proof-of-work blockchain";
        let sig = sign(3, &sk, msg).unwrap();
        assert_eq!(sig.len(), ED_SIG_LEN);
        verify(3, &pk, &sig, msg).expect("good sig verifies");
        verify(3, &pk, &sig, b"different message").expect_err("tampered msg fails");
    }

    #[test]
    fn rejects_wrong_pk_len() {
        assert!(matches!(
            verify(3, &[0u8; 31], &[0u8; ED_SIG_LEN], b"x"),
            Err(CryptoError::Malformed)
        ));
    }

    #[test]
    fn falcon_still_not_wired() {
        assert!(matches!(sign(1, &[], b""), Err(CryptoError::NotWired)));
    }

    #[test]
    fn pubkey_from_secret_matches_keypair() {
        let mut rng = OsRng;
        let (sk, pk) = ed25519_keypair(&mut rng);
        let derived = ed25519_pubkey_from_secret(&sk);
        assert_eq!(pk, derived);
    }
}
