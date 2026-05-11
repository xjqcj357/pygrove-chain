//! Post-quantum signature dispatch.
//!
//! The public surface is `sign(algo, sk, msg)` and `verify(algo, pk, sig, msg)`. All
//! callers go through these; no algorithm-specific import should leak outside this
//! crate. That discipline is what lets `UpgradeCrypto` swap primitives without
//! touching consensus code.
//!
//! - `algo = 1` (Falcon-512 / FN-DSA) — Phase B hot signature. Wired when
//!   `--features falcon` is active (default-on). FIPS builds drop it
//!   (Falcon-512 is FIPS 206 draft, not yet allowlisted). See [`falcon`].
//! - `algo = 2` (SLH-DSA-128s / FIPS 205) — cold governance signature.
//!   **Live in all build profiles**, including FIPS where it's the
//!   cornerstone of `FIPS_ALLOWLIST_SIG`. Wired via the pure-Rust
//!   `fips205` crate (no `signature`-crate diamond, no C compiler).
//!   Deterministic mode per FIPS 205 §10.2.1. See [`slhdsa`].
//! - `algo = 3` (Ed25519) — Phase A bringup. Wired when `--features ed25519`
//!   is active (default-on). Dropped from FIPS builds.
//! - `algo = 4` (ML-DSA-65 / FIPS 204) — FIPS-profile path, not yet wired.
//! - `algo = 5` (BLS12-381, min-pk) — finality committee. Wired when
//!   `--features bls` is active (default-on). Used for aggregated
//!   finality certs; N validator sigs collapse to a single 96-byte
//!   sig + 48-byte aggregated pubkey. See [`bls`].
//!
//! ## Build profiles
//!
//! - **Default** (`cargo build`): `ed25519` + `falcon` features active.
//!   Matches the testnet-3 binary surface. SLH-DSA stays off because of
//!   the upstream signature-version diamond.
//! - **FIPS** (`cargo build --features fips`): drops Ed25519 + Falcon
//!   from the dependency graph; pulls SLH-DSA-128s. Refuses sig_algo=1
//!   and sig_algo=3 with `NotAllowedInFipsBuild`. `allowed_sig()` /
//!   `allowed_hash()` consult `FIPS_ALLOWLIST_*`.

use thiserror::Error;

#[cfg(feature = "ed25519")]
use ed25519_dalek::{
    Signature as EdSignature, Signer, SigningKey as EdSigningKey, Verifier,
    VerifyingKey as EdVerifyingKey,
};
#[cfg(any(feature = "ed25519", feature = "falcon"))]
use rand_core::{CryptoRng, RngCore};

// Ed25519 size constants — RFC 8032 fixes these forever, so we keep them as
// local consts. `ED_SIG_LEN` is needed unconditionally because `sizes()`
// reports it for algo=3 in every build profile (it's spec metadata, not a
// callable surface). `ED_SK_LEN` is only consumed by `ed25519_sign` and so
// is gated on the `ed25519` feature.
const ED_SIG_LEN: usize = 64; // ed25519_dalek::SIGNATURE_LENGTH
#[cfg(feature = "ed25519")]
const ED_SK_LEN: usize = 32; // ed25519_dalek::SECRET_KEY_LENGTH

#[cfg(feature = "falcon")]
pub mod falcon;
#[cfg(feature = "slhdsa")]
pub mod slhdsa;
#[cfg(feature = "bls")]
pub mod bls;

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
    #[error("algorithm {0} is not allowed in a FIPS-profile build")]
    NotAllowedInFipsBuild(u8),
}

/// Sign a message under the given algorithm tag.
///
/// Note: `algo = 1` (Falcon-512) is randomized by spec. The signing path
/// internally uses `OsRng`; the same `(sk, msg)` produces a different
/// signature each call. That's a Falcon design property, not a bug.
#[allow(unused_variables)]
pub fn sign(algo: u8, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match algo {
        1 => {
            #[cfg(feature = "falcon")]
            {
                use rand_core::OsRng;
                falcon::sign(sk, msg, &mut OsRng)
            }
            #[cfg(all(not(feature = "falcon"), feature = "fips"))]
            {
                Err(CryptoError::NotAllowedInFipsBuild(1))
            }
            #[cfg(all(not(feature = "falcon"), not(feature = "fips")))]
            {
                Err(CryptoError::NotWired)
            }
        }
        2 => {
            #[cfg(feature = "slhdsa")]
            {
                slhdsa::sign(sk, msg)
            }
            #[cfg(not(feature = "slhdsa"))]
            {
                Err(CryptoError::NotWired)
            }
        }
        4 => Err(CryptoError::NotWired), // ML-DSA-65 — deferred
        3 => {
            #[cfg(feature = "ed25519")]
            {
                ed25519_sign(sk, msg)
            }
            #[cfg(all(not(feature = "ed25519"), feature = "fips"))]
            {
                Err(CryptoError::NotAllowedInFipsBuild(3))
            }
            #[cfg(all(not(feature = "ed25519"), not(feature = "fips")))]
            {
                Err(CryptoError::NotWired)
            }
        }
        5 => {
            #[cfg(feature = "bls")]
            {
                bls::sign(sk, msg)
            }
            #[cfg(not(feature = "bls"))]
            {
                Err(CryptoError::NotWired)
            }
        }
        _ => Err(CryptoError::UnknownAlgo(algo)),
    }
}

/// Verify a signature under the given algorithm tag.
#[allow(unused_variables)]
pub fn verify(algo: u8, pk: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), CryptoError> {
    match algo {
        1 => {
            #[cfg(feature = "falcon")]
            {
                falcon::verify(pk, sig, msg)
            }
            #[cfg(all(not(feature = "falcon"), feature = "fips"))]
            {
                Err(CryptoError::NotAllowedInFipsBuild(1))
            }
            #[cfg(all(not(feature = "falcon"), not(feature = "fips")))]
            {
                Err(CryptoError::NotWired)
            }
        }
        2 => {
            #[cfg(feature = "slhdsa")]
            {
                slhdsa::verify(pk, sig, msg)
            }
            #[cfg(not(feature = "slhdsa"))]
            {
                Err(CryptoError::NotWired)
            }
        }
        4 => Err(CryptoError::NotWired),
        3 => {
            #[cfg(feature = "ed25519")]
            {
                ed25519_verify(pk, sig, msg)
            }
            #[cfg(all(not(feature = "ed25519"), feature = "fips"))]
            {
                Err(CryptoError::NotAllowedInFipsBuild(3))
            }
            #[cfg(all(not(feature = "ed25519"), not(feature = "fips")))]
            {
                Err(CryptoError::NotWired)
            }
        }
        5 => {
            #[cfg(feature = "bls")]
            {
                bls::verify(pk, sig, msg)
            }
            #[cfg(not(feature = "bls"))]
            {
                Err(CryptoError::NotWired)
            }
        }
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
        5 => Some((48, 96)),         // BLS12-381 min-pk
        _ => None,
    }
}

/// Algorithms approved for FIPS-profile builds (i.e., in `cargo build --features fips`).
/// Used by `UpgradeCrypto` validation: a governance tx that tries to rotate
/// to a non-allowlisted algo is rejected at apply time on a FIPS-profile node.
pub const FIPS_ALLOWLIST_SIG: &[u8] = &[2, 4]; // SLH-DSA-128s, ML-DSA-65
pub const FIPS_ALLOWLIST_HASH: &[u8] = &[3]; // SHA3-512

/// Algorithms approved on the default (testnet) build. Wider — includes
/// the Phase A bringup primitives + BLS for finality aggregation.
pub const DEFAULT_ALLOWLIST_SIG: &[u8] = &[1, 2, 3, 4, 5];
pub const DEFAULT_ALLOWLIST_HASH: &[u8] = &[1, 2, 3];

/// The signature-algorithm allowlist active in this build.
///
/// FIPS builds get the FIPS allowlist; default builds get the wider allowlist.
/// Consensus code (specifically `UpgradeCrypto` apply in `crates/state`) calls
/// `allowed_sig()` to gate governance rotations.
#[inline]
pub fn active_allowlist_sig() -> &'static [u8] {
    #[cfg(feature = "fips")]
    {
        FIPS_ALLOWLIST_SIG
    }
    #[cfg(not(feature = "fips"))]
    {
        DEFAULT_ALLOWLIST_SIG
    }
}

/// The hash-algorithm allowlist active in this build.
#[inline]
pub fn active_allowlist_hash() -> &'static [u8] {
    #[cfg(feature = "fips")]
    {
        FIPS_ALLOWLIST_HASH
    }
    #[cfg(not(feature = "fips"))]
    {
        DEFAULT_ALLOWLIST_HASH
    }
}

/// Whether this build will accept the given signature algorithm.
#[inline]
pub fn allowed_sig(algo: u8) -> bool {
    active_allowlist_sig().contains(&algo)
}

/// Whether this build will accept the given hash algorithm.
#[inline]
pub fn allowed_hash(algo: u8) -> bool {
    active_allowlist_hash().contains(&algo)
}

/// Returns `true` if this binary was compiled with `--features fips`.
#[inline]
pub const fn is_fips_build() -> bool {
    cfg!(feature = "fips")
}

/// Generate a fresh Ed25519 keypair. Returns `(secret_key_32, public_key_32)`.
///
/// Available only when `--features ed25519` is active (default-on).
#[cfg(feature = "ed25519")]
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
#[cfg(feature = "ed25519")]
pub fn ed25519_pubkey_from_secret(sk: &[u8; 32]) -> [u8; 32] {
    let signing = EdSigningKey::from_bytes(sk);
    let mut out = [0u8; 32];
    out.copy_from_slice(signing.verifying_key().as_bytes());
    out
}

#[cfg(feature = "ed25519")]
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

#[cfg(feature = "ed25519")]
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

    #[cfg(feature = "ed25519")]
    mod ed25519_tests {
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
        fn pubkey_from_secret_matches_keypair() {
            let mut rng = OsRng;
            let (sk, pk) = ed25519_keypair(&mut rng);
            let derived = ed25519_pubkey_from_secret(&sk);
            assert_eq!(pk, derived);
        }
    }

    #[cfg(feature = "falcon")]
    #[test]
    fn falcon_dispatch_roundtrips() {
        use rand_core::OsRng;
        let mut rng = OsRng;
        let (sk, vk) = falcon::keypair(&mut rng);
        let msg = b"falcon via the dispatch surface";
        let sig = sign(1, &sk, msg).expect("falcon sign via dispatch");
        assert_eq!(sig.len(), falcon::FALCON512_SIG_LEN);
        verify(1, &vk, &sig, msg).expect("falcon verify via dispatch");
        verify(1, &vk, &sig, b"different msg").expect_err("tampered msg fails");
    }

    /// SLH-DSA-128s is wired in non-FIPS builds (default-on slhdsa feature).
    /// In FIPS-only builds it's also active (`fips` feature enables `slhdsa`).
    #[cfg(feature = "slhdsa")]
    #[test]
    fn slhdsa_dispatch_roundtrips() {
        let (sk, vk) = slhdsa::keypair().expect("keygen");
        let msg = b"slh-dsa via the dispatch surface";
        let sig = sign(2, &sk, msg).expect("slh-dsa sign via dispatch");
        assert_eq!(sig.len(), slhdsa::SLHDSA128S_SIG_LEN);
        verify(2, &vk, &sig, msg).expect("slh-dsa verify via dispatch");
        verify(2, &vk, &sig, b"tampered").expect_err("tampered fails");
    }

    /// SLH-DSA deterministic sigs verified through the dispatch layer.
    #[cfg(feature = "slhdsa")]
    #[test]
    fn slhdsa_dispatch_determinism() {
        let (sk, _) = slhdsa::keypair().expect("keygen");
        let msg = b"governance: rotate at height N";
        let s1 = sign(2, &sk, msg).expect("first sign");
        let s2 = sign(2, &sk, msg).expect("second sign");
        assert_eq!(s1, s2);
    }

    #[cfg(all(feature = "fips", not(feature = "ed25519")))]
    #[test]
    fn ed25519_refused_in_fips_build() {
        assert!(matches!(
            sign(3, &[0u8; 32], b"x"),
            Err(CryptoError::NotAllowedInFipsBuild(3))
        ));
        assert!(matches!(
            verify(3, &[0u8; 32], &[0u8; 64], b"x"),
            Err(CryptoError::NotAllowedInFipsBuild(3))
        ));
    }

    #[cfg(all(feature = "fips", not(feature = "falcon")))]
    #[test]
    fn falcon_refused_in_fips_build() {
        assert!(matches!(
            sign(1, &[], b""),
            Err(CryptoError::NotAllowedInFipsBuild(1))
        ));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn fips_allowlist_active() {
        assert!(is_fips_build());
        assert_eq!(active_allowlist_sig(), FIPS_ALLOWLIST_SIG);
        assert_eq!(active_allowlist_hash(), FIPS_ALLOWLIST_HASH);
        assert!(!allowed_sig(3)); // Ed25519 not in FIPS
        assert!(!allowed_sig(1)); // Falcon-512 not in FIPS
        assert!(allowed_sig(2)); // SLH-DSA-128s
        assert!(allowed_sig(4)); // ML-DSA-65
        assert!(allowed_hash(3)); // SHA3-512
        assert!(!allowed_hash(1)); // Blake3-XOF-512 not in FIPS
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn default_allowlist_active() {
        assert!(!is_fips_build());
        assert_eq!(active_allowlist_sig(), DEFAULT_ALLOWLIST_SIG);
        assert_eq!(active_allowlist_hash(), DEFAULT_ALLOWLIST_HASH);
    }

    #[test]
    fn mldsa_still_not_wired() {
        assert!(matches!(sign(4, &[], b""), Err(CryptoError::NotWired)));
    }

    #[cfg(feature = "bls")]
    #[test]
    fn bls_dispatch_roundtrips() {
        use rand_core::OsRng;
        let mut rng = OsRng;
        let (sk, vk) = bls::keypair(&mut rng);
        let msg = b"bls via the dispatch surface";
        let sig = sign(5, &sk, msg).expect("bls sign via dispatch");
        assert_eq!(sig.len(), bls::BLS_SIG_LEN);
        verify(5, &vk, &sig, msg).expect("bls verify via dispatch");
        verify(5, &vk, &sig, b"tampered").expect_err("tampered msg fails");
    }

    #[test]
    fn allowlists_are_sorted_and_unique() {
        for list in [
            FIPS_ALLOWLIST_SIG,
            FIPS_ALLOWLIST_HASH,
            DEFAULT_ALLOWLIST_SIG,
            DEFAULT_ALLOWLIST_HASH,
        ] {
            for w in list.windows(2) {
                assert!(w[0] < w[1], "allowlist {list:?} must be sorted + unique");
            }
        }
    }
}
