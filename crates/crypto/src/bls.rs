//! BLS12-381 / BLS signatures (sig_algo = 5).
//!
//! Wired via `blst = "0.3"` — the canonical fast-path implementation.
//! Used by the BFT finality committee: N validator signatures over the
//! same message **aggregate** into a single 96-byte signature, plus an
//! aggregated public key, that verifies in a single pairing check.
//! This is what lets a 5-of-5 (or 67-of-100) finality cert stay
//! constant-sized on the wire.
//!
//! ## Profile
//!
//! min-pubkey-size: pubkey lives in G1 (48 bytes), signature in G2
//! (96 bytes). Opposite from typical Ethereum (min-sig) — Ethereum
//! aggregates *signatures*, we aggregate *both pubkeys and signatures*
//! per round, and the finality cert is the (committee_aggregated_pk,
//! aggregated_sig) pair plus an N-bit signer-bitmap. Verification cost
//! is dominated by the pairing check, not by which group is which, so
//! the choice is arbitrary; min-pubkey matches the BLS-Eth signing
//! tag convention while keeping our sigs at 96 bytes.
//!
//! ## Domain separation
//!
//! `DST = b"PG_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"` — a custom
//! PyGrove suite tag so a sig over PyGrove's signing-hash can't be
//! replayed against any other BLS-using chain.
//!
//! ## Sizes
//!
//! - Verifying key (G1 affine compressed): 48 bytes
//! - Signing key                         : 32 bytes
//! - Signature (G2 affine compressed)    : 96 bytes
//! - Aggregated signature                : 96 bytes (same shape)
//! - Aggregated pubkey                   : 48 bytes

use crate::CryptoError;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use rand_core::{CryptoRng, RngCore};

/// BLS12-381 (min-pk) verifying-key size in bytes.
pub const BLS_VK_LEN: usize = 48;
/// BLS12-381 (min-pk) signing-key size in bytes.
pub const BLS_SK_LEN: usize = 32;
/// BLS12-381 (min-pk) signature size in bytes.
pub const BLS_SIG_LEN: usize = 96;

/// PyGrove's BLS domain-separation tag. Per RFC 9380 §8.10, a unique
/// per-application tag so a sig over a PyGrove payload cannot be
/// replayed against any other BLS-using protocol.
pub const DST: &[u8] = b"PG_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// Generate a fresh BLS keypair. Returns `(signing_key_32, verifying_key_48)`.
pub fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ([u8; BLS_SK_LEN], [u8; BLS_VK_LEN]) {
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).expect("blst key_gen");
    let pk = sk.sk_to_pk();
    let mut sk_bytes = [0u8; BLS_SK_LEN];
    sk_bytes.copy_from_slice(&sk.to_bytes());
    let mut pk_bytes = [0u8; BLS_VK_LEN];
    pk_bytes.copy_from_slice(&pk.to_bytes());
    (sk_bytes, pk_bytes)
}

/// Sign `msg` with the given BLS signing key. Deterministic per spec:
/// `(sk, msg)` → unique signature. Output is 96 bytes.
pub fn sign(sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sk_bytes.len() != BLS_SK_LEN {
        return Err(CryptoError::Malformed);
    }
    let sk = SecretKey::from_bytes(sk_bytes).map_err(|_| CryptoError::Malformed)?;
    let sig = sk.sign(msg, DST, &[]);
    Ok(sig.to_bytes().to_vec())
}

/// Verify a BLS signature.
pub fn verify(vk_bytes: &[u8], sig_bytes: &[u8], msg: &[u8]) -> Result<(), CryptoError> {
    if vk_bytes.len() != BLS_VK_LEN {
        return Err(CryptoError::Malformed);
    }
    if sig_bytes.len() != BLS_SIG_LEN {
        return Err(CryptoError::Malformed);
    }
    let pk = PublicKey::from_bytes(vk_bytes).map_err(|_| CryptoError::Malformed)?;
    let sig = Signature::from_bytes(sig_bytes).map_err(|_| CryptoError::Malformed)?;
    match sig.verify(true, msg, DST, &[], &pk, true) {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(CryptoError::BadSignature),
    }
}

/// Aggregate N signatures into a single 96-byte sig. All N signatures
/// must be over the **same message** for the aggregated cert to verify
/// against the aggregated pubkey (verify_aggregated). For
/// signature-per-message aggregation, use `verify_aggregated_distinct`
/// (not provided here — finality votes are over a single header hash).
///
/// Returns `Malformed` on length mismatch or invalid sig bytes.
pub fn aggregate_signatures(sigs: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    if sigs.is_empty() {
        return Err(CryptoError::Malformed);
    }
    let parsed: Vec<Signature> = sigs
        .iter()
        .map(|b| {
            if b.len() != BLS_SIG_LEN {
                Err(CryptoError::Malformed)
            } else {
                Signature::from_bytes(b).map_err(|_| CryptoError::Malformed)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let refs: Vec<&Signature> = parsed.iter().collect();
    let agg = AggregateSignature::aggregate(&refs, true)
        .map_err(|_| CryptoError::BadSignature)?;
    Ok(agg.to_signature().to_bytes().to_vec())
}

/// Aggregate N pubkeys into a single 48-byte aggregated pubkey. Used by
/// the finality verifier to fold an N-bit signer-bitmap into a single
/// key against which the aggregated signature is checked.
pub fn aggregate_pubkeys(pks: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    if pks.is_empty() {
        return Err(CryptoError::Malformed);
    }
    let parsed: Vec<PublicKey> = pks
        .iter()
        .map(|b| {
            if b.len() != BLS_VK_LEN {
                Err(CryptoError::Malformed)
            } else {
                PublicKey::from_bytes(b).map_err(|_| CryptoError::Malformed)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let refs: Vec<&PublicKey> = parsed.iter().collect();
    let agg = AggregatePublicKey::aggregate(&refs, true)
        .map_err(|_| CryptoError::BadSignature)?;
    Ok(agg.to_public_key().to_bytes().to_vec())
}

/// Verify a single aggregated signature against a single aggregated
/// pubkey and a single message. The standard "all signers signed the
/// same msg" flow.
pub fn verify_aggregated(
    agg_vk: &[u8],
    agg_sig: &[u8],
    msg: &[u8],
) -> Result<(), CryptoError> {
    verify(agg_vk, agg_sig, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn bls_keypair_sizes() {
        let mut rng = OsRng;
        let (sk, vk) = keypair(&mut rng);
        assert_eq!(sk.len(), BLS_SK_LEN);
        assert_eq!(vk.len(), BLS_VK_LEN);
    }

    #[test]
    fn bls_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let (sk, vk) = keypair(&mut rng);
        let msg = b"a self-reflective stability-seeking proof-of-work blockchain";
        let sig = sign(&sk, msg).expect("sign");
        assert_eq!(sig.len(), BLS_SIG_LEN);
        verify(&vk, &sig, msg).expect("good sig verifies");
        verify(&vk, &sig, b"tampered").expect_err("tampered fails");
    }

    /// BLS signatures are deterministic by spec.
    #[test]
    fn bls_sign_is_deterministic() {
        let mut rng = OsRng;
        let (sk, _) = keypair(&mut rng);
        let s1 = sign(&sk, b"x").unwrap();
        let s2 = sign(&sk, b"x").unwrap();
        assert_eq!(s1, s2, "BLS sigs must be deterministic per spec");
    }

    /// 5-of-5 aggregation: every validator signs the same header hash;
    /// aggregate the sigs + pks; one pairing verifies the lot.
    #[test]
    fn bls_5_of_5_aggregation_roundtrip() {
        let mut rng = OsRng;
        let msg = b"finalize height=6 hash=DEADBEEF";

        let pairs: Vec<([u8; 32], [u8; 48])> = (0..5).map(|_| keypair(&mut rng)).collect();
        let sigs: Vec<Vec<u8>> = pairs.iter().map(|(sk, _)| sign(sk, msg).unwrap()).collect();
        let sig_refs: Vec<&[u8]> = sigs.iter().map(|v| v.as_slice()).collect();
        let pk_refs: Vec<&[u8]> = pairs.iter().map(|(_, pk)| &pk[..]).collect();

        let agg_sig = aggregate_signatures(&sig_refs).expect("aggregate sigs");
        let agg_pk = aggregate_pubkeys(&pk_refs).expect("aggregate pks");
        assert_eq!(agg_sig.len(), BLS_SIG_LEN);
        assert_eq!(agg_pk.len(), BLS_VK_LEN);

        verify_aggregated(&agg_pk, &agg_sig, msg).expect("aggregated cert verifies");
        verify_aggregated(&agg_pk, &agg_sig, b"different msg").expect_err("tampered fails");
    }

    /// Verifier accepts a 3-of-5 subset (e.g., bitmap = 11010) — only
    /// the 3 selected pks aggregate, and the verifier matches those
    /// 3 selected sigs.
    #[test]
    fn bls_3_of_5_subset_verifies() {
        let mut rng = OsRng;
        let msg = b"partial committee";

        let pairs: Vec<([u8; 32], [u8; 48])> = (0..5).map(|_| keypair(&mut rng)).collect();
        // Select validators 0, 2, 3 (bitmap 10110 read LSB-first).
        let selected = [0usize, 2, 3];

        let sigs: Vec<Vec<u8>> = selected.iter().map(|&i| sign(&pairs[i].0, msg).unwrap()).collect();
        let sig_refs: Vec<&[u8]> = sigs.iter().map(|v| v.as_slice()).collect();
        let pk_refs: Vec<&[u8]> = selected.iter().map(|&i| &pairs[i].1[..]).collect();

        let agg_sig = aggregate_signatures(&sig_refs).expect("aggregate sigs");
        let agg_pk = aggregate_pubkeys(&pk_refs).expect("aggregate pks");
        verify_aggregated(&agg_pk, &agg_sig, msg).expect("3-of-5 verifies");
    }

    /// An attacker who substitutes their own pk for one of the
    /// validators' fails the aggregated check.
    #[test]
    fn bls_substituted_pk_fails() {
        let mut rng = OsRng;
        let msg = b"honest";

        let pairs: Vec<([u8; 32], [u8; 48])> = (0..3).map(|_| keypair(&mut rng)).collect();
        let sigs: Vec<Vec<u8>> = pairs.iter().map(|(sk, _)| sign(sk, msg).unwrap()).collect();
        let sig_refs: Vec<&[u8]> = sigs.iter().map(|v| v.as_slice()).collect();

        // Replace pubkey 1 with a different keypair's pk.
        let (_, attacker_pk) = keypair(&mut rng);
        let pk_refs: Vec<&[u8]> = vec![&pairs[0].1[..], &attacker_pk[..], &pairs[2].1[..]];

        let agg_sig = aggregate_signatures(&sig_refs).expect("aggregate sigs");
        let agg_pk = aggregate_pubkeys(&pk_refs).expect("aggregate pks");
        verify_aggregated(&agg_pk, &agg_sig, msg).expect_err("substituted pk must fail");
    }

    #[test]
    fn bls_rejects_wrong_lengths() {
        assert!(matches!(
            verify(&[0u8; 10], &[0u8; BLS_SIG_LEN], b"x"),
            Err(CryptoError::Malformed)
        ));
        assert!(matches!(
            verify(&[0u8; BLS_VK_LEN], &[0u8; 10], b"x"),
            Err(CryptoError::Malformed)
        ));
    }
}
