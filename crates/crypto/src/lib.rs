//! Post-quantum signature dispatch.
//!
//! The public surface is `sign(algo, sk, msg)` and `verify(algo, pk, sig, msg)`. All
//! callers go through these; no algorithm-specific import should leak outside this crate.
//! That discipline is what lets `UpgradeCrypto` swap primitives without touching
//! consensus code.

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
///
/// v0.1 stub: returns `NotWired` until `fn-dsa` / `slh-dsa` crate APIs are pinned.
pub fn sign(algo: u8, _sk: &[u8], _msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match algo {
        1 | 2 => Err(CryptoError::NotWired),
        _ => Err(CryptoError::UnknownAlgo(algo)),
    }
}

/// Verify a signature under the given algorithm tag.
pub fn verify(algo: u8, _pk: &[u8], _sig: &[u8], _msg: &[u8]) -> Result<(), CryptoError> {
    match algo {
        1 | 2 => Err(CryptoError::NotWired),
        _ => Err(CryptoError::UnknownAlgo(algo)),
    }
}

/// Declared sizes (bytes) for each algorithm's public key and signature. Used for
/// block-size accounting and sanity checks on deserialized witnesses.
pub fn sizes(algo: u8) -> Option<(usize, usize)> {
    match algo {
        1 => Some((897, 666)),    // Falcon-512 / FN-DSA
        2 => Some((32, 7856)),    // SLH-DSA-128s
        _ => None,
    }
}
