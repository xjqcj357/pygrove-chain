//! 20-byte account identifiers and their human-readable bech32 encoding.
//!
//! An `AccountId` is the first 20 bytes of `blake3-XOF-512` of a public key's
//! canonical bytes, with a domain tag specific to the address purpose. The
//! 20-byte choice mirrors Ethereum: small enough to copy-paste, large enough
//! that birthday-collision security stays at ~80 bits.
//!
//! On the wire the account id is the raw 20 bytes; in user-facing surfaces
//! (wallets, RPC strings, the explorer) the address is bech32m-encoded with
//! the `pyg` human-readable prefix — `pyg1qz4f...` everywhere (testnet,
//! mainnet, anywhere). There is no per-network HRP.
//!
//! Bech32m has built-in error detection: a single typo in the address fails
//! the checksum and the wallet refuses to send.

use bech32::{Bech32m, Hrp};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::Digest32;

/// Human-readable prefix for every PyGrove address.
pub const ADDRESS_HRP: &str = "pyg";

/// Account id length in bytes — 20, matching Ethereum's choice.
pub const ACCOUNT_ID_LEN: usize = 20;

/// Domain tag used when deriving `AccountId` from a public key — same shape
/// as `b"PGhdr\x00"` in `pow::hash_header`. Cross-domain collisions are
/// computationally meaningless because the tag prefix differs.
pub const ACCOUNT_DERIVE_TAG: &[u8] = b"PGaddr\x00";

/// 20-byte account identifier. Wire format on the chain; bech32-encoded for users.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AccountId(pub [u8; ACCOUNT_ID_LEN]);

#[derive(Debug, Error)]
pub enum AddressError {
    #[error("bech32 decode failed: {0}")]
    Decode(String),
    #[error("wrong hrp: expected `pyg`, got `{0}`")]
    WrongHrp(String),
    #[error("wrong length: expected 20 bytes, got {0}")]
    WrongLength(usize),
}

impl AccountId {
    pub const ZERO: AccountId = AccountId([0u8; ACCOUNT_ID_LEN]);

    pub fn new(bytes: [u8; ACCOUNT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Derive an `AccountId` from a raw public key. Domain-tagged blake3 of the
    /// pubkey bytes, truncated to 20 bytes. Same algorithm regardless of which
    /// signature scheme produced the public key — `pyg1...` addresses unify
    /// across crypto agility.
    pub fn from_pubkey(pubkey_bytes: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(ACCOUNT_DERIVE_TAG);
        h.update(pubkey_bytes);
        let digest = h.finalize();
        let mut out = [0u8; ACCOUNT_ID_LEN];
        out.copy_from_slice(&digest.as_bytes()[..ACCOUNT_ID_LEN]);
        Self(out)
    }

    /// Pack into a fixed 32-byte slot used by `BlockHeader.coinbase`. The id
    /// goes in the leading 20 bytes; trailing 12 are zero.
    pub fn pad_to_32(&self) -> Digest32 {
        let mut out = [0u8; 32];
        out[..ACCOUNT_ID_LEN].copy_from_slice(&self.0);
        out
    }

    /// Recover an `AccountId` from a 32-byte coinbase slot — first 20 bytes.
    pub fn from_coinbase(coinbase: &Digest32) -> Self {
        let mut out = [0u8; ACCOUNT_ID_LEN];
        out.copy_from_slice(&coinbase[..ACCOUNT_ID_LEN]);
        Self(out)
    }

    /// Bech32m-encoded address: `pyg1...`.
    pub fn to_bech32(&self) -> String {
        let hrp = Hrp::parse(ADDRESS_HRP).expect("`pyg` is a valid hrp");
        bech32::encode::<Bech32m>(hrp, &self.0).expect("encoding 20 bytes never fails")
    }

    /// Decode a bech32m `pyg1...` address back to its raw 20 bytes.
    pub fn from_bech32(s: &str) -> Result<Self, AddressError> {
        let (hrp, data) =
            bech32::decode(s).map_err(|e| AddressError::Decode(e.to_string()))?;
        if hrp.as_str() != ADDRESS_HRP {
            return Err(AddressError::WrongHrp(hrp.as_str().to_string()));
        }
        if data.len() != ACCOUNT_ID_LEN {
            return Err(AddressError::WrongLength(data.len()));
        }
        let mut out = [0u8; ACCOUNT_ID_LEN];
        out.copy_from_slice(&data);
        Ok(Self(out))
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_bech32())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_address_roundtrip() {
        let zero = AccountId::ZERO;
        let s = zero.to_bech32();
        assert!(s.starts_with("pyg1"));
        let back = AccountId::from_bech32(&s).unwrap();
        assert_eq!(zero, back);
    }

    #[test]
    fn from_pubkey_is_deterministic() {
        let pk = [42u8; 32];
        let a = AccountId::from_pubkey(&pk);
        let b = AccountId::from_pubkey(&pk);
        assert_eq!(a, b);
    }

    #[test]
    fn coinbase_padding_roundtrip() {
        let pk = [9u8; 32];
        let id = AccountId::from_pubkey(&pk);
        let coinbase = id.pad_to_32();
        let recovered = AccountId::from_coinbase(&coinbase);
        assert_eq!(id, recovered);
    }

    #[test]
    fn rejects_wrong_hrp() {
        // bc1... is bitcoin's hrp
        let result = AccountId::from_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(matches!(result, Err(AddressError::WrongHrp(_))));
    }

    #[test]
    fn rejects_typo() {
        let pk = [1u8; 32];
        let id = AccountId::from_pubkey(&pk);
        let mut s = id.to_bech32();
        // Mutate one character — bech32m checksum should catch it.
        let bytes = unsafe { s.as_bytes_mut() };
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'a' { b'q' } else { b'a' };
        assert!(AccountId::from_bech32(&s).is_err());
    }
}
