//! Transaction types with signature-algorithm and hash-algorithm tag bytes.
//!
//! Phase A (`sig_algo = 3` = Ed25519): testnet bringup. Lets us prove the
//! account/tx/apply-block path end-to-end without the cost of wiring Falcon-512
//! at the same time as everything else.
//!
//! Phase B (`sig_algo = 1` = Falcon-512): activated by an `UpgradeCrypto`
//! governance tx on the live testnet — which itself is the first real-world
//! exercise of the crypto-agility layer the whitepaper promises.

use serde::{Deserialize, Serialize};

pub use crate::address::AccountId;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigAlgo {
    Falcon512 = 1,
    SlhDsa128s = 2,
    /// Ed25519 — Phase-A bringup placeholder. Tag = 3 explicitly so that an
    /// `UpgradeCrypto` event can rotate to Falcon-512 without invalidating
    /// any signed-with-3 history. Not for mainnet.
    Ed25519 = 3,
}

impl SigAlgo {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Falcon512),
            2 => Some(Self::SlhDsa128s),
            3 => Some(Self::Ed25519),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PubKeyRef {
    /// The pubkey is already committed to the accounts subtree — lookup by id.
    Known(AccountId),
    /// First tx from this account — full pubkey bytes inline, sized by algo.
    Inline(#[serde(with = "serde_bytes")] Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxCall {
    Transfer {
        to: AccountId,
        amount: u128,
    },
    DeployContract {
        code_ref: [u8; 32],
        #[serde(with = "serde_bytes")]
        init_args: Vec<u8>,
    },
    CallContract {
        contract: AccountId,
        method: String,
        #[serde(with = "serde_bytes")]
        args: Vec<u8>,
    },
    UpgradeCrypto {
        target_height: u64,
        sig_algo: u8,
        hash_algo: u8,
    },
}

/// The body of a transaction — everything that gets signed.
///
/// The witness `(sig, pubkey)` is segregated into a separate structure
/// per whitepaper §7.2; the body's `witness_hash` field commits to it
/// without storing the raw signature alongside the state-transition
/// payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxBody {
    pub nonce: u64,
    pub from_account: AccountId,
    pub call: TxCall,
    /// Fee in sat (sat = 10⁻⁸ PYG). Paid to the block's coinbase recipient.
    pub fee_sat: u64,
    pub gas_limit: u32,
    pub witness_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness {
    pub sig_algo: u8,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    pub pubkey: PubKeyRef,
}

impl Witness {
    /// Domain-tagged hash of the witness, used as `TxBody.witness_hash`.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"PGwit\x00");
        h.update(&[self.sig_algo]);
        h.update(&(self.sig.len() as u32).to_le_bytes());
        h.update(&self.sig);
        match &self.pubkey {
            PubKeyRef::Known(id) => {
                h.update(&[0u8]); // discriminator
                h.update(&id.0);
            }
            PubKeyRef::Inline(bytes) => {
                h.update(&[1u8]);
                h.update(&(bytes.len() as u32).to_le_bytes());
                h.update(bytes);
            }
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize().as_bytes()[..]);
        out
    }
}
