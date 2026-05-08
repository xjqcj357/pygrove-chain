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

/// Canonical encoding of a `TxCall` into a hasher. Field order is fixed forever —
/// changing it changes every signing hash and therefore every existing signature.
fn hash_call(h: &mut blake3::Hasher, call: &TxCall) {
    match call {
        TxCall::Transfer { to, amount } => {
            h.update(&[0u8]);
            h.update(&to.0);
            h.update(&amount.to_le_bytes());
        }
        TxCall::DeployContract { code_ref, init_args } => {
            h.update(&[1u8]);
            h.update(code_ref);
            h.update(&(init_args.len() as u32).to_le_bytes());
            h.update(init_args);
        }
        TxCall::CallContract { contract, method, args } => {
            h.update(&[2u8]);
            h.update(&contract.0);
            h.update(&(method.len() as u32).to_le_bytes());
            h.update(method.as_bytes());
            h.update(&(args.len() as u32).to_le_bytes());
            h.update(args);
        }
        TxCall::UpgradeCrypto {
            target_height,
            sig_algo,
            hash_algo,
        } => {
            h.update(&[3u8]);
            h.update(&target_height.to_le_bytes());
            h.update(&[*sig_algo, *hash_algo]);
        }
    }
}

impl TxBody {
    /// Hash that the witness signs. Excludes `witness_hash` itself (which would be
    /// circular — it's a commitment to the signature) and the `gas_limit` (also a
    /// post-signing field, paid for separately). Domain tag `PGtxsign\0`.
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"PGtxsign\x00");
        h.update(&self.nonce.to_le_bytes());
        h.update(&self.from_account.0);
        hash_call(&mut h, &self.call);
        h.update(&self.fee_sat.to_le_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize().as_bytes()[..]);
        out
    }

    /// Hash committed in `tx_root` of the block. Includes every field including
    /// `witness_hash` so the block header binds to a specific signature.
    pub fn body_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"PGtxbody\x00");
        h.update(&self.nonce.to_le_bytes());
        h.update(&self.from_account.0);
        hash_call(&mut h, &self.call);
        h.update(&self.fee_sat.to_le_bytes());
        h.update(&self.gas_limit.to_le_bytes());
        h.update(&self.witness_hash);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize().as_bytes()[..]);
        out
    }
}

/// Domain-tagged Merkle-ish root over a vector of leaves. v0.1: simple ordered
/// concatenation hash, deterministic. Production path swaps to a proper sparse
/// Merkle tree under the GroveDB rollout.
pub fn vec_root(domain: &[u8], leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(&(leaves.len() as u32).to_le_bytes());
    for leaf in leaves {
        h.update(leaf);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize().as_bytes()[..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx() -> TxBody {
        TxBody {
            nonce: 7,
            from_account: AccountId::new([1u8; 20]),
            call: TxCall::Transfer {
                to: AccountId::new([2u8; 20]),
                amount: 1_000,
            },
            fee_sat: 10,
            gas_limit: 21000,
            witness_hash: [9u8; 32],
        }
    }

    #[test]
    fn signing_hash_excludes_witness() {
        let mut a = sample_tx();
        let h_a = a.signing_hash();
        a.witness_hash = [0u8; 32];
        let h_b = a.signing_hash();
        assert_eq!(h_a, h_b, "signing_hash must not depend on witness_hash");
    }

    #[test]
    fn body_hash_includes_witness() {
        let mut a = sample_tx();
        let h_a = a.body_hash();
        a.witness_hash = [0u8; 32];
        let h_b = a.body_hash();
        assert_ne!(h_a, h_b);
    }

    #[test]
    fn signing_hash_changes_with_amount() {
        let a = sample_tx();
        let mut b = a.clone();
        if let TxCall::Transfer { amount, .. } = &mut b.call {
            *amount = 1_001;
        }
        assert_ne!(a.signing_hash(), b.signing_hash());
    }
}
