//! Transaction types with signature-algorithm and hash-algorithm tag bytes.

use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigAlgo {
    Falcon512 = 1,
    SlhDsa128s = 2,
}

impl SigAlgo {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Falcon512),
            2 => Some(Self::SlhDsa128s),
            _ => None,
        }
    }
}

/// 6-byte content-derived account identifier. First bytes of a domain-tagged hash
/// of the public key. Collisions extend to 8 bytes via a length-prefixed variant
/// (not wired in v0.1).
pub type AccountId = [u8; 6];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PubKeyRef {
    /// The pubkey is already committed to the accounts subtree. Lookup by id.
    Known(AccountId),
    /// First tx from this account — full pubkey bytes inline, sized by algo.
    Inline(#[serde(with = "serde_bytes")] Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxCall {
    Transfer { to: AccountId, amount: u128 },
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxBody {
    pub nonce: u64,
    pub from_account: AccountId,
    pub call: TxCall,
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
