//! PyGrove Chain core types: blocks, transactions, canonical encoding, domain-tagged hashing.
//!
//! This crate is the ground floor of the chain. It defines the wire format, the hash
//! domains, and the algo-tag bytes that make the rest of the system crypto-agile.

pub mod address;
pub mod hash;
pub mod tx;
pub mod block;

pub use address::{AccountId, AddressError, ACCOUNT_ID_LEN, ADDRESS_HRP};
pub use block::{Block, BlockBody, BlockHeader};
pub use hash::{Digest32, Digest64, HashAlgo, domain_tag};
pub use tx::{PubKeyRef, SigAlgo, TxBody, TxCall, Witness};
