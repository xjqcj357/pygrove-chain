//! PyGrove Chain core types: blocks, transactions, canonical encoding, domain-tagged hashing.
//!
//! This crate is the ground floor of the chain. It defines the wire format, the hash
//! domains, and the algo-tag bytes that make the rest of the system crypto-agile.

pub mod hash;
pub mod tx;
pub mod block;

pub use block::{Block, BlockBody, BlockHeader};
pub use hash::{Digest32, Digest64, HashAlgo, domain_tag};
pub use tx::{AccountId, PubKeyRef, SigAlgo, TxBody, TxCall, Witness};
