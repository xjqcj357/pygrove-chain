//! Domain-tagged hashing with a 1-byte HashAlgo discriminator baked into every digest.
//!
//! All chain digests funnel through [`hash_with_domain`] so a v2 hash algorithm can be
//! activated via an `UpgradeCrypto` governance tx without forking historical blocks.

use blake3::Hasher as Blake3Hasher;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

pub type Digest32 = [u8; 32];
pub type Digest64 = [u8; 64];

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Blake3Xof512 = 1,
    Shake256 = 2,
}

impl HashAlgo {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Blake3Xof512),
            2 => Some(Self::Shake256),
            _ => None,
        }
    }
}

/// A per-subtree / per-purpose domain tag. Each hash invocation includes one of these
/// so colliding bytes across domains is useless even with Grover.
pub fn domain_tag(domain: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + domain.len());
    v.push(b'P');
    v.push(b'G');
    v.extend_from_slice(domain.as_bytes());
    v.push(0);
    v
}

/// Produce a 64-byte digest under the given algo with a domain tag prefix.
pub fn hash_with_domain(algo: HashAlgo, domain: &str, bytes: &[u8]) -> Digest64 {
    let tag = domain_tag(domain);
    match algo {
        HashAlgo::Blake3Xof512 => {
            let mut h = Blake3Hasher::new();
            h.update(&tag);
            h.update(bytes);
            let mut out = [0u8; 64];
            let mut xof = h.finalize_xof();
            xof.fill(&mut out);
            out
        }
        HashAlgo::Shake256 => {
            let mut h = Shake256::default();
            h.update(&tag);
            h.update(bytes);
            let mut out = [0u8; 64];
            let mut reader = h.finalize_xof();
            reader.read(&mut out);
            out
        }
    }
}

/// Truncate a 64-byte digest to its first 32 bytes. Used anywhere a fixed 32-byte
/// reference is stored (header fields, account ids).
pub fn truncate_to_32(d: &Digest64) -> Digest32 {
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[..32]);
    out
}
