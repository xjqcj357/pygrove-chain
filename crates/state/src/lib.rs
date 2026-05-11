//! State: authenticated KV store with named subtrees.
//!
//! v0.1 defines the subtree layout and a trait surface; the GroveDB-backed
//! implementation is wired in once the `grovedb` crate builds cleanly on Linux CI and
//! MSVC. Until then an in-memory hash-tree stub keeps the rest of the workspace
//! compilable and testable.

pub mod accounts;
pub mod apply;
pub mod store;
pub mod subtrees;

pub use accounts::Account;
pub use apply::{
    apply_block, load_active_crypto, load_attest_authority, load_governance,
    load_latest_reflection, load_reflection_at, register_attest_gov_payload,
    set_governance_gov_payload, upgrade_crypto_gov_payload, verify_governance_proof,
    ActiveCrypto, ApplyError, ApplyOutput, AttestRecord, CoordinatorAuthority,
    GovernanceConfig, GovernanceError, GovernanceProof, GovernanceSig, GovernanceSigner,
    PedigreeRecord, PendingCryptoUpgrade,
};
pub use store::{MemState, StateStore};
pub use subtrees::Subtree;
