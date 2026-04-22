//! State: authenticated KV store with named subtrees.
//!
//! v0.1 defines the subtree layout and a trait surface; the GroveDB-backed
//! implementation is wired in once the `grovedb` crate builds cleanly on Linux CI and
//! MSVC. Until then an in-memory hash-tree stub keeps the rest of the workspace
//! compilable and testable.

pub mod subtrees;
pub mod store;

pub use store::{MemState, StateStore};
pub use subtrees::Subtree;
