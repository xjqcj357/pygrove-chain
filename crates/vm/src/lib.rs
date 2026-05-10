//! PyGrove Chain WASM contract VM.
//!
//! ## History
//!
//! v0.1 shipped a CPython-via-PyO3 placeholder (the original v1.2 plan).
//! Reviewing it for the v0.4 sprint, Palantir oversight rejected the
//! Python-in-the-VM design: CMVP cannot validate an interpreted-language
//! boundary with dynamic dispatch and an open `__import__` surface.
//! Replacement: `wasmtime` + a small ABI for hash + sig + np-array
//! reductions. The Python *ecosystem* still reaches the chain via wasmtime
//! hosts running PyO3-compiled bindings outside the FIPS boundary; the
//! chain's contract VM is WASM.
//!
//! ## Build profiles
//!
//! - **Default** (`cargo build`): the [`Vm`] trait surface compiles, but
//!   only the [`RejectingVm`] backend is available. `apply_block` calls
//!   for `DeployContract` / `CallContract` continue to reject with
//!   `UnsupportedCall`. This keeps the testnet-3 image small.
//! - **WASM** (`cargo build -p pygrove-vm --features wasm`): the
//!   [`WasmtimeVm`] backend is available. Contracts compile from a
//!   WebAssembly module reference, run with fuel-metered gas, and may
//!   call host functions registered against [`Host`].
//!
//! ## API surface (stable across both profiles)
//!
//! - [`Vm`] — trait. `compile(code)`, `run(handle, method, args, gas)`.
//! - [`VmError`] — failure cases (out-of-gas, trap, host-rejected, etc).
//! - [`Host`] — registry of host functions exposed to contracts. v0.5
//!   stocks one function: `chain_reflect_get(key) -> bytes`.
//! - [`RejectingVm`] — default backend. Always `Err(VmError::NotEnabled)`.
//! - `WasmtimeVm` — feature-gated.

use thiserror::Error;

#[cfg(feature = "wasm")]
pub mod wasmtime_backend;

/// Read-only view onto the chain's `Subtree::Reflect` records. Implemented
/// by `pygrove-state::MemState` (and any future GroveDB-backed store)
/// outside this crate; consumed by the [`Vm`] when a contract calls the
/// `chain_reflect_get` host function (the `CHAIN_REFLECT(key)` opcode the
/// whitepaper specifies).
///
/// Keys follow the convention written by `pygrove_state::apply_block`:
///   - `b"latest"`              — most recent block's Reflection record
///   - `b"block/" || height_be` — per-height records (CBOR-encoded)
///
/// Returning `None` means "no record at that key"; the host function
/// surfaces that to the contract as a length of `-1`.
pub trait ReflectionView {
    fn reflect_get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

/// A no-op `ReflectionView` used by the rejecting backend and by tests
/// that don't care about reflection. Returns `None` for every key.
pub struct NoReflection;

impl ReflectionView for NoReflection {
    fn reflect_get(&self, _key: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

#[derive(Debug, Error)]
pub enum VmError {
    #[error("contract VM is not enabled in this build (rebuild with --features wasm)")]
    NotEnabled,
    #[error("module compile failed: {0}")]
    CompileFailed(String),
    #[error("module instantiation failed: {0}")]
    InstantiateFailed(String),
    #[error("contract trapped: {0}")]
    Trap(String),
    #[error("out of gas")]
    OutOfGas,
    #[error("contract aborted by host policy: {0}")]
    HostRejected(String),
    #[error("entry function {0} not found in module")]
    MethodNotFound(String),
    #[error("malformed argument bytes")]
    BadArgs,
}

/// A compiled contract module reference. Backend-specific behind the
/// feature; default builds use a unit-typed handle.
#[cfg(not(feature = "wasm"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct ContractHandle;

/// Host-function registry. Today: `chain_reflect_get` (read from
/// `Subtree::Reflect`). Mirrors the `CHAIN_REFLECT(key)` opcode the
/// whitepaper specifies.
#[derive(Default)]
pub struct Host;

impl Host {
    pub fn new() -> Self {
        Self
    }
}

/// The VM trait. Implementations: [`RejectingVm`] (default) and
/// `WasmtimeVm` (when `--features wasm`).
pub trait Vm {
    type Handle;

    /// Validate + compile a WASM module. Returns a handle for subsequent
    /// `run` calls.
    fn compile(&mut self, wasm_bytes: &[u8]) -> Result<Self::Handle, VmError>;

    /// Invoke `method` on a previously-compiled module with `args`,
    /// metered to `gas_limit` units. Returns the method's return bytes
    /// (typically an SCALE / CBOR payload) on success.
    ///
    /// `reflect` provides the contract's read-only view onto
    /// `Subtree::Reflect`. Contracts call the `chain_reflect_get` host
    /// function (the `CHAIN_REFLECT(key)` opcode) to read from it.
    fn run(
        &mut self,
        handle: &Self::Handle,
        method: &str,
        args: &[u8],
        gas_limit: u64,
        reflect: &dyn ReflectionView,
    ) -> Result<Vec<u8>, VmError>;
}

/// Default backend. Always rejects. Lets the rest of the crate compile in
/// non-WASM builds without paying the wasmtime dependency cost.
pub struct RejectingVm;

impl RejectingVm {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RejectingVm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "wasm"))]
impl Vm for RejectingVm {
    type Handle = ContractHandle;

    fn compile(&mut self, _wasm_bytes: &[u8]) -> Result<Self::Handle, VmError> {
        Err(VmError::NotEnabled)
    }

    fn run(
        &mut self,
        _handle: &Self::Handle,
        _method: &str,
        _args: &[u8],
        _gas_limit: u64,
        _reflect: &dyn ReflectionView,
    ) -> Result<Vec<u8>, VmError> {
        Err(VmError::NotEnabled)
    }
}

#[cfg(feature = "wasm")]
pub use wasmtime_backend::{ContractHandle, WasmtimeVm};

#[cfg(feature = "wasm")]
impl Vm for RejectingVm {
    type Handle = ContractHandle;

    fn compile(&mut self, _wasm_bytes: &[u8]) -> Result<Self::Handle, VmError> {
        Err(VmError::NotEnabled)
    }

    fn run(
        &mut self,
        _handle: &Self::Handle,
        _method: &str,
        _args: &[u8],
        _gas_limit: u64,
        _reflect: &dyn ReflectionView,
    ) -> Result<Vec<u8>, VmError> {
        Err(VmError::NotEnabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejecting_vm_says_not_enabled() {
        let mut vm = RejectingVm::new();
        let h = vm.compile(b"\x00asm\x01\x00\x00\x00");
        assert!(matches!(h, Err(VmError::NotEnabled)));
    }

    #[test]
    fn host_constructs() {
        let _h = Host::new();
    }

    #[test]
    fn no_reflection_always_misses() {
        let v = NoReflection;
        assert!(v.reflect_get(b"latest").is_none());
        assert!(v.reflect_get(b"block/00").is_none());
    }
}
