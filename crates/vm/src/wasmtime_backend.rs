//! WASM contract VM via `wasmtime`.
//!
//! Enabled with `cargo build -p pygrove-vm --features wasm`. Provides a
//! sandboxed, fuel-metered contract execution surface for `DeployContract`
//! and `CallContract` transactions.
//!
//! ## Sandbox guarantees
//!
//! - **Pure WASM:** no filesystem, no network, no clock, no system calls.
//!   The only outside surface is a small registry of host functions
//!   (currently empty by default; v0.5 adds `chain_reflect_get`).
//! - **Fuel metered:** every WASM instruction consumes one unit. The
//!   `gas_limit` argument bounds total execution. Going over traps with
//!   [`super::VmError::OutOfGas`].
//! - **Memory bounded:** WASM linear memory is capped at the module's
//!   declared maximum (no `grow` past it).
//! - **Deterministic:** wasmtime in fuel-metered mode + no host
//!   randomness sources = reproducible execution. Two replays of the
//!   same block on different machines produce identical results.
//!
//! ## Method calling convention
//!
//! v0.5 starting point:
//!
//! - The contract exports functions taking `(args_ptr: i32, args_len: i32)`
//!   and returning `i64` (high 32 bits = result_ptr, low 32 bits = result_len).
//! - `args` is written into a contract-allocated buffer at `args_ptr`.
//! - The contract reads its inputs out of WASM linear memory at that
//!   buffer, computes a result, allocates space, and returns the result
//!   pointer + length.
//! - The host reads result bytes back from linear memory.
//!
//! For the v0.4 sprint foundation we ship a simpler convention: the
//! contract exports a function with pure WASM signature (zero or more
//! `i64` args, returns `i64`), and `args`/return are SCALE-encoded
//! integers. That's enough to demonstrate fuel metering and the
//! sandbox surface; a richer ABI lands with the contract type system in
//! v0.5+.

use crate::VmError;
use wasmtime::{Config, Engine, Instance, Module, Store};

/// A compiled module + its source-bytes hash (for content-addressed
/// caching downstream).
pub struct ContractHandle {
    module: Module,
    /// Blake3 hash of the original `wasm_bytes`. Lets state.code subtree
    /// key on this without re-hashing.
    pub code_hash: [u8; 32],
}

impl std::fmt::Debug for ContractHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContractHandle")
            .field("code_hash", &hex_short(&self.code_hash))
            .finish()
    }
}

fn hex_short(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(16);
    for b in bytes.iter().take(6) {
        s.push_str(&format!("{b:02x}"));
    }
    s.push('…');
    s
}

/// The wasmtime-backed contract VM.
pub struct WasmtimeVm {
    engine: Engine,
}

impl WasmtimeVm {
    pub fn new() -> Result<Self, VmError> {
        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        // Determinism: turn off any nondeterministic features wasmtime
        // might add by default.
        cfg.wasm_threads(false);
        cfg.wasm_simd(false);
        cfg.wasm_relaxed_simd(false);
        cfg.wasm_reference_types(true); // needed for many compilers' output
        cfg.wasm_bulk_memory(true);
        let engine = Engine::new(&cfg).map_err(|e| VmError::CompileFailed(e.to_string()))?;
        Ok(Self { engine })
    }
}

impl Default for WasmtimeVm {
    fn default() -> Self {
        Self::new().expect("wasmtime engine creation")
    }
}

impl crate::Vm for WasmtimeVm {
    type Handle = ContractHandle;

    fn compile(&mut self, wasm_bytes: &[u8]) -> Result<ContractHandle, VmError> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| VmError::CompileFailed(e.to_string()))?;
        let code_hash: [u8; 32] = blake3::hash(wasm_bytes).into();
        Ok(ContractHandle { module, code_hash })
    }

    fn run(
        &mut self,
        handle: &ContractHandle,
        method: &str,
        args: &[u8],
        gas_limit: u64,
    ) -> Result<Vec<u8>, VmError> {
        let mut store = Store::new(&self.engine, ());
        store
            .set_fuel(gas_limit)
            .map_err(|e| VmError::Trap(e.to_string()))?;

        let instance = Instance::new(&mut store, &handle.module, &[])
            .map_err(|e| VmError::InstantiateFailed(e.to_string()))?;

        // v0.4 ABI: contract export `method` is a function `(i64...) -> i64`.
        // Args are big-endian-packed i64 lanes (first 8 bytes = first arg, etc).
        // Return is the i64 packed big-endian into 8 bytes.
        let func = instance
            .get_func(&mut store, method)
            .ok_or_else(|| VmError::MethodNotFound(method.into()))?;

        let ty = func.ty(&store);
        let n_params = ty.params().len();

        if args.len() != 8 * n_params {
            return Err(VmError::BadArgs);
        }

        let mut params = Vec::with_capacity(n_params);
        for chunk in args.chunks_exact(8) {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(chunk);
            params.push(wasmtime::Val::I64(i64::from_be_bytes(arr)));
        }

        let mut results = vec![wasmtime::Val::I64(0); ty.results().len()];

        let call_result = func.call(&mut store, &params, &mut results);

        match call_result {
            Ok(()) => {
                let mut out = Vec::with_capacity(8 * results.len());
                for r in &results {
                    let v = r.i64().ok_or_else(|| {
                        VmError::Trap("non-i64 result not supported in v0.4 ABI".into())
                    })?;
                    out.extend_from_slice(&v.to_be_bytes());
                }
                Ok(out)
            }
            Err(e) => {
                let s = e.to_string();
                if s.contains("all fuel consumed") || s.contains("out of fuel") {
                    Err(VmError::OutOfGas)
                } else {
                    Err(VmError::Trap(s))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vm;

    /// Smoke test: compile a tiny WAT module exporting `add(i64, i64) -> i64`,
    /// run it, observe correct sum.
    #[test]
    fn wasmtime_runs_simple_add() {
        let wat = r#"
            (module
                (func (export "add") (param $a i64) (param $b i64) (result i64)
                    local.get $a
                    local.get $b
                    i64.add)
            )
        "#;
        let wasm = wat::parse_str(wat).unwrap();

        let mut vm = WasmtimeVm::new().unwrap();
        let handle = vm.compile(&wasm).expect("compile");
        let mut args = Vec::new();
        args.extend_from_slice(&7i64.to_be_bytes());
        args.extend_from_slice(&35i64.to_be_bytes());
        let out = vm.run(&handle, "add", &args, 100_000).expect("run");
        let result = i64::from_be_bytes(out[..8].try_into().unwrap());
        assert_eq!(result, 42);
    }

    /// Out-of-gas: a tight loop with a low fuel budget traps cleanly.
    #[test]
    fn wasmtime_out_of_gas_traps() {
        let wat = r#"
            (module
                (func (export "spin") (result i64)
                    (loop $loop
                        br $loop)
                    i64.const 0)
            )
        "#;
        let wasm = wat::parse_str(wat).unwrap();
        let mut vm = WasmtimeVm::new().unwrap();
        let handle = vm.compile(&wasm).expect("compile");
        let r = vm.run(&handle, "spin", &[], 1000);
        assert!(matches!(r, Err(VmError::OutOfGas)), "got {r:?}");
    }

    /// Method-not-found returns the right error.
    #[test]
    fn wasmtime_missing_method() {
        let wat = r#"(module (func (export "foo") (result i64) i64.const 0))"#;
        let wasm = wat::parse_str(wat).unwrap();
        let mut vm = WasmtimeVm::new().unwrap();
        let handle = vm.compile(&wasm).expect("compile");
        let r = vm.run(&handle, "bar", &[], 1000);
        assert!(matches!(r, Err(VmError::MethodNotFound(_))));
    }

    /// Compile failure on garbage bytes.
    #[test]
    fn wasmtime_rejects_garbage() {
        let mut vm = WasmtimeVm::new().unwrap();
        assert!(matches!(
            vm.compile(b"\x00\x01\x02\x03"),
            Err(VmError::CompileFailed(_))
        ));
    }

    /// Two compiles of the same WASM bytes produce the same code_hash.
    #[test]
    fn wasmtime_code_hash_is_deterministic() {
        let wat = r#"(module (func (export "f") (result i64) i64.const 99))"#;
        let wasm = wat::parse_str(wat).unwrap();
        let mut vm = WasmtimeVm::new().unwrap();
        let h1 = vm.compile(&wasm).expect("compile 1");
        let h2 = vm.compile(&wasm).expect("compile 2");
        assert_eq!(h1.code_hash, h2.code_hash);
    }
}
