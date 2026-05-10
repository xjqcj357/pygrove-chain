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

use crate::{ReflectionView, VmError};
use wasmtime::{Caller, Config, Engine, Extern, Linker, Module, Store};

/// Per-invocation store state for a contract call. Wraps a raw pointer to
/// the caller-supplied `&dyn ReflectionView` so the host function can
/// reach the chain's reflection records. The pointer is valid for the
/// lifetime of `run()`, never escapes it, and the host function is
/// guaranteed to be called synchronously from the same call.
///
/// We carry it as a raw pointer (cast back to `&dyn ReflectionView`
/// inside the host fn) because `wasmtime::Store`'s `T` must be
/// `'static`, and a `&'a dyn ...` reference isn't.
struct ContractCtx {
    reflect_ptr: *const (),
    reflect_call: unsafe fn(*const (), &[u8]) -> Option<Vec<u8>>,
}

// Safety: `WasmtimeVm::run` keeps `reflect: &dyn ReflectionView` alive
// for the entire wasmtime call; no part of `ContractCtx` outlives that.
unsafe impl Send for ContractCtx {}
unsafe impl Sync for ContractCtx {}

unsafe fn dispatch_reflect_get<V: ReflectionView + ?Sized>(
    p: *const (),
    key: &[u8],
) -> Option<Vec<u8>> {
    let view = unsafe { &*(p as *const V) };
    view.reflect_get(key)
}

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
        // might add by default. Threads + reference-types + GC are gated
        // at the cargo-feature level (we don't enable
        // wasmtime/{threads,gc,...}), so no Config knob is needed for
        // them in wasmtime 27+.
        cfg.wasm_simd(false);
        cfg.wasm_relaxed_simd(false);
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
        reflect: &dyn ReflectionView,
    ) -> Result<Vec<u8>, VmError> {
        // Build the per-call context. Erase the trait-object lifetime
        // into a raw pointer; we re-create it inside the host function.
        // Safe because the &dyn outlives this whole `run()` call.
        let ctx = ContractCtx {
            reflect_ptr: reflect as *const dyn ReflectionView as *const (),
            reflect_call: dispatch_reflect_get::<dyn ReflectionView>,
        };
        let mut store = Store::new(&self.engine, ctx);
        store
            .set_fuel(gas_limit)
            .map_err(|e| VmError::Trap(e.to_string()))?;

        // Register the `env.chain_reflect_get` host function.
        //
        // Signature:
        //   chain_reflect_get(key_ptr: i32, key_len: i32,
        //                     out_ptr: i32, out_max_len: i32) -> i32
        //
        // Reads `key_len` bytes from contract memory at `key_ptr`, looks
        // up the corresponding record in `Subtree::Reflect` via the
        // host's `ReflectionView`, writes up to `out_max_len` value
        // bytes to contract memory at `out_ptr`, and returns the number
        // of bytes actually written. On a miss, returns -1. On a write
        // overflow (`value.len() > out_max_len`), returns -2 — contracts
        // can retry with a larger buffer.
        let mut linker: Linker<ContractCtx> = Linker::new(&self.engine);
        linker
            .func_wrap(
                "env",
                "chain_reflect_get",
                |mut caller: Caller<'_, ContractCtx>,
                 key_ptr: i32,
                 key_len: i32,
                 out_ptr: i32,
                 out_max_len: i32|
                 -> i32 {
                    // Fetch the linear memory export.
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(m)) => m,
                        _ => return -3, // no memory export — programmer error
                    };
                    if key_ptr < 0 || key_len < 0 || out_ptr < 0 || out_max_len < 0 {
                        return -3;
                    }
                    let key_ptr = key_ptr as usize;
                    let key_len = key_len as usize;
                    let out_ptr = out_ptr as usize;
                    let out_max_len = out_max_len as usize;
                    let data = mem.data(&caller);
                    let key = match data.get(key_ptr..key_ptr.saturating_add(key_len)) {
                        Some(slice) => slice.to_vec(),
                        None => return -3, // OOB key read
                    };
                    let value = {
                        let ctx = caller.data();
                        // Safety: ctx.reflect_ptr came from a `&dyn`
                        // that's still alive for this whole `run`.
                        unsafe { (ctx.reflect_call)(ctx.reflect_ptr, &key) }
                    };
                    let value = match value {
                        Some(v) => v,
                        None => return -1,
                    };
                    if value.len() > out_max_len {
                        return -2;
                    }
                    let data_mut = mem.data_mut(&mut caller);
                    let dst = match data_mut.get_mut(out_ptr..out_ptr.saturating_add(value.len())) {
                        Some(slice) => slice,
                        None => return -3, // OOB write
                    };
                    dst.copy_from_slice(&value);
                    value.len() as i32
                },
            )
            .map_err(|e| VmError::InstantiateFailed(e.to_string()))?;

        let instance = linker
            .instantiate(&mut store, &handle.module)
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
                // wasmtime 27 surfaces the typed trap; the user-visible
                // string just says "error while executing at wasm
                // backtrace ...". Downcast to detect out-of-fuel reliably.
                if let Some(trap) = e.downcast_ref::<wasmtime::Trap>() {
                    if matches!(trap, wasmtime::Trap::OutOfFuel) {
                        return Err(VmError::OutOfGas);
                    }
                }
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
        let out = vm.run(&handle, "add", &args, 100_000, &crate::NoReflection).expect("run");
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
        let r = vm.run(&handle, "spin", &[], 1000, &crate::NoReflection);
        assert!(matches!(r, Err(VmError::OutOfGas)), "got {r:?}");
    }

    /// Method-not-found returns the right error.
    #[test]
    fn wasmtime_missing_method() {
        let wat = r#"(module (func (export "foo") (result i64) i64.const 0))"#;
        let wasm = wat::parse_str(wat).unwrap();
        let mut vm = WasmtimeVm::new().unwrap();
        let handle = vm.compile(&wasm).expect("compile");
        let r = vm.run(&handle, "bar", &[], 1000, &crate::NoReflection);
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

    /// In-memory `ReflectionView` for tests. Maps `latest` → fixed bytes.
    struct Fixture;
    impl crate::ReflectionView for Fixture {
        fn reflect_get(&self, key: &[u8]) -> Option<Vec<u8>> {
            if key == b"latest" {
                Some(vec![0xDE, 0xAD, 0xBE, 0xEF])
            } else {
                None
            }
        }
    }

    /// `chain_reflect_get` host function: contract reads its own
    /// memory for the key, calls the import, host writes value back
    /// into contract memory, contract returns the value's first byte.
    ///
    /// Module layout:
    ///   - 1 page of linear memory (export "memory")
    ///   - data segment at offset 0: 6 bytes of "latest"
    ///   - exported `read(out_ptr: i32) -> i32` calls
    ///       chain_reflect_get(0, 6, out_ptr, 32)
    ///     returning the length result, then reads the first byte of
    ///     the written value to confirm the host wrote the right bytes.
    #[test]
    fn wasmtime_chain_reflect_get_roundtrip() {
        let wat = r#"
            (module
                (import "env" "chain_reflect_get"
                    (func $reflect (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "latest")
                (func (export "read") (param $out i32) (result i32)
                    (call $reflect
                        (i32.const 0)        ;; key_ptr = 0 ("latest" lives here)
                        (i32.const 6)        ;; key_len = 6
                        (local.get $out)     ;; out_ptr = caller-chosen
                        (i32.const 32))      ;; out_max_len = 32
                )
                (func (export "peek") (param $ptr i32) (result i64)
                    (i64.extend_i32_u (i32.load8_u (local.get $ptr)))
                )
            )
        "#;
        let wasm = wat::parse_str(wat).unwrap();
        let mut vm = WasmtimeVm::new().unwrap();
        let handle = vm.compile(&wasm).expect("compile");

        // First: call `read` with out_ptr = 100.
        // Expected: returns 4 (length of [0xDE, 0xAD, 0xBE, 0xEF]).
        // The contract's return convention is i64; we're passing i32 args
        // and reading i32 results back through the i64 ABI shim. The
        // backend's run() expects i64 args, but the contract takes i32.
        // Skip the high-level run() and use a direct wasmtime call.
        let ctx = ContractCtx {
            reflect_ptr: &Fixture as *const dyn ReflectionView as *const (),
            reflect_call: dispatch_reflect_get::<dyn ReflectionView>,
        };
        let mut store = Store::new(&vm.engine, ctx);
        store.set_fuel(100_000).unwrap();

        let mut linker: Linker<ContractCtx> = Linker::new(&vm.engine);
        linker
            .func_wrap(
                "env",
                "chain_reflect_get",
                |mut caller: Caller<'_, ContractCtx>,
                 key_ptr: i32,
                 key_len: i32,
                 out_ptr: i32,
                 out_max_len: i32|
                 -> i32 {
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(m)) => m,
                        _ => return -3,
                    };
                    let data = mem.data(&caller);
                    let key = match data.get(key_ptr as usize..(key_ptr + key_len) as usize) {
                        Some(s) => s.to_vec(),
                        None => return -3,
                    };
                    let value = {
                        let c = caller.data();
                        unsafe { (c.reflect_call)(c.reflect_ptr, &key) }
                    };
                    let value = match value {
                        Some(v) => v,
                        None => return -1,
                    };
                    if value.len() as i32 > out_max_len {
                        return -2;
                    }
                    let data_mut = mem.data_mut(&mut caller);
                    let dst = match data_mut
                        .get_mut(out_ptr as usize..out_ptr as usize + value.len())
                    {
                        Some(s) => s,
                        None => return -3,
                    };
                    dst.copy_from_slice(&value);
                    value.len() as i32
                },
            )
            .unwrap();

        let instance = linker.instantiate(&mut store, &handle.module).unwrap();
        let read = instance
            .get_typed_func::<i32, i32>(&mut store, "read")
            .unwrap();
        let peek = instance
            .get_typed_func::<i32, i64>(&mut store, "peek")
            .unwrap();

        let n = read.call(&mut store, 100).expect("read");
        assert_eq!(n, 4, "expected 4 bytes written from `latest`");

        // Now peek the first byte the host wrote — should be 0xDE.
        let b0 = peek.call(&mut store, 100).expect("peek");
        assert_eq!(b0, 0xDE);
    }

    /// Missing key returns -1.
    #[test]
    fn wasmtime_chain_reflect_get_miss_returns_neg1() {
        let wat = r#"
            (module
                (import "env" "chain_reflect_get"
                    (func $reflect (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "no-such-key")
                (func (export "lookup") (result i32)
                    (call $reflect
                        (i32.const 0) (i32.const 11)
                        (i32.const 100) (i32.const 32)))
            )
        "#;
        let wasm = wat::parse_str(wat).unwrap();
        let mut vm = WasmtimeVm::new().unwrap();
        let handle = vm.compile(&wasm).expect("compile");

        let ctx = ContractCtx {
            reflect_ptr: &Fixture as *const dyn ReflectionView as *const (),
            reflect_call: dispatch_reflect_get::<dyn ReflectionView>,
        };
        let mut store = Store::new(&vm.engine, ctx);
        store.set_fuel(100_000).unwrap();
        let mut linker: Linker<ContractCtx> = Linker::new(&vm.engine);
        linker
            .func_wrap(
                "env",
                "chain_reflect_get",
                |mut caller: Caller<'_, ContractCtx>,
                 key_ptr: i32,
                 key_len: i32,
                 _out_ptr: i32,
                 _out_max_len: i32|
                 -> i32 {
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(m)) => m,
                        _ => return -3,
                    };
                    let data = mem.data(&caller);
                    let key = data
                        [key_ptr as usize..(key_ptr + key_len) as usize]
                        .to_vec();
                    let value = {
                        let c = caller.data();
                        unsafe { (c.reflect_call)(c.reflect_ptr, &key) }
                    };
                    match value {
                        Some(_) => 0,
                        None => -1,
                    }
                },
            )
            .unwrap();
        let instance = linker.instantiate(&mut store, &handle.module).unwrap();
        let lookup = instance
            .get_typed_func::<(), i32>(&mut store, "lookup")
            .unwrap();
        let r = lookup.call(&mut store, ()).expect("lookup");
        assert_eq!(r, -1);
    }
}
