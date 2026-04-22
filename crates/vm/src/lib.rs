//! PyGrove Chain VM.
//!
//! Planned for v1.2: CPython embedded via PyO3, RestrictedPython sandbox, gas metered by
//! CPython bytecode opcode count via `sys.settrace(..., opcode=True)`. Contracts read
//! the Reflection subtree via a `CHAIN_REFLECT` opcode and may invoke `VDF_TICK` for
//! physical-time-enforced gas units once the finalizer VDF is live.
//!
//! v0.1: module stub. No symbols yet beyond the placeholder below.

pub const PLANNED: &str = "pygrove-vm: v1.2 — CPython + RestrictedPython + opcode gas";
