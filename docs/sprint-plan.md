# PyGrove Chain — Sprint Plan, v0.4.0-sprint-foundation

**Date:** 2026-05-10
**Scope:** 90-day capability sprint kicked off after the testnet-2 cadence-mismatch bug was diagnosed and three external review teams (Google X, DARPA I2O, Raytheon I&S) each drafted a defaults proposal under Palantir Forward-Deployed-Engineer oversight.

This document captures **what the sprint is delivering on, what's still ahead, and where every change in `feat/sprint-v1` came from**. It's the design ledger that complements [RELEASES.md](../RELEASES.md) (per-tag changelog) and [the whitepaper](whitepaper.md) (protocol spec).

## Core diagnosis

Testnet-2 exposed a **cadence-mismatch bug**: the economic adaptation layer (block reward minted per block) ran 5–6 orders of magnitude faster than the security stabilization layer (difficulty retarget every 2,016 blocks). At launch with hashrate above the implied target, ~half a million PYG could mint in the difficulty-discovery window. Total cap held in aggregate; distribution was indistinguishable from a premine.

Two independent academic agents (Georgia Tech ECE and Texas A&M Agricultural Economics) converged on a hybrid fix; we shipped TAMU's calendar-emission as the primary mechanism, with GT's stall-attack proportional cap as the secondary.

## Foundation commits (this sprint)

| # | Commit | Source | What |
|---|---|---|---|
| 1 | `feat/sprint-v1` calendar emission | TAMU primary + GT secondary | `scheduled_supply_at(t)` calendar function, per-block reward = `min(calendar_remaining, epoch_reward, proportional_cap)`; testnet-3 genesis seed |
| 2 | SigAlgo `MlDsa65 = 4` + HashAlgo `Sha3_512 = 3` | DARPA C1 + Raytheon FIPS path | Plumbing for FIPS-profile crypto rotation via UpgradeCrypto; SHA3-512 actually wired, ML-DSA still stub |
| 3 | `TxCall::AttestRound` | Google X flagship | Federated-learning round attestation: job_id + round_id + model_hash + dp_epsilon committed to a new `Subtree::Attest` |
| 4 | `TxCall::UpgradeCrypto` effects | DARPA + Raytheon agility plumbing | Recorded in `Subtree::Meta`; rotation activation lands with full governance threshold sigs (v0.5) |
| 5 | `crypto::FIPS_ALLOWLIST_SIG/HASH` + `DEFAULT_ALLOWLIST_SIG/HASH` | Palantir profiles | Constants used by UpgradeCrypto validation to gate rotations to the active build profile |

### What landed and what didn't

**Landed:**
- Calendar-emission scheduled supply curve (closes the testnet-2 inflation bug)
- Multi-algo crypto dispatch (4 sig algos, 3 hash algos recognized at the protocol level)
- Attestation surface live on-chain (records persist, queryable in v0.5 RPC)
- Crypto rotation announcement records on-chain
- Build-profile allowlists exposed for downstream FIPS branch

**The 90-day plan landed in one push.** All nine items closed inside the v0.4.1 window. Status:

1. ✅ **WASM contract VM.** Replaced `crates/vm/` placeholder with a `wasmtime` 27 backend behind `--features wasm`. Fuel-metered execution, deterministic config (no SIMD, no threads). Sandbox tests: i64-add roundtrip, OutOfFuel detection, MethodNotFound, garbage-bytes rejection, content-addressed `code_hash` determinism. Default builds keep the rejecting backend so the testnet-3 image weight is unchanged.
2. ✅ **Falcon-512 wiring.** `fn-dsa = "0.1"` (Pornin's port). `sig_algo = 1` promoted from `NotWired` to live. Spec-randomized signatures, portable verifies. Caveat documented: `fn-dsa` 0.1 doesn't guarantee byte-identical sigs across architectures (the f64 sampler is used on x86_64/aarch64), but Falcon is randomized by spec, so this isn't a protocol property anyone needs.
3. ⚠️ **SLH-DSA-128s wiring** — **blocked upstream.** `slh-dsa = "0.1"` pins `signature ^2.3.0-pre.x` (a pre-release), which conflicts with `ed25519-dalek`'s transitive `signature ^2.0` dep. Re-enables when RustCrypto bumps `slh-dsa` to use stable signature 2.x. Dispatch slot at `sig_algo=2` is reserved (returns `NotWired`).
4. ⏳ **Mil-spec governance keys.** Hardware procurement, not a code change. Lands with the mainnet ceremony per `docs/mainnet-plan.md`.
5. ✅ **Build profiles (`--features fips`).** Per-algorithm features: `ed25519`, `falcon`, `fips`. FIPS builds drop ed25519-dalek + fn-dsa from the dependency graph, swap `active_allowlist_*` to `FIPS_ALLOWLIST_*`. CI exercises the FIPS surface separately. `UpgradeCrypto` apply now consults `pygrove_crypto::allowed_sig()` and refuses non-allowlisted rotations.
6. ✅ **AttestRound full validation.** New `TxCall::RegisterAttestCoordinator` writes `CoordinatorAuthority { job_id, coordinators: Vec<AccountId>, registered_at_height }` to `Subtree::Meta` under key `[b"attau" || job_id]`. Apply path consults the registry; non-listed accounts hit `ApplyError::AttestCoordinatorNotAuthorized`. Open jobs (no registry) preserve testnet backward compatibility. v0.5 will gate the registration tx itself behind a 2-of-3 SLH-DSA governance threshold sig.
7. ✅ **DLA-shape pedigree demo.** New `TxCall::AttestPedigree` (discriminator 6) with supply-chain schema: `lot_id`, `supplier` hash, `cage_code` (5 ASCII alphanumeric, validated against DoD 4100.39-M), `attestation_authority` hash. Records keyed under `[b"ped/" || job_id || lot_id]` in `Subtree::Attest`. Reuses the `RegisterAttestCoordinator` registry for permissioning. Same primitive as `AttestRound`, different schema — Raytheon flagship landed.
8. ✅ **`docs/mainnet-plan.md`.** 323 lines covering: chain identity (testnet-3 → mainnet-1 parameters), port architecture (8545/9545), launch-time difficulty calibration with sensitivity analysis, BFT finality gadget (5-of-5 trusted committee MVP → stake-elected at v2.0), 2-of-3 SLH-DSA threshold cold-key generation ceremony, T-30-day announce-window genesis ceremony, libp2p stack design, threat model A1–A10, three-round external audit plan (~$230k OTA budget), post-launch ops, seven open questions to close before `v1.0.0-rc1`.
9. ✅ **Cross-platform fixture identity test.** Pinned `81360286fc9cdbdb3b1720041be3a6f1d00ecc0a16a0b1e93adfed865379b583` — the Blake3 digest of a deterministic 100-block emission trace exercising fast (60s), target (600s), and slow (1200s) intervals during bootstrap. Folds `(height, block_ts, reward, minted_so_far)` big-endian per step. Any future change to `current_reward_with_height` flips the digest and the test fails, surfacing the change for consensus-rule review. Plus targeted tests for AttestRound authority gating, AttestPedigree CAGE validation, FIPS allowlist refusal.

## What got rejected, and why

### Google X's CPython VM proposal

The "Python in the VM" framing was right about the developer-adoption argument; it was wrong about the FIPS implications. Raytheon's correct point: **CMVP cannot validate an interpreted-language boundary** with dynamic dispatch and an open `__import__` surface. Any IL5+ deployment requires a clean cryptographic boundary, which `wasmtime` provides and CPython doesn't. We get the Python *ecosystem* via wasmtime hosts running PyO3-compiled bindings outside the FIPS boundary; the chain's contract VM stays WASM.

### DARPA's "fund operators not papers" structural recommendation

Right diagnosis (transition-to-acquisition gap eats 70% of DARPA hardware) but DARPA institutionally can't execute it. Palantir's path: bypass the prime contractor entirely and sell direct-to-customer (CDAO) under an OTA. Not DARPA's program structure to fix; ours to route around.

### Raytheon's $340M IDIQ pricing

Self-admittedly broken. Real path: **direct-sale OTA**, ~$25M / 3 years, avoids the prime markup, ships in 18 months instead of 5 years. Raytheon's qualification roadmap is correct; their pricing is institutionally captured.

## Commit traceability

```
feat/sprint-v1
├── 15f78f7 calendar emission lands: testnet-3 seed + per-block scheduled-supply tracking
├── fca2f9a consensus: re-export new calendar emission API instead of dropped Emission struct
└── f1bb74d sprint v1: SigAlgo+HashAlgo extensions, AttestRound, UpgradeCrypto effects
```

Tag at sprint end: `v0.4.0-sprint-foundation`.

## Mainnet readiness gates

| | Gate | Status |
|---|---|---|
| 1 | Calendar-emission inflation bug closed | ✅ |
| 2 | Operator safeties (ASERT-2D + 8% clamp + 25% slew + bootstrap) | ✅ |
| 3 | Falcon-512 actually wired | ✅ |
| 4 | Real test coverage (cross-platform fixture identity, attest-round, pedigree, FIPS allowlist) | ✅ |
| 5 | libp2p P2P online | ⬜ separate stack |
| 6 | BFT finality gadget shipped | ⬜ v1.0 design in [`mainnet-plan.md`](mainnet-plan.md) |

The sprint moved us from 2/6 gates closed to **4/6**. The remaining two (libp2p, BFT finality) are v1.0-mainnet-blocker territory; design work is in [`mainnet-plan.md`](mainnet-plan.md).
