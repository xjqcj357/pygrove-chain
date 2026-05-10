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

**Still on the 90-day plan, in the recommended Palantir order:**

1. **WASM contract VM.** Replace the `crates/vm/` placeholder with `wasmtime` + a small ABI for hash + sig + ed25519 + np-array reductions. **Raytheon's recommendation, accepted by Palantir over Google X's CPython pitch — CMVP can't validate interpreted Python in the boundary.** ETA: 4 weeks.
2. **DARPA C1: actual Falcon-512 wiring.** Pin `fn-dsa` integer-sampler crate, byte-identical sigs across Linux/Windows. Promotes `sig_algo = 1` from `NotWired` to live. ETA: 2 weeks.
3. **DARPA C1.b: SLH-DSA-128s wiring.** Cold governance keys; gates the threshold-sig validation step on UpgradeCrypto. ETA: 1 week after DARPA C1.
4. **Mil-spec governance keys (Raytheon C3).** 2-of-3 SLH-DSA threshold cold key with HSM backing for the canonical operator. ETA: 4 weeks (after #3).
5. **Build profiles (`cargo build --features fips`).** Cargo feature flag system selecting the FIPS allowlist as the canonical algo set. Prerequisite for FedRAMP / FIPS-140-3 module submission. ETA: 1 week.
6. **AttestRound full validation.** Coordinator authority registry for FL jobs; today any account can attest, v0.5 enforces governance-key endorsement of coordinator addresses per `job_id`. ETA: 2 weeks.
7. **DLA-shape demo.** Component-pedigree variant of AttestRound: replace ML-specific fields with supply-chain provenance fields (lot_id, supplier, cage_code, attestation_authority). Same primitive, different schema. ETA: 1 week (after #6). Raytheon flagship.
8. **`docs/mainnet-plan.md`.** Full mainnet-launch design covering: mainnet RPC port (9545), launch-time difficulty calibration to expected hashrate, BFT finality gadget design (5-of-5 trusted committee MVP, swapping to stake-elected committee at v2.0). ETA: 2 weeks of writing while #1–#7 run in parallel.
9. **Tests.** Calendar-emission cross-platform fixture identity, attest-round round-trip, upgrade-crypto rotation activation, FIPS-profile algo allowlist enforcement. ETA: ongoing.

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

## Mainnet readiness gates (unchanged from RELEASES.md)

- Falcon-512 wired (#2 above)
- Audit gap #1: real test coverage (#9 above)
- Audit gap #4: reorg path / fork-choice rule (BFT finality gadget; v1.0 design)
- libp2p P2P online (separate stack)
- Mainnet genesis ceremony (after `docs/mainnet-plan.md` lands)
- Cold governance keys generated (#3 + #4)

The sprint moves us from 2/6 gates closed to 4/6 gates closed if all 90-day items ship. The remaining 2 (P2P, BFT finality) are v1.0-mainnet-blocker territory; not sprint scope.
