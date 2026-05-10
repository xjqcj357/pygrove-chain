# PyGrove Chain — Mainnet Plan

**Status:** draft, sprint-foundation+1.
**Authors:** Palantir senior dev oversight, with input from DARPA I2O, Raytheon I&S, Google X review teams.
**Audience:** anyone running, integrating, or auditing the v1.0 mainnet launch.
**Companion documents:** [whitepaper.md](whitepaper.md) (protocol spec), [sprint-plan.md](sprint-plan.md) (current sprint design ledger), [../RELEASES.md](../RELEASES.md) (per-tag changelog).

This document specifies how PyGrove Chain transitions from `pygrove-testnet-3` to `pygrove-mainnet-1`. Every parameter, port, key, and bring-up step that has to be settled before the genesis-coinbase BTC headline is committed is enumerated here.

## Table of contents

1. [Mainnet readiness gates](#mainnet-readiness-gates)
2. [Network identity](#network-identity)
3. [Port architecture](#port-architecture)
4. [Launch-time difficulty calibration](#launch-time-difficulty-calibration)
5. [BFT finality gadget](#bft-finality-gadget)
6. [Cold governance keys](#cold-governance-keys)
7. [Genesis ceremony](#genesis-ceremony)
8. [P2P layer](#p2p-layer)
9. [Threat model](#threat-model)
10. [External review](#external-review)
11. [Post-launch ops](#post-launch-ops)
12. [Open questions](#open-questions)

## Mainnet readiness gates

Six gates have to close before mainnet:

| Gate | Status | Owner | Plan |
|---|---|---|---|
| 1. Calendar-emission inflation bug closed | ✅ shipped in v0.4.0 | TAMU + GT | `crates/consensus/src/emission.rs` — `scheduled_supply_at()` + `current_reward()`. Fixture identity tests under #9 below. |
| 2. Operator safeties (ASERT-2D + 8% clamp + 25% slew + bootstrap) | ✅ shipped in v0.4.0 | Palantir | `crates/consensus/src/asert.rs`. Activated in genesis.toml via `asert_tau_ms`, `bootstrap_*`, `max_*_pct_change_per_block`. |
| 3. Falcon-512 actually wired | ✅ shipped in v0.4.1 (sprint-foundation+1) | DARPA C1 | `crates/crypto/src/falcon.rs` via `fn-dsa = "0.1"`. Activated by an `UpgradeCrypto` tx from testnet → mainnet. |
| 4. Real test coverage | ⬜ in flight | All | Calendar-emission cross-platform identity, attest-round round-trip, upgrade-crypto rotation activation, FIPS-profile algo allowlist enforcement. See [#external-review](#external-review). |
| 5. libp2p P2P online | ⬜ separate stack | TBD | Section [P2P layer](#p2p-layer) below. |
| 6. BFT finality gadget shipped | ⬜ v1.0 design | Palantir + DARPA | Section [BFT finality gadget](#bft-finality-gadget) below. |

Mainnet launches when all six are closed and an external review has signed off on the threat model.

## Network identity

| Parameter | testnet-3 | mainnet-1 |
|---|---|---|
| `chain_id` | `pygrove-testnet-3` | `pygrove-mainnet-1` |
| `genesis_time_ms` | `1778468929000` (2026-05-11 03:08:49 UTC) | TBD — set 30 days before launch, with a 30-day public announce window (longer than testnet's 24h) |
| `genesis_headline_hex` | BTC block 948713 | BTC block mined within 1 hour of `genesis.toml` commit |
| `initial_bits` | `0x1f00ffff` (laptop-mineable) | calibrated to expected hashrate (see [Launch-time difficulty calibration](#launch-time-difficulty-calibration)) |
| `initial_reward_sat` | `5_000_000_000` (50 PYG) | unchanged (Bitcoin parity) |
| `target_block_time_ms` | `600000` (10 min) | unchanged |
| `retarget_interval` | `2016` | unchanged |
| `halving_interval_base` | `210000` | unchanged |
| `seconds_per_halving` | `126_000_000` (4 years) | unchanged |
| `sig_algo` | 1 (Falcon-512) | 1 (Falcon-512) |
| `hash_algo` | 1 (Blake3-XOF-512) | 1 (Blake3-XOF-512) |
| `governance_pubkey_hex` | `""` (placeholder) | committed: 2-of-3 SLH-DSA-128s threshold pubkey (see [Cold governance keys](#cold-governance-keys)) |
| `initial_accounts` | `[]` (no premine) | `[]` (no premine) |

The address scheme stays `pyg1...` bech32m. The same testnet secret-key files do **not** carry over to mainnet — testnet keys cannot accidentally sign a valid mainnet transaction because `chain_id` is part of every transaction's signing hash.

## Port architecture

| Service | testnet | mainnet |
|---|---|---|
| JSON-RPC | `8545` | `9545` |
| P2P (libp2p) | `8546` | `9546` |
| Metrics (Prometheus) | `8547` | `9547` |

Both networks can run on the same host. The `genesis-node` Vultr deployment will move from a single-port single-network model to a two-container model post-launch:

- `pygrove-node-testnet` — bound to `:8545`, mounted at `/var/lib/pygrove-testnet`, image `ghcr.io/xjqcj357/pygrove-chain:latest`, genesis `genesis-testnet-3.toml`.
- `pygrove-node-mainnet` — bound to `:9545`, mounted at `/var/lib/pygrove-mainnet`, image `ghcr.io/xjqcj357/pygrove-chain:vX.Y.Z`, genesis `genesis-mainnet-1.toml`.

The reverse-proxy (akiyafinder-frontend nginx) maps:

- `https://str4w.com/api/testnet/rpc` → `pygrove-node-testnet:8545/rpc`
- `https://str4w.com/api/mainnet/rpc` → `pygrove-node-mainnet:9545/rpc`

The mobile wallet at `https://str4w.com/` already has a chain selector wired to `localStorage` — flipping mainnet on at the UI is one config change.

## Launch-time difficulty calibration

Testnet ships with `initial_bits = 0x1f00ffff` so a laptop with one core can mine genesis in seconds. Mainnet cannot: the bootstrap window has to be hard enough that a single curious laptop cannot dominate the chain for the first 2,016 blocks (the bootstrap window).

### The calibration target

We want **expected block time at launch ≈ 10 minutes**, given an honest-network estimate of `H_expected` hashes/sec on day 1.

Per-block hash work expected = `target_block_time_ms / 1000 × H_expected`. Set `initial_bits` so `target_from_bits(initial_bits)` corresponds to that work.

### Honest-network estimate

For mainnet launch, plan for `H_expected` in the range `[10⁶, 10⁹]` hashes/sec — i.e., 1 MH/s to 1 GH/s. That bracket assumes:

- 50–500 GPU miners on day 1 (rough analog of low-end altcoin launches)
- Each miner running `pygrove-node --mine` against the simple Blake3-XOF-512 puzzle, ~10⁵ H/s/GPU before any optimized kernel
- A handful of pool-scale operators (10⁶–10⁷ H/s each) testing capacity

Pick `H_expected = 10⁸` as the median; `initial_bits = 0x1d7fffff` (ballpark) gets us to a 10-minute first block at that hashrate. The bootstrap window's tighter ASERT τ (1 hour vs. 2 days) catches under- or over-shoots within the first 6 blocks.

### Cross-check against the testnet-3 trace

By the time the calibration is finalized, we'll have ≥ 30 days of testnet-3 hashrate data. The actual `H_observed` from testnet-3 — even though it's at toy difficulty — gives a within-population variance estimate that anchors the mainnet `H_expected` better than guessing.

### Failure mode

If `H_expected` is off by an order of magnitude high, the first block lands in 60 seconds instead of 10 minutes. Calendar emission caps the over-issuance (per-block reward shrinks to keep cumulative supply on the wall-clock curve), so the inflation tail is bounded. ASERT catches up within 6 blocks. No protocol parameters need to change.

If `H_expected` is off by an order of magnitude low, the first block lands in 100 minutes. Annoying for early miners but harmless. ASERT corrects.

### Concrete deliverable

`docs/mainnet-calibration.md` (separate document) with:

- Empirical hashrate distribution from the testnet-3 trace
- Sensitivity analysis on `initial_bits` ± 3 orders of magnitude
- The exact `initial_bits` value for `genesis-mainnet-1.toml`, signed by the cold governance keys at the moment `genesis_time_ms` is committed

## BFT finality gadget

Bitcoin's "finality" is probabilistic: 6 confirmations means the honest chain has out-paced any private fork by 6×, so the cost of reverting is 6× the block-reward bounty. PyGrove inherits this for mining but adds a **BFT finality gadget** on top so a confirmed transaction is irreversible after a single round, not 60 minutes.

### Design (v1.0 MVP)

A 5-of-5 signed-trusted-committee finality gadget:

- 5 fixed validator keys, committed in the genesis governance metadata.
- Every 6 blocks (~60 minutes nominal), each validator broadcasts a BLS-aggregated signature over the height-6n header hash.
- 5-of-5 quorum is the **finality threshold**. Once observed, the node refuses to reorg below that height.
- Validators are run by separate institutions: Palantir (genesis operator), one TBD academic partner (TAMU?), one infra-partner (Vultr or equivalent), one watchtower (community, non-stake), one "circuit breaker" (programmatically ratifies the longest-PoW chain unless it conflicts with the prior 4).

A 5-of-5 quorum means any single validator going offline halts finality but doesn't halt mining — reorg-back-to-quorum is bounded by ASERT plus the 8% clamp.

### Design (v2.0)

Replace the trusted committee with a stake-elected committee of size N, where stake is bonded PYG locked for ≥ 1 year. Slashing for double-signing is automatic. Same 5-block finality interval; same aggregation primitive (BLS).

### Why a separate gadget vs. in-band consensus

PoW alone gives probabilistic finality. Tendermint-style BFT alone gives deterministic finality but requires committee election upfront. We want both: PoW for permissionless block production + BFT for fast deterministic finality on the resulting chain. The gadget reads the PoW chain's longest tip, doesn't replace it. Same architecture as Ethereum's Casper FFG (pre-merge); same architecture as Cosmos Polkadot finalization.

### Implementation cost

- ~2,000 lines of Rust (committee state, signature aggregation via `blst`, RPC method `submit_finalization`, fork-choice rule extension)
- 2 weeks of development for the MVP
- 2 weeks of testing (committee outage scenarios, fork conflicts, upgrade-crypto-on-finality-keys)

Lands as `crates/finality/`. The fork-choice rule in `crates/consensus/src/forkchoice.rs` (currently absent — single-node deployment) gains a `finalized_height: u64` field that bounds reorg depth.

## Cold governance keys

The `governance_pubkey_hex` field in genesis commits to a 2-of-3 SLH-DSA-128s threshold public key.

### Generation ceremony

- 3 SLH-DSA-128s keypairs generated on 3 air-gapped machines, each in a separate physical location.
- Secret-key shares stored in HSMs (YubiHSM 2 minimum; Thales Luna for IL5+).
- Public keys aggregated to a single threshold pubkey via Shamir-style recombination (or a CHARM-Crypto threshold variant — design choice deferred to the SLH-DSA-128s wiring sprint).
- Witnessed by 3 separate parties; each signs an attestation of the keygen log.
- Attestation logs stored at `governance/keygen-log-mainnet-1.txt`, public after launch.

### Authorization scope

A 2-of-3 governance signature is required for:

- `UpgradeCrypto` transactions (rotating sig_algo or hash_algo)
- BFT finality committee membership changes (until v2.0 swaps to stake-elected)
- Coordinator authority registry updates for `AttestRound` (per-`job_id`)
- DLA-shape supply-chain provenance attestation authority registry

A 2-of-3 governance signature is **not** required for:

- Routine block production (PoW alone)
- Routine transactions (Falcon-512 hot keys per account)
- Mempool admission (network policy, not consensus)

### Recovery

If 2 of 3 governance shares are compromised (or lost), the chain has no recovery path — `UpgradeCrypto` cannot be exercised, and the fixed v1.0 protocol must run as-is. This is by design: governance is a brake, not a steering wheel. v2.0 will introduce stake-elected committee replacement.

## Genesis ceremony

### Sequence

| T | Action |
|---|---|
| T-30 days | `genesis-mainnet-1.toml` committed with `genesis_time_ms` set to T+0. `governance_pubkey_hex` filled in. `initial_bits` finalized per the calibration above. Tag `v1.0.0-rc1`. Public announcement. |
| T-30 days to T-7 days | Public review window. Anyone can clone, build, and `pygrove-node init` to reproduce the genesis tip hash. |
| T-7 days | If no critical issues, tag `v1.0.0`. The container image at `ghcr.io/xjqcj357/pygrove-chain:v1.0.0` is the canonical mainnet binary. |
| T-1 hour | The BTC headline is locked: the most recent BTC tip at T-1h is committed to `genesis_headline_hex`. **This is the proof-of-no-prior-knowledge slot.** |
| T+0 | Lockout drops. Block 1 can be mined. |
| T+1 hour | First retarget arrives if hashrate matches `H_expected`. ASERT begins applying. |
| T+2 weeks | Bootstrap window ends at height 2,016. Full coinbase reward payable. |

### Reproducibility

The genesis ceremony is **byte-deterministic**: given the seed values in `genesis.toml`, `pygrove-node init` is a pure function of those values. Any clone of the repo, on any platform, must produce the same genesis tip hash. Witnesses to the ceremony — anyone who runs `pygrove-node init` during the announce window and reports their tip hash — accumulate evidence that no premined accounts were spliced in.

CI test (lands with #9, calendar-emission cross-platform identity): on every PR, build the genesis from `genesis.toml`, assert the tip hash equals a fixed expected value committed in `tests/fixtures/genesis-mainnet-1.tip-hash`. Any change to genesis seed values requires updating that fixture in the same PR.

## P2P layer

### Stack

`libp2p-rs` 0.55 with the following modules:

- `kad-dht` for peer discovery
- `gossipsub` for block + tx propagation
- `noise` + `yamux` for transport (Noise XX handshake, multiplexed streams)
- `mdns` for local-network bootstrap
- `identify` for peer metadata exchange

### Bootstrap

- 5 hardcoded bootstrap nodes shipped in `genesis.toml` as `bootstrap_peers`. Same 5 institutions as the BFT finality committee, with separate keys.
- Each bootstrap node maintains an open `relay-v2` circuit so NAT'd peers can join without UPnP.

### Transport

- TCP + WebSocket (port `9546` for mainnet, `8546` for testnet).
- QUIC reserved for v1.1 (currently `libp2p-quic` doesn't have stable BLS-aggregation interop).

### Block propagation

- Compact block-relay protocol (similar to BIP 152, adapted for our `state_root`-anchored format).
- Tx mempool gossip: small-mesh (D=4, D_lo=2, D_hi=8) gossipsub, 1.5MB max per gossip message.

### Implementation cost

- ~3,000 lines of Rust
- 3 weeks of development
- 2 weeks of testing (peer-discovery scenarios, partition recovery, eclipse-attack mitigation)

Lands as `crates/p2p/`.

## Threat model

The threat model adopted from DARPA I2O's Test Resource Management Center input:

| Threat | Severity | Mitigation in v1.0 |
|---|---|---|
| **A1. 51% hashrate attack** | Critical | BFT finality gadget bounds reorg depth to last finalized header (≤ 6 blocks ≤ 60 min). |
| **A2. Selfish mining** | Medium | ASERT-2D + 8% clamp keeps difficulty responsive enough that selfish mining margin shrinks to ≤ 1.5% advantage at honest-mining-fraction ≥ 51%. |
| **A3. Eclipse attack** | High | 5 hardcoded bootstrap peers; mandatory diversity check (refuse to connect to ≥ 3 peers in same /24). |
| **A4. Quantum signature forgery** | Long-horizon | Falcon-512 hot keys (lattice — Shor-resistant); SLH-DSA-128s cold keys (hash-based — Grover-resistant); UpgradeCrypto rotation path keeps the chain ahead of NIST PQC milestones. |
| **A5. Sybil attack on adoption bellow** | Medium | Sybil guard: dust floor (`sybil_dust_floor_sat = 100_000`) + age gate (`sybil_min_age_blocks = 2016`) + paid-fee requirement. Cost of fake address > value of bellow inflation. |
| **A6. Calendar-emission stall attack** | Critical | GT's proportional cap: per-block reward bounded by `(elapsed_ms / target_block_time_ms) × epoch_reward`. Stalls don't accumulate emission. |
| **A7. Genesis seed substitution** | Critical | Reproducible build + 30-day announce window + BTC headline binding. Witnesses verify on launch day. |
| **A8. Governance key compromise** | High | 2-of-3 threshold, air-gapped HSM custody, 3 separate physical locations. No single-key recovery path (by design). |
| **A9. Long-range attack** | Medium | BFT finality gadget pins the chain at every finalized height. Pre-finality reorg is bounded; post-finality reorg is impossible without compromising the finality committee. |
| **A10. Coordinator authority spoofing on AttestRound** | Medium | Coordinator authority registry per `job_id`, governance-signed (lands with roadmap #6). |

## External review

Three review rounds before mainnet:

### Round 1: protocol audit (T-90 days)

- Trail of Bits or NCC Group reviews the consensus crate (`crates/consensus/`), the crypto crate (`crates/crypto/`), and the state-apply crate (`crates/state/src/apply.rs`).
- Scope: cadence-mismatch closure, ASERT correctness, Falcon-512 + SLH-DSA-128s wiring, coinbase math.
- Budget: ~$120k.

### Round 2: BFT finality + P2P audit (T-60 days)

- Same firm or a complement (NCC Group + Trail of Bits split).
- Scope: BFT finality gadget, libp2p integration, fork-choice rule, eclipse-attack resistance.
- Budget: ~$80k.

### Round 3: Threat-model review (T-30 days)

- Internal Palantir red team plus DARPA I2O TRMC observer (no funding, observational only).
- Scope: A1–A10 above, plus open-question items below.
- Budget: ~$30k.

Total external-review budget: ~$230k. Funded directly (OTA path), not via prime contractor.

## Post-launch ops

### Monitoring

- Prometheus scrape on `:9547`, dashboard on `https://str4w.com/info/`.
- Alert rules in `ops/alerts.yml`:
  - Block time > 30 min (any)
  - Hashrate drop > 80% over 1 hour
  - BFT finality stalled > 2 hours
  - Mempool size > 10,000 txs

### Incident response

- Runbook at `ops/runbook.md`.
- Severity tiers: SEV-0 (chain halted), SEV-1 (BFT finality stalled), SEV-2 (mempool flooded), SEV-3 (RPC degraded).
- On-call rotation: 3-person, 1-week shifts. Initial roster: Palantir + 2 community.

### Software updates

- Backwards-compatible bug fixes ship as `v1.0.x`. No `UpgradeCrypto` required.
- Protocol parameter changes (new ASERT τ, new bootstrap_height, etc.) ship as `v1.1.0+` and require an `UpgradeCrypto`-style governance announcement (gated by 2-of-3 SLH-DSA threshold).
- Security patches ship under embargo: 14-day private disclosure to validator operators, then public release.

### Mainnet decommissioning

If the threat model fails post-launch (e.g., a critical bug requires a hard fork that breaks the calendar-emission contract):

- Halt mining via the BFT finality gadget refusing to finalize.
- Tag a `v1.0.x-EOL` release with the exact halt height committed in `governance/eol.toml`.
- Drain accounts to a v2 chain via a one-shot account-state migration tx.

This is a worst-case. The intent is for v1.0 to run unmodified for the full 127-year design horizon.

## Open questions

The list below tracks unresolved design decisions. Each must close before `v1.0.0-rc1`.

1. **Threshold-signature scheme for governance.** Shamir secret sharing on SLH-DSA private keys vs. CHARM-Crypto threshold variant. Tradeoff: Shamir is conceptually simple but recombination requires assembling the full key in memory; CHARM-style keeps shares isolated but is less battle-tested. Decision deadline: T-90 days.
2. **BFT finality committee composition.** Five fixed institutions are listed above as candidates. The actual list, with public keys and operator agreements, has to be settled at T-30 days.
3. **WASM contract VM ABI.** Do we expose `CHAIN_REFLECT` directly to contracts, or wrap it in a higher-level "chain stats" host function? This is a v1.1 question but affects v1.0's contract-deployment surface (`crates/state/src/subtrees.rs::Code`).
4. **Stake mechanism for v2.0 stake-elected validators.** Bonded PYG locked for ≥ 1 year is the strawman. Specifics (slashing curve, withdrawal queue, validator entry/exit cadence) deferred to v2.0 design doc.
5. **AttestRound coordinator-authority registry storage.** Per-`job_id` authority is recorded in `Subtree::Meta` today as a stub. The mainnet form is a per-`job_id` permissioned set, settable by 2-of-3 governance. Schema in roadmap #6.
6. **Mainnet validator economics.** Block reward (50 PYG → halving curve) is fixed. BFT finality validators in v1.0 are not paid; v2.0 stake-elected validators receive a slice of the per-block reward. Slice-size TBD; strawman is 5%.
7. **Mainnet RPC endpoint hardening.** Public `https://str4w.com/api/mainnet/rpc` will see DDoS at launch. WAF rules + per-IP rate limit + Cloudflare in front. Specifics in `ops/rpc-hardening.md`.

---

*This document evolves as the sprint advances. Every change is a PR. Every PR is reviewed by Palantir oversight before merge.*
