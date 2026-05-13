# PyGrove Chain

A small proof-of-work blockchain that listens to itself.

It inherits Bitcoin's economic skeleton — 10-minute blocks, 2,016-block retargets, halvings every 210,000 blocks, a 21,000,000-coin hard cap — and adds a measured kind of self-awareness on top. The chain reads its own statistics from a dedicated subtree of its own state. Emission breathes with hashrate and adoption inside that information. The cryptography is post-quantum where it can be, agile where it can't. The design horizon is 127 years.

> **Status:** `pygrove-testnet-6` is in its 24-hour public-announcement window. The lockout drops at **2026-05-14 00:00:20 UTC**, after which block 1 can be mined. Until then, every node refuses to extend the chain — the source has been public, in this repo, for the entire window.
>
> Five earlier testnets (`-2`, `-3`, `-4`, `-5`) preceded this one. Testnet-5 actually launched briefly but hit a difficulty-retarget bug — `try_apply_block` had `if hdr.bits != st.bits { bail!() }`, forcing every block to the *initial* genesis bits forever and preventing ASERT-2D from firing. Blocks landed in milliseconds. Testnet-6 wires both the miner and the validator through the same `next_bits_from_parent()` helper so they cannot diverge; per-block bits are now computed from parent (bits, timestamp) and validated on submit.

## Table of contents

- [Where it lives](#where-it-lives)
- [Verifying the fair launch](#verifying-the-fair-launch)
- [What's distinctive](#whats-distinctive)
- [Operator safeties](#operator-safeties)
- [What's actually shipped](#whats-actually-shipped)
- [Cryptographic suite](#cryptographic-suite)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Genesis seed](#genesis-seed)
- [JSON-RPC surface](#json-rpc-surface)
- [Observability](#observability)
- [Mainnet readiness](#mainnet-readiness)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Where it lives

The sixth public testnet (`pygrove-testnet-6`) opens on **2026-05-14 00:00:20 UTC**. You can touch it at:

- **Wallet** — [str4w.com](https://str4w.com/), works on any phone or browser
- **Block explorer** — [str4w.com/explorer](https://str4w.com/explorer/), with a live launch-countdown banner until block 1 lands
- **Emission monitor** — [str4w.com/info](https://str4w.com/info/), zooming from one day out to one hundred and twenty-seven years
- **Windows desktop wallet** — `pygrove-gui.exe` from the [latest release](https://github.com/xjqcj357/pygrove-chain/releases/latest)
- **Windows full node** — `pygrove-node.exe` + `pygrove-cli.exe` from the [latest release](https://github.com/xjqcj357/pygrove-chain/releases/latest)
- **Linux full node** — `pygrove-node-linux-x86_64` + `pygrove-cli-linux-x86_64` from the [latest release](https://github.com/xjqcj357/pygrove-chain/releases/latest), or as a container image at `ghcr.io/xjqcj357/pygrove-chain:latest`
- **JSON-RPC** — `https://str4w.com/api/testnet/rpc`
- **Prometheus metrics** — `https://str4w.com/metrics` (height, genesis_offset_ms, mempool_size, block_reward_sat, finality height)

The same `pyg1...` address works on every client. Your secret-key file carries between them.

## Verifying the fair launch

Anyone can verify, from a clean clone, that this testnet was not premined.

```sh
git clone https://github.com/xjqcj357/pygrove-chain
cd pygrove-chain
cargo build --release --bin pygrove-node
./target/release/pygrove-node init
# prints something like:
# genesis: height=0 nonce=<N> hash=<32-byte hex>
```

The genesis hash is a pure function of the seed values in [`genesis.toml`](genesis.toml). Three independent properties make the launch credible:

The first is the **24-hour announce window.** `genesis_time_ms` is `2026-05-14 00:00:20 UTC`. Every node refuses to accept a block whose timestamp is earlier than that; the in-process miner refuses to even submit one. There is no path by which a peer-with-source can produce coin before the window closes.

The second is the **proof-of-no-prior-knowledge headline.** The genesis coinbase carries the hash of the Bitcoin block mined a few minutes before the testnet-6 seed was committed — `0000000000000000000054f816d4e95007fb5ddd141c999a43e9c4ee56aefca3`. Bitcoin's own difficulty is the timestamp authority: this seed could not have been constructed before that BTC block existed.

The third is the **byte-deterministic genesis.** Given the seed values, `pygrove-node init` is a pure function. The canonical genesis tip hash will be pinned in [RELEASES.md](RELEASES.md) when v0.5.0 is tagged so any auditor can compare their local build against the chain's claim.

Verify the live chain matches your local seed:

```sh
curl -sS https://str4w.com/api/testnet/rpc \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info","params":{}}'
```

The `tip_hash` field at height 0 must equal the hash you produced locally. While `genesis_offset_ms` is negative, the public chain is in lockout.

## What's distinctive

The protocol does five things you won't find together anywhere else.

The first is **the Accordion.** Two adaptive bellows — one tracking hashrate ratio period over period, the other tracking the count of unique sybil-guarded active addresses — modulate the halving schedule and difficulty around Bitcoin's curve. When both bellows are pumping, halvings arrive sooner and difficulty doesn't lag. When they deflate, halvings pause. At equilibrium it's pure Bitcoin.

The second is **the Reflection.** A dedicated `reflect/` subtree of the chain state holds rolling statistics — hashrate proxy, active addresses, fee density, emission rate — committed on every `apply_block`. Consensus reads them to compute the accordion. The WASM contract VM reads them via a `chain_reflect_get` host function (the `CHAIN_REFLECT(key)` opcode the whitepaper specifies). The chain learns from its own past.

The third is **the ETF of one.** The accordion is steered toward flat fees-per-active-address — a proxy for whether the median user finds the chain affordable. No oracles. The chain rebalances itself on every retarget against a basket whose only constituent is itself.

The fourth is **calendar emission.** Per-block reward is a delta against a wall-clock schedule, capped per block. Even when blocks land a hundred times faster than target during difficulty discovery, cumulative emission tracks the calendar. No premine optics, by construction. The math is pinned by a 210,000-block backtest digest (`921ebf27...`) so any future change to the emission curve flips the digest and fails CI.

The fifth is **crypto agility from block zero.** Every signature carries a one-byte algorithm tag. Every hash carries one too. The full post-quantum suite is wired today (Falcon-512, SLH-DSA-128s, BLS12-381 for finality aggregation, ML-DSA-65 slot reserved). An `UpgradeCrypto` governance transaction — gated by a k-of-N threshold signature once a `GovernanceConfig` is installed — activates new primitives at a future block height without forking. The chain is meant to outlive its first cryptosuite, and its second, and its third.

## Operator safeties

Testnet-2 exposed a **cadence-mismatch bug**: the economic adaptation layer (block reward minted per block) ran 5–6 orders of magnitude faster than the security stabilization layer (difficulty retarget every 2,016 blocks). At launch with hashrate above the implied target, half a million PYG could mint in the difficulty-discovery window before retarget caught up. Total cap held in aggregate; distribution was indistinguishable from a premine. Testnet-6 inherits the testnet-3 fix and stacks more on top:

1. **Calendar emission** — per-block reward is bounded by `min(calendar_remaining, epoch_reward, proportional_cap)`. Even when blocks land 100× faster than target during difficulty discovery, cumulative emission tracks the wall-clock schedule.
2. **ASERT-2D per-block retarget** — Bitcoin Cash's 2020 difficulty algorithm, ported. Difficulty adjusts continuously, not only every 2,016 blocks. Default τ = 2 days; bootstrap τ = 1 hour for the first 2,016 blocks while the discovery window settles.
3. **8% per-block bits clamp** — no matter what ASERT computes, the difficulty target cannot move by more than 8% in either direction in a single block. A single hashrate spike cannot instantly flatten the curve.
4. **25% per-block issuance slew rate** — the mined reward cannot change by more than 25% relative to the previous block's reward. Smooths the calendar-emission delta across hashrate transients.
5. **Bootstrap mode** for `height < 2,016` — caps the reward at 50% of the epoch baseline, runs ASERT with the 1-hour τ, and refuses to pay full coinbase until the chain has settled past the first retarget interval.
6. **Property-based fuzz invariants** — 1000+ random blocks per CI run, asserting non-negative balances, conservation (no inflation outside the calendar curve), and monotone nonces. Surfaces any future regression in `apply_block` that would print money.

Together these close the cadence mismatch: economic and security loops now run at the same per-block granularity, and the math is regression-tested under adversarial input.

## What's actually shipped

The whitepaper specifies the v1.0 protocol. The current testnet is honest about which parts are live.

**Live now:**
- Calendar emission with all five operator safeties above
- Bitcoin-curve skeleton (10-minute target, 2,016-block retargets, 210,000-block halvings, 21M cap)
- ASERT-2D per-block retarget with the bootstrap-mode τ switch
- Reflection subtree (`reflect/`) updated on every `apply_block` — per-block and `latest` records
- WASM contract VM via `wasmtime` 27 (behind `--features wasm`), with `chain_reflect_get` host function exposing the reflection subtree to contracts
- Signed transactions with full account state — Ed25519 + Blake3-XOF-512 are the default-on hot path; Falcon-512 wired and ready for `UpgradeCrypto` rotation
- **SLH-DSA-128s** (FIPS 205) wired via `fips205` for cold-governance / FIPS-profile signing — deterministic mode per spec
- **BLS12-381** wired via `blst` for BFT finality aggregation — N validator sigs collapse to a single 96-byte cert verified in one pairing check
- **k-of-N governance threshold signatures** — `UpgradeCrypto`, `RegisterAttestCoordinator`, `SetGovernance` all gated against a `GovernanceConfig` committed to `Subtree::Meta`. Bootstrap mode allows the first config install with an empty proof; subsequent rotations require threshold.
- **Genesis governance committee** — installable at chain birth via `initial_governance` in `genesis.toml` (Ed25519 placeholder today; HSM-backed SLH-DSA at mainnet)
- **`UpgradeCrypto` activation** at `target_height` writes an `ActiveCrypto` record to `Subtree::Meta` (the rotation actually fires, not just announces)
- Mempool with size-bounded admission
- Federated-attestation transaction surface (`AttestRound`) writing to the `attest/` subtree, with coordinator-authority registry per `job_id`
- DLA-shape pedigree variant (`AttestPedigree`) — supply-chain provenance with `lot_id` + CAGE code + supplier hash
- Mobile wallet at str4w.com (browser-based, `pyg1...` bech32 addresses)
- Windows desktop wallet (Slint GUI)
- Block explorer + emission monitor (str4w.com)
- JSON-RPC node, Linux + Windows binaries, Docker image
- `pygrove-cli` as a real JSON-RPC client (10 subcommands; no more stubs)
- `/metrics` Prometheus endpoint
- `ops/runbook.md` for chain halts / mempool flooding / mining incidents
- **RocksDB state-store backend** as an opt-in feature (`--features rocksdb`), byte-identical root with the in-memory `MemState`
- **BFT finality gadget** — committee, votes, plain + BLS-aggregated cert verifiers, fork-choice helper (libp2p transport pending)
- **P2P wire protocol** — peer-id format, 8 gossipsub topics, `P2pMessage` envelope, in-process broker (libp2p sockets pending)
- 24-hour fair-launch lockout enforced by every node before `genesis_time_ms`
- Long-form emission backtest with pinned canonical digest for cross-platform identity

**Plumbed but not yet wired:**
- ML-DSA-65 (FIPS 204 alternate signature, `sig_algo=4`)
- libp2p socket transport (the wire protocol is shipped; only the network integration crate is pending — `pygrove-p2p-libp2p`)
- HSM-backed governance keys (hardware procurement, not a code change; threshold-sig protocol is live in software today)
- `cargo build --features fips` profile excludes Ed25519 + Falcon from the dependency graph entirely; FIPS allowlist enforces SLH-DSA + ML-DSA + SHA3-512

**Not on testnet by design:**
- Real economic value. Mainnet ships when the deferred items (libp2p transport, external audits) close and the threat model has passed external review.

## Cryptographic suite

| Tag | Algorithm | Status | Use |
|---|---|---|---|
| 1 | **Falcon-512** (FN-DSA, NIST PQC lattice) | ✅ wired (`fn-dsa` 0.1) | Hot transaction signatures, post-quantum |
| 2 | **SLH-DSA-128s** (FIPS 205, SHAKE-128s) | ✅ wired (`fips205` 0.4) | Cold governance, threshold sigs, FIPS-profile |
| 3 | **Ed25519** | ✅ wired (`ed25519-dalek` 2) | Default hot signature (Phase A bringup) |
| 4 | ML-DSA-65 (FIPS 204) | ⬜ deferred | Alternative FIPS-profile signature |
| 5 | **BLS12-381 min-pk** | ✅ wired (`blst` 0.3) | BFT finality aggregation (single 96-byte cert) |

| Tag | Algorithm | Status |
|---|---|---|
| 1 | **Blake3-XOF-512** | ✅ live, header hashing |
| 2 | SHAKE256 with per-subtree domain tags | ⬜ deferred |
| 3 | **SHA3-512** | ✅ wired (FIPS-profile hash alternate) |

## Architecture

```
pygrove-chain/
├── crates/
│   ├── core/        block + tx types, canonical CBOR, domain-tagged hashing
│   ├── crypto/      algo dispatch (Ed25519, Falcon-512, SLH-DSA-128s, BLS12-381 all live)
│   ├── consensus/   PoW, ASERT-2D, accordion, calendar emission, reflection
│   ├── state/       state store with subtree segregation (MemState + RocksDB backends)
│   ├── vm/          WASM contract VM (wasmtime, behind --features wasm)
│   ├── finality/    BFT finality — committee, votes, plain + BLS-aggregated certs
│   ├── p2p/         P2P wire protocol — peer-id, gossipsub topics, in-process broker
│   ├── node/        pygrove-node + pygrove-cli binaries
│   └── gui/         pygrove-gui Slint desktop wallet
├── sim/             Python reference for accordion math + adversarial backtests
├── docs/
│   ├── whitepaper.md       full protocol spec
│   ├── sprint-plan.md      current sprint design ledger
│   └── mainnet-plan.md     port architecture, BFT design, audit plan, threat model
├── ops/
│   └── runbook.md          incident response playbook
├── web-mobile/      browser wallet, explorer, emission monitor (deployed to str4w.com)
├── genesis.toml     testnet-6 seed values
├── RELEASES.md      per-tag changelog
└── .github/workflows/
    ├── build.yml    fmt + clippy + build + test + ghcr image publish
    └── release.yml  Linux + Windows binaries on tag pushes (auto-attached to GitHub Release)
```

The state store segregates nine top-level subtrees:

| Subtree | Holds |
|---|---|
| `accounts` | Account balances, nonces, code refs, registered pubkeys |
| `code` | Deployed contract bytecode (the WASM module backing) |
| `storage` | Per-contract key-value storage |
| `meta` | Chain-level metadata — `governance` config, `upgrade_crypto` pending, `active_crypto` current, `attau/<job_id>` coordinator authorities |
| `reflect` | Rolling statistics — `block/<height>` per-block records, `latest` most-recent |
| `blocks` | Block bodies, indexed by height |
| `headers` | Block headers, indexed by hash |
| `witnesses` | Signatures + public keys, prunable by design |
| `attest` | Federated-learning round attestations (`AttestRound`) + supply-chain pedigree (`AttestPedigree`) |

`state_root` commits to *post-apply* state, not to signatures. Witnesses live in their own prunable subtree. A long-running archival node retains everything; a pruning peer discards `witnesses/` after some retention window without invalidating any header.

## Quick start

### Run a node from source (Linux / macOS)

```sh
git clone https://github.com/xjqcj357/pygrove-chain
cd pygrove-chain
cargo build --release --bin pygrove-node --bin pygrove-cli

# initialize state from genesis.toml (mines genesis, prints tip hash)
./target/release/pygrove-node init

# run with the in-process miner attached
./target/release/pygrove-node run --mine
# until 2026-05-14 00:00:20 UTC, you'll see "PRE-GENESIS: submit_block locked"
```

### Run a node from Docker

```sh
docker run -d \
  --name pygrove-node \
  --restart unless-stopped \
  -p 8545:8545 \
  -v pygrove-data:/var/lib/pygrove \
  ghcr.io/xjqcj357/pygrove-chain:latest
```

### Run a node on Windows

Download `pygrove-node.exe` and `pygrove-cli.exe` from [Releases](https://github.com/xjqcj357/pygrove-chain/releases/latest). They're self-contained — no MSVC runtime needed.

```powershell
.\pygrove-node.exe init
.\pygrove-node.exe run --mine
```

### Connect the CLI

```sh
# Default endpoint is http://localhost:8545/rpc; --rpc to override.
./target/release/pygrove-cli get-info
./target/release/pygrove-cli get-balance pyg1...
./target/release/pygrove-cli list-blocks --limit 20
./target/release/pygrove-cli emission-series --from 0 --to 10000 --step 100
./target/release/pygrove-cli --rpc https://str4w.com/api/testnet/rpc get-info
```

### Connect the Windows GUI wallet

Download `pygrove-gui.exe` from [Releases](https://github.com/xjqcj357/pygrove-chain/releases/latest). Self-contained Slint app. Paste any RPC endpoint — your local node, or `https://str4w.com/api/testnet/rpc` — and it'll show balances and submit transactions.

## Genesis seed

Pinned in [`genesis.toml`](genesis.toml) at the root of the repo:

```toml
chain_id              = "pygrove-testnet-6"
genesis_time_ms       = 1778716820000          # 2026-05-14 00:00:20 UTC
genesis_headline_hex  = "0000000000000000000054f816d4e95007fb5ddd141c999a43e9c4ee56aefca3"
                                               # ^ Latest BTC tip at testnet-6 seed time

initial_bits          = 0x1f00ffff             # laptop-mineable initial difficulty
target_block_time_ms  = 600000                 # 10 minutes
retarget_interval     = 2016
halving_interval_base = 210000
seconds_per_halving   = 126000000              # 4 years exactly
initial_reward_sat    = 5000000000             # 50 PYG

# Operator safeties
asert_tau_ms                    = 172800000    # 2 days
bootstrap_asert_tau_ms          = 3600000      # 1 hour
bootstrap_height                = 2016
bootstrap_reward_pct            = 50
max_reward_pct_change_per_block = 25
max_bits_pct_change_per_block   = 8

# Accordion params
accordion_epsilon       = 0.05
accordion_beta_h        = 0.5
accordion_beta_a        = 0.5
accordion_beta_s        = 0.25
stability_window_blocks = 2016

# Sybil guard for adoption bellow
sybil_dust_floor_sat    = 100000
sybil_min_age_blocks    = 2016
sybil_require_paid_fee  = true

# Crypto agility (default dispatch on signed txs)
sig_algo  = 1   # 1 = Falcon512  /  2 = SLH-DSA-128s  /  3 = Ed25519
                # 4 = ML-DSA-65 (deferred)  /  5 = BLS12-381 (finality only)
hash_algo = 1   # 1 = Blake3Xof512  /  3 = SHA3-512

initial_accounts = []   # no premine
initial_governance = [] # empty → bootstrap allows the first SetGovernance
```

## JSON-RPC surface

All requests POST to `/rpc` with a standard JSON-RPC 2.0 envelope.

| Method | Description |
|---|---|
| `get_info` | Chain id, height, tip hash, current bits, `genesis_offset_ms`, mempool size, current block reward |
| `get_template` | Block template for an external miner |
| `submit_block` | Submit a mined block (rejected if `now() < genesis_time_ms`) |
| `list_blocks` | Recent blocks, paginated |
| `get_block` | Full block body + header at a given height |
| `submit_tx` | Submit a CBOR-encoded `TxBody` + `Witness` |
| `submit_transfer` | Convenience helper for plain transfers |
| `get_balance` | Account balance for an address |
| `get_account` | Full account state (balance + nonce + code ref + pubkey) |
| `get_mempool` | Mempool size + tx hashes |
| `emission_series` | Replay emission curve over a height range, for the info-page chart |

The HTTP server also serves:
- `GET /` (block explorer HTML)
- `GET /healthz` (liveness probe)
- `GET /metrics` (Prometheus text format, see [Observability](#observability))

## Observability

The node exposes Prometheus-format metrics at `GET /metrics`. Default scrape:

```
# HELP pygrove_height current chain tip height
# TYPE pygrove_height gauge
pygrove_height{chain="pygrove-testnet-6"} 0

# HELP pygrove_genesis_offset_ms milliseconds past (or before, negative) genesis
# TYPE pygrove_genesis_offset_ms gauge
pygrove_genesis_offset_ms{chain="pygrove-testnet-6"} -84629875

# HELP pygrove_mempool_size pending transactions
# TYPE pygrove_mempool_size gauge
pygrove_mempool_size{chain="pygrove-testnet-6"} 0

# HELP pygrove_block_reward_sat current block reward in sat
# TYPE pygrove_block_reward_sat gauge
pygrove_block_reward_sat{chain="pygrove-testnet-6"} 5000000000

# HELP pygrove_finality_height highest BFT-finalized block
# TYPE pygrove_finality_height gauge
pygrove_finality_height{chain="pygrove-testnet-6"} 0
```

Operator playbook for chain halts, mempool flooding, mining incidents, and SLA-grade response is in [`ops/runbook.md`](ops/runbook.md).

## Mainnet readiness

Six gates close before mainnet:

| | Gate | Status |
|---|---|---|
| 1 | Calendar-emission inflation bug closed | ✅ |
| 2 | Operator safeties (ASERT-2D + 8% clamp + 25% slew + bootstrap + fuzz invariants) | ✅ |
| 3 | Falcon-512 actually wired | ✅ |
| 3b | SLH-DSA-128s actually wired | ✅ |
| 3c | BLS12-381 actually wired (finality aggregation) | ✅ |
| 4 | Real test coverage (cross-platform fixture identity, governance threshold roundtrip, fuzz invariants, long-form emission backtest digest pinned, BLS 5-of-5 + 3-of-5 roundtrips, P2P broker pub/sub) | ✅ |
| 4b | k-of-N governance threshold sigs enforced | ✅ |
| 4c | Production state-store backend (RocksDB) byte-identical with MemState | ✅ |
| 4d | Observability — `/metrics` endpoint + operator runbook | ✅ |
| 5 | libp2p P2P online | ⏳ wire protocol shipped in [`crates/p2p/`](crates/p2p/src/lib.rs); transport integration is the remaining gap |
| 6 | BFT finality gadget shipped | ✅ committee, votes, plain + BLS-aggregated certs in [`crates/finality/`](crates/finality/src/lib.rs) |

**Five of six gates fully closed.** The remaining one (libp2p transport) has the wire protocol shipped — only the socket-integration crate is pending. Mainnet launches when libp2p ships and an external audit signs off on the threat model.

## Roadmap

There isn't one.

Every item that lived on the original 90-day roadmap landed. The follow-up "deferred" list (SLH-DSA, BLS, HSM gov keys, libp2p) was attacked next and three of four landed. The remaining four risks flagged in external review (state-store, metrics, ops, genesis committee, fuzz, emission backtest) all landed in this sprint.

What replaces "the roadmap" is [`docs/mainnet-plan.md`](docs/mainnet-plan.md). Every change is now reviewed against it.

## Contributing

This is currently a single-author build. Issues and PRs are welcome but the bar is high: anything that touches consensus needs a Python-sim port and an adversarial-trace replay before it merges. See [`docs/mainnet-plan.md`](docs/mainnet-plan.md) for the design ledger PRs are evaluated against.

## License

Apache-2.0 for the source. CC BY 4.0 for the whitepaper.

Whitepaper at [`docs/whitepaper.md`](docs/whitepaper.md). Per-tag changelog at [`RELEASES.md`](RELEASES.md). Current sprint's design ledger at [`docs/sprint-plan.md`](docs/sprint-plan.md). Mainnet design and threat model at [`docs/mainnet-plan.md`](docs/mainnet-plan.md). Operator playbook at [`ops/runbook.md`](ops/runbook.md).
