# PyGrove Chain

A small proof-of-work blockchain that listens to itself.

It inherits Bitcoin's economic skeleton — 10-minute blocks, 2,016-block retargets, halvings every 210,000 blocks, a 21,000,000-coin hard cap — and adds a measured kind of self-awareness on top. The chain reads its own statistics from a dedicated subtree of its own state. Emission breathes with hashrate and adoption inside that information. The cryptography is post-quantum where it can be, agile where it can't. The design horizon is 127 years.

> **Status:** `pygrove-testnet-4` is in its 24-hour public-announcement window. The lockout drops at **2026-05-12 01:03:26 UTC**, after which block 1 can be mined. Until then, every node refuses to extend the chain — the source has been public, in this repo, for the entire window. (Testnet-3 was retired pre-launch to roll in the v0.5 sprint: SLH-DSA, BLS aggregation, governance threshold sigs, the WASM VM host fn, and the P2P wire protocol.)

## Table of contents

- [Where it lives](#where-it-lives)
- [Verifying the fair launch](#verifying-the-fair-launch)
- [What's distinctive](#whats-distinctive)
- [Operator safeties](#operator-safeties)
- [What's actually shipped](#whats-actually-shipped)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Genesis seed](#genesis-seed)
- [JSON-RPC surface](#json-rpc-surface)
- [Roadmap](#roadmap)
- [Mainnet readiness](#mainnet-readiness)
- [Contributing](#contributing)
- [License](#license)

## Where it lives

The fourth public testnet (`pygrove-testnet-4`) opens on **2026-05-12 01:03:26 UTC**. You can touch it at:

- **Wallet** — [str4w.com](https://str4w.com/), works on any phone or browser
- **Block explorer** — [str4w.com/explorer](https://str4w.com/explorer/), with a live launch-countdown banner until block 1 lands
- **Emission monitor** — [str4w.com/info](https://str4w.com/info/), zooming from one day out to one hundred and twenty-seven years
- **Windows desktop wallet** — `pygrove-gui.exe` from the [latest release](https://github.com/xjqcj357/pygrove-chain/releases)
- **Windows full node** — `pygrove-node.exe` + `pygrove-cli.exe` from the [latest release](https://github.com/xjqcj357/pygrove-chain/releases)
- **Linux full node** — `pygrove-node` + `pygrove-cli` from the [latest release](https://github.com/xjqcj357/pygrove-chain/releases), or as a container image at `ghcr.io/xjqcj357/pygrove-chain:latest`
- **JSON-RPC** — `https://str4w.com/api/testnet/rpc`

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
# The hash is a pure function of the seed values in genesis.toml — the
# canonical value will be pinned in RELEASES.md for the v0.5 tag once
# the first verifier's run lands.
```

Three independent properties give the launch its credibility.

The first is the **24-hour announce window.** `genesis_time_ms` in [`genesis.toml`](genesis.toml) is `2026-05-12 01:03:26 UTC`. Every node refuses to accept a block whose timestamp is earlier than that; the in-process miner refuses to even submit one. There is no path by which a peer-with-source can produce coin before the window closes.

The second is the **proof-of-no-prior-knowledge headline.** The genesis coinbase carries the hash of the latest Bitcoin block at testnet-4 seed time — `00000000000000000001b442356b8e2e0b349cd704cc74084e0762ba57838196` — mined a few minutes before this seed was committed. Bitcoin's own difficulty is the timestamp authority: this seed could not have been constructed before that block existed.

The third is the **byte-deterministic genesis.** Given the seed values in [`genesis.toml`](genesis.toml), `pygrove-node init` is a pure function of those values. Anyone running the build above will produce the exact same tip hash, on any platform. There is no place to hide a premined account.

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

The second is **the Reflection.** A dedicated `reflect/` subtree of the chain state holds rolling statistics — hashrate, active addresses, fee density, emission rate — across short (144 blocks), long (2,016), and epoch (210,000) windows. Consensus reads them to compute the accordion. A future contract VM reads them via a `CHAIN_REFLECT` opcode. The chain learns from its own past.

The third is **the ETF of one.** The accordion is steered toward flat fees-per-active-address — a proxy for whether the median user finds the chain affordable. No oracles. The chain rebalances itself on every retarget against a basket whose only constituent is itself.

The fourth is **calendar emission.** Per-block reward is a delta against a wall-clock schedule, capped per block. Even when blocks land a hundred times faster than target during difficulty discovery, cumulative emission tracks the calendar. No premine optics, by construction.

The fifth is **crypto agility from block zero.** Every signature carries a one-byte algorithm tag. Every hash carries one too. Falcon-512, SLH-DSA-128s, ML-DSA-65, and SHA3-512 are tag-plumbed and waiting; testnet runs the lighter Ed25519 + Blake3-XOF-512 path while the post-quantum suite finishes wiring. An `UpgradeCrypto` governance transaction activates new primitives at a future block height — no fork. The chain is meant to outlive its first cryptosuite, and its second, and its third.

## Operator safeties

Testnet-2 exposed a **cadence-mismatch bug**: the economic adaptation layer (block reward minted per block) ran 5–6 orders of magnitude faster than the security stabilization layer (difficulty retarget every 2,016 blocks). At launch with hashrate above the implied target, half a million PYG could mint in the difficulty-discovery window before retarget caught up. Total cap held in aggregate; distribution was indistinguishable from a premine. Testnet-3 addresses this with **calendar emission** as the primary fix and four operator-grade safeties stacked on top:

1. **ASERT-2D per-block retarget** — Bitcoin Cash's 2020 difficulty algorithm, ported. Difficulty adjusts continuously, not only every 2,016 blocks. Default τ = 2 days; bootstrap τ = 1 hour for the first 2,016 blocks while the discovery window settles.
2. **8% per-block bits clamp** — no matter what ASERT computes, the difficulty target cannot move by more than 8% in either direction in a single block. A single hashrate spike cannot instantly flatten the curve.
3. **25% per-block issuance slew rate** — the mined reward cannot change by more than 25% relative to the previous block's reward. Smooths the calendar-emission delta across hashrate transients.
4. **Bootstrap mode** for `height < 2,016` — caps the reward at 50% of the epoch baseline, runs ASERT with the 1-hour τ, and refuses to pay full coinbase until the chain has settled past the first retarget interval.

Together these close the cadence mismatch: economic and security loops now run at the same per-block granularity.

## What's actually shipped

The whitepaper specifies the v1.0 protocol. The current testnet is honest about which parts are live.

**Live now:**
- Calendar emission with all four operator safeties above
- Bitcoin-curve skeleton (10-minute target, 2,016-block retargets, 210,000-block halvings, 21M cap)
- Reflection subtree (`reflect/`) updated on every `apply_block`
- Signed transactions with full account state, Ed25519 + Blake3-XOF-512
- Mempool with size-bounded admission
- Federated-attestation transaction surface (`AttestRound`) writing to the `attest/` subtree
- Crypto-rotation announcements (`UpgradeCrypto`) writing to the `meta/` subtree
- Mobile wallet at str4w.com (browser-based, `pyg1...` bech32 addresses)
- Windows desktop wallet (Slint GUI)
- Block explorer + emission monitor (str4w.com)
- JSON-RPC node, Linux + Windows binaries, Docker image
- 24-hour fair-launch lockout enforced by every node before `genesis_time_ms`

**Plumbed but not yet wired:**
- Falcon-512 (FN-DSA, integer sampler) — promotes `sig_algo = 1` from `NotWired` to live
- SLH-DSA-128s (cold governance keys, threshold-sig validation for `UpgradeCrypto`)
- ML-DSA-65 (FIPS 204 alternate signature)
- SHA3-512 (FIPS hash alternate, dispatch wired)
- WASM contract VM (replacing the placeholder `crates/vm/`)
- BFT finality gadget (mainnet blocker)
- libp2p P2P networking (mainnet blocker)
- `cargo build --features fips` profile (FedRAMP / FIPS-140-3 path)

**Not on testnet by design:**
- Real economic value. Mainnet ships when the deferred items are wired and the threat model has passed external review.

## Architecture

```
pygrove-chain/
├── crates/
│   ├── core/        block + tx types, canonical CBOR, domain-tagged hashing
│   ├── crypto/      algo dispatch (Ed25519 live, Falcon/SLH-DSA/ML-DSA plumbed)
│   ├── consensus/   PoW, ASERT-2D, accordion, calendar emission, reflection
│   ├── state/       in-memory state store with subtree segregation
│   ├── vm/          WASM contract VM (wasmtime, behind --features wasm)
│   ├── finality/    BFT finality gadget — committee + votes + BLS-aggregated cert
│   ├── p2p/         P2P wire protocol — peer-id, gossipsub topics, in-process broker
│   ├── node/        pygrove-node + pygrove-cli binaries
│   └── gui/         pygrove-gui Slint desktop wallet
├── sim/             Python reference for accordion math + adversarial backtests
├── docs/
│   ├── whitepaper.md       full protocol spec
│   ├── sprint-plan.md      current sprint design ledger
│   └── ...
├── web-mobile/      browser wallet, explorer, emission monitor (deployed to str4w.com)
├── genesis.toml     testnet-4 seed values
├── RELEASES.md      per-tag changelog
└── .github/workflows/
    ├── build.yml    fmt + clippy + build + test + ghcr image publish
    └── release.yml  Linux + Windows binaries on tag pushes
```

The state store segregates nine top-level subtrees:

| Subtree | Holds |
|---|---|
| `accounts` | Account balances, nonces, code refs |
| `code` | Deployed contract bytecode (placeholder for the WASM VM) |
| `storage` | Per-contract key-value storage |
| `meta` | Chain-level metadata, including pending `UpgradeCrypto` rotations |
| `reflect` | Rolling statistics consumed by the accordion |
| `blocks` | Block bodies, indexed by height |
| `headers` | Block headers, indexed by hash |
| `witnesses` | Signatures + public keys, prunable by design |
| `attest` | Federated-learning round attestations from `AttestRound` transactions |

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
# until 2026-05-12 01:03:26 UTC, you'll see "PRE-GENESIS: submit_block locked"
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

Download `pygrove-node.exe` and `pygrove-cli.exe` from [Releases](https://github.com/xjqcj357/pygrove-chain/releases). They're self-contained — no MSVC runtime needed.

```powershell
.\pygrove-node.exe init
.\pygrove-node.exe run --mine
```

### Connect a CLI

```sh
./target/release/pygrove-cli --rpc http://localhost:8545/rpc get-info
./target/release/pygrove-cli --rpc http://localhost:8545/rpc get-balance --address pyg1...
```

### Connect the Windows GUI wallet

Download `pygrove-gui.exe` from [Releases](https://github.com/xjqcj357/pygrove-chain/releases). Self-contained Slint app. Paste any RPC endpoint — your local node, or `https://str4w.com/api/testnet/rpc` — and it'll show balances and submit transactions.

## Genesis seed

Pinned in [`genesis.toml`](genesis.toml) at the root of the repo:

```toml
chain_id              = "pygrove-testnet-4"
genesis_time_ms       = 1778547806000          # 2026-05-12 01:03:26 UTC
genesis_headline_hex  = "00000000000000000001b442356b8e2e0b349cd704cc74084e0762ba57838196"
                                               # ^ Latest BTC tip at testnet-4 seed time

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

# Crypto agility
sig_algo  = 1   # 1 = Falcon512 (FN-DSA, integer sampler) — plumbed
hash_algo = 1   # 1 = Blake3Xof512 — live

initial_accounts = []   # no premine
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
| `get_account` | Full account state (balance + nonce + code ref) |
| `get_mempool` | Mempool size + tx hashes |
| `emission_series` | Replay emission curve over a height range, for the info page chart |

The HTTP server also serves `GET /` (block explorer HTML) and `GET /healthz` (liveness probe).

## Roadmap

There isn't one.

The 90-day sprint plan that lived here had nine items. All landed; their v0.5 follow-ups landed too. The current state:

- **Calendar-emission cross-platform fixture identity** — pinned blake3 digest of a 100-block deterministic trace, [`crates/consensus/src/emission.rs`](crates/consensus/src/emission.rs)
- **Falcon-512 wiring** — `fn-dsa` 0.1 ported, `sig_algo=1` live, [`crates/crypto/src/falcon.rs`](crates/crypto/src/falcon.rs)
- **WASM contract VM** — `wasmtime` 27 with fuel-metered execution + `chain_reflect_get` host function reading [`Subtree::Reflect`](crates/state/src/apply.rs), [`crates/vm/src/wasmtime_backend.rs`](crates/vm/src/wasmtime_backend.rs) (build with `--features wasm`)
- **`--features fips` build profile** — drops Ed25519 + Falcon, gates `UpgradeCrypto` against `FIPS_ALLOWLIST_*`, [`crates/crypto/src/lib.rs`](crates/crypto/src/lib.rs)
- **AttestRound coordinator authority registry** — per-`job_id` allowlist, [`crates/state/src/apply.rs`](crates/state/src/apply.rs)
- **DLA-shape pedigree attestation** — supply-chain variant (`lot_id` + CAGE code + supplier hash), [`TxCall::AttestPedigree`](crates/core/src/tx.rs)
- **Mainnet plan** — [`docs/mainnet-plan.md`](docs/mainnet-plan.md), 323 lines covering BFT finality, port architecture, launch-difficulty calibration, governance ceremony, threat model, audit plan
- **Reflection subtree writes** — every `apply_block` emits a per-block `Reflection` record, [`crates/state/src/apply.rs`](crates/state/src/apply.rs)
- **UpgradeCrypto activation** — pending rotations now actually activate at `target_height`, writing `ActiveCrypto` to `Subtree::Meta`
- **`pygrove-cli` as real RPC client** — no more stubs; `get-info`, `show-block`, `list-blocks`, `get-balance`, `get-account`, `submit-tx`, `get-mempool`, `emission-series`, `state-root`, `health`
- **BFT finality gadget** — committee, votes, certs, quorum check, fork-choice helper, [`crates/finality/`](crates/finality/src/lib.rs). N-of-N MVP.
- **SLH-DSA-128s wiring** — `sig_algo=2` live in all build profiles via the pure-Rust `fips205` crate (no `signature`-crate diamond). FIPS 205 deterministic mode. [`crates/crypto/src/slhdsa.rs`](crates/crypto/src/slhdsa.rs)
- **BLS12-381 aggregation** — `sig_algo=5` for finality votes; N validator sigs collapse to a 96-byte constant-sized cert verified in one pairing check. [`crates/crypto/src/bls.rs`](crates/crypto/src/bls.rs), [`AggregatedFinalizationCert`](crates/finality/src/lib.rs)
- **k-of-N governance threshold sigs** — `UpgradeCrypto` and `RegisterAttestCoordinator` now require a k-of-N proof from the active committee once governance is installed. Bootstrap mode preserved. [`GovernanceConfig`](crates/state/src/apply.rs)
- **P2P wire protocol** — peer-id format, 8 gossipsub topics, message envelope, in-process broker for tests. Transport (libp2p) lands as a follow-up integration crate. [`crates/p2p/`](crates/p2p/src/lib.rs)

One item deliberately deferred:

- **HSM-backed governance keys.** Hardware procurement, not a code change. The threshold-sig protocol is live in software today (Ed25519 placeholder for the signer algo today; SLH-DSA when the HSMs arrive — wire format unchanged).

What replaces "the roadmap" is [`docs/mainnet-plan.md`](docs/mainnet-plan.md). It's the design ledger every change is now reviewed against.

## Mainnet readiness

Six gates close before mainnet:

| | Gate | Status |
|---|---|---|
| 1 | Calendar-emission inflation bug closed | ✅ |
| 2 | Operator safeties (ASERT-2D + 8% clamp + 25% slew + bootstrap) | ✅ |
| 3 | Falcon-512 actually wired | ✅ |
| 4 | Real test coverage (unit + integration + cross-platform fixture identity) | ✅ |
| 5 | libp2p P2P online | ⏳ wire protocol shipped in [`crates/p2p/`](crates/p2p/src/lib.rs); libp2p transport (separate integration crate) is the remaining gap |
| 6 | BFT finality gadget shipped | ✅ committee, votes, BLS-aggregated certs in [`crates/finality/`](crates/finality/src/lib.rs) |

All six gates have code shipped; the P2P transport integration (a layer on top of the now-stable wire protocol) is the only remaining external surface. Mainnet launches when libp2p is wired and an external review has signed off on the threat model.

## Contributing

This is currently a single-author build. Issues and PRs are welcome but the bar is high: anything that touches consensus needs a Python-sim port and an adversarial-trace replay before it merges. See [`docs/mainnet-plan.md`](docs/mainnet-plan.md) for the design ledger PRs are evaluated against.

## License

Apache-2.0 for the source. CC BY 4.0 for the whitepaper.

Whitepaper at [docs/whitepaper.md](docs/whitepaper.md). Per-tag changelog at [RELEASES.md](RELEASES.md). Current sprint's design ledger at [docs/sprint-plan.md](docs/sprint-plan.md).
