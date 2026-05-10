# PyGrove Chain

A small proof-of-work blockchain that listens to itself.

- **Bitcoin-style curve** — 10-min blocks, 2016-block retargets, 210k halvings, 21M cap.
- **The Accordion** — adaptive emission driven by two bellows: hashrate and sybil-guarded adoption.
- **The Reflection** — rolling on-chain stats committed into a dedicated state subtree; consensus and (future) contracts read their own past.
- **ETF-of-one objective** — the accordion is steered by a stability-seeking function (flat fees-per-active-address), not just a monotone adaptation. The chain is its own basket.
- **Quantum- and photonic-hostile PoW** — RandomX-lite proposer (memory-hard, branchy microcode, photonic matmul immune) + class-group Wesolowski VDF finalizer (inherently sequential, no trusted setup).
- **Post-quantum signatures** — Falcon-512 / FN-DSA (integer sampler) for hot txs; SLH-DSA-128s for cold governance keys.
- **Crypto-agile from block zero** — `SigAlgo` and `HashAlgo` tag bytes on every primitive; `UpgradeCrypto` governance tx activates new algos at a future height with no hard fork. Designed to run for 127 years.
- **Authenticated state** — GroveDB-style hierarchical Merkle store; every query is provable.

Status: **v0.3.0-testnet — public testnet `pygrove-testnet-2` is live, send & receive works.** See [Whitepaper](docs/whitepaper.md) for the protocol, [RELEASES.md](RELEASES.md) for what each tag actually shipped, and below for participation.

> **What's actually live.** The whitepaper specifies the v1.0 protocol; the
> tagged testnet ships the accordion math, reflection layout, fair-launch
> ceremony, U256 retarget, domain-tagged hashing, signed transactions with
> full account state via `apply_block`, a mempool, and end-to-end wallet flow
> (mobile + Windows). The PoW seal is Blake3-XOF-512 (RandomX-lite + VDF
> deferred to v1.1). Phase A signs with **Ed25519** (`sig_algo = 3`);
> Falcon-512 (`1`) and SLH-DSA-128s (`2`) are tag-plumbed but still
> `NotWired` — they activate via `UpgradeCrypto` in Phase B, which itself
> is the first real exercise of the crypto-agility layer the whitepaper
> promises. The contract VM is a placeholder. See
> [Whitepaper §0 v0.1 scope](docs/whitepaper.md#0-v01-implementation-scope)
> for the authoritative live/deferred map. **Don't deploy economic value
> on testnet that assumes deferred components are present.**

## Try it

Three clients, all talking to the same chain:

| | |
|---|---|
| **Web wallet** *(any phone or browser)* | https://str4w.com/ |
| **Block explorer** | https://str4w.com/explorer/ |
| **Emission monitor** *(actual vs. 127y planned)* | https://str4w.com/info/ |
| **Windows GUI** *(wallet + miner)* | [latest release](https://github.com/xjqcj357/pygrove-chain/releases) → `pygrove-gui.exe` |
| **JSON-RPC** *(headless / scripting)* | `https://str4w.com/api/testnet/rpc` (HTTPS, same-origin) or `http://66.42.93.85:8545/rpc` |

Same `pyg1...` address works on any client — wallet keys port across them via Export / Import.

## Public testnet — `pygrove-testnet-2`

Fair-launch testnet running on `66.42.93.85`. **No premine.** The node refuses
to accept block submissions before genesis time; the genesis coinbase carries
a Bitcoin block hash mined before our deploy as proof-of-no-prior-knowledge.

| | |
|---|---|
| **Chain ID** | `pygrove-testnet-2` |
| **Genesis time** | `2026-05-10 00:00:00 UTC` (`genesis_time_ms = 1778371200000`) |
| **Genesis hash** | `000077e5ac42f9540a69655e9f889e60b44639c7a34e1b8c30bcdb56d388f5d7` |
| **Genesis headline** | BTC block `948515` — `00000000000000000001b62fbb2361bb622e8b767db52961d700cb0ad352304e` (mined `2026-05-08 22:23:16 UTC`) |
| **Initial bits** | `0x1f00ffff` (laptop-mineable; mainnet uses harder bits matched to expected launch hashrate) |
| **Sig algo** | `3` (Ed25519) — Phase A bringup; rotates to Falcon-512 (`1`) via `UpgradeCrypto` in Phase B |
| **Block reward** | 50 PYG |
| **Hard cap** | 21,000,000 PYG |

testnet-1 was retired pre-launch when we landed real send/receive (the
protocol shape changed substantively). testnet-2 ships the same fair-launch
ceremony with the new mechanics in place: AccountId + bech32 addresses,
signed transactions, mempool, `apply_block`, wallet balance polling, mobile
+ desktop clients.

### Verifying the genesis headline

The headline is a Bitcoin block hash that did not exist before its block's
timestamp. You can confirm independently:

```bash
curl https://blockstream.info/api/block/00000000000000000001b62fbb2361bb622e8b767db52961d700cb0ad352304e | jq
```

That hash appears as the genesis block's `coinbase` field on PyGrove. Nothing
about it was predictable before BTC mined block 948515 (`2026-05-08 22:23:16 UTC`),
so the PyGrove genesis cannot have been mined before that moment.

### Mining

Download `pygrove-gui.exe` from the [latest release](https://github.com/xjqcj357/pygrove-chain/releases),
double-click, click **Connect** (the RPC URL is pre-filled), then **Start mining**.
Block rewards land in the wallet generated on first launch (`%APPDATA%\PyGrove\wallet.json`).

Headless miners on Linux/macOS use `pygrove-cli` from the same release,
pointed at the public RPC.

A throttled server-side miner runs at ~5 H/s as a chain keepalive — when no
external miner is online, blocks land every ~3.6 hours. With even a casual
laptop attached, the laptop wins essentially every block.

## Layout

```
crates/core        # Block, Tx, SigAlgo / HashAlgo tags, canonical CBOR, Blake3-XOF-512, bech32 addresses
crates/crypto      # Ed25519 (Phase A), Falcon-512 / SLH-DSA-128s slots (Phase B)
crates/consensus   # RandomX-lite stub, retarget (U256), accordion, reflection, emission
crates/state       # Authenticated KV store, subtree tags, apply_block, account model
crates/vm          # stub for v1.2 Python VM
crates/node        # node daemon + clap CLI + JSON-RPC + bundled explorer
crates/gui         # Slint GUI shell — pygrove-gui wallet + miner
sim/               # Python 3.13 accordion simulator with BTC backtest + adversarial traces
web/               # Janet landing-page sidecar (~80-line Lisp)
web-mobile/        # str4w.com SPA — mobile wallet, explorer, emission monitor
docs/whitepaper.md # Protocol specification
RELEASES.md        # Per-version release notes
```

## Build

Linux (CI-blessed):

```bash
cargo build --workspace
cargo test --workspace
```

Windows GUI builds via CI on `windows-latest` and is uploaded as the
`pygrove-gui-windows-x86_64` artifact on every push to `main`. Tagged
releases attach the same artifact under [GitHub Releases](https://github.com/xjqcj357/pygrove-chain/releases).

## License

Apache-2.0 for source code. CC BY 4.0 recommended for the whitepaper. See [LICENSE](LICENSE).
