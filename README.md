# PyGrove Chain

A small proof-of-work blockchain that listens to itself.

- **Bitcoin-style curve** — 10-min blocks, 2016-block retargets, 210k halvings, 21M cap.
- **The Accordion** — adaptive emission driven by two bellows: hashrate and sybil-guarded adoption.
- **The Reflection** — rolling on-chain stats committed into a dedicated state subtree; consensus and (future) contracts read their own past.
- **ETF-of-one objective** — accordion is steered by a stability-seeking function (flat fees-per-active-address), not just a monotone adaptation. The chain is its own basket.
- **Quantum- and photonic-hostile PoW** — RandomX-lite proposer (memory-hard, branchy microcode, photonic matmul immune) + class-group Wesolowski VDF finalizer (inherently sequential, no trusted setup).
- **Post-quantum signatures** — Falcon-512 / FN-DSA (integer sampler) for hot txs; SLH-DSA-128s for cold governance keys.
- **Crypto-agile from block zero** — `SigAlgo` and `HashAlgo` tag bytes on every primitive; `UpgradeCrypto` governance tx activates new algos at a future height with no hard fork. Designed to run for 127 years.
- **Authenticated state** — GroveDB-style hierarchical Merkle store; every query is provable.

Status: **v0.1 — public testnet**. See [Whitepaper](docs/whitepaper.md) for the protocol; see below for testnet participation.

## Public testnet — `pygrove-testnet-1`

Fair-launch testnet running on `66.42.93.85`. **No premine.** The node refuses
to accept block submissions before genesis time; the genesis coinbase carries
a Bitcoin block hash mined before our deploy as proof-of-no-prior-knowledge.

| | |
|---|---|
| **Chain ID** | `pygrove-testnet-1` |
| **Genesis time** | `2026-04-29 00:00:00 UTC` (`genesis_time_ms = 1777420800000`) |
| **Genesis headline** | BTC block `946923` — hash `000000000000000000021018660f24da5d8566c2d71eaf182287ca977ef0f67a` (mined `2026-04-28 05:53:12 UTC`) |
| **Initial bits** | `0x1f00ffff` (laptop-mineable; mainnet uses `0x1d00ffff`) |
| **RPC endpoint** | `http://66.42.93.85:8545/rpc` |
| **Block explorer** | http://66.42.93.85:8545/ |
| **Landing page** | http://66.42.93.85:8000/ |

### Verifying the genesis headline

The headline is a Bitcoin block hash that did not exist before its block's
timestamp. You can confirm independently:

```bash
curl https://blockstream.info/api/block/000000000000000000021018660f24da5d8566c2d71eaf182287ca977ef0f67a | jq
```

That hash appears as the genesis block's `coinbase` field in the chain. The
PyGrove genesis block could not have been mined before `2026-04-28 05:53:12 UTC`
because nothing about that BTC block hash was predictable before then.

### Mining

Download `pygrove-gui.exe` from the [latest CI artifact](https://github.com/xjqcj357/pygrove-chain/actions/workflows/release.yml)
(Windows). Headless miners on Linux/macOS use `pygrove-cli` from the same
release, with the RPC URL pointed at the public node.

The node will return a clear `pre-genesis: launch in Ns` error to any block
submission before the genesis time. Once `now() >= genesis_time_ms`, block 1
becomes eligible — first valid hash wins.

## Layout

```
crates/core        # Block, Tx, SigAlgo tag, canonical CBOR, Blake3-XOF-512
crates/crypto      # Falcon-512, SLH-DSA-128s, algo-tag dispatch
crates/consensus   # RandomX-lite stub, retarget, accordion, reflection, emission
crates/state       # Authenticated KV store, subtree tags, apply_block (v0.2)
crates/vm          # stub for v1.2 Python VM
crates/node        # clap CLI + miner loop + JSON-RPC + bundled explorer
crates/gui         # Slint GUI shell — pygrove-gui wallet + miner
sim/               # Python 3.13 accordion simulator with BTC backtest + adversarial traces
web/               # Janet landing-page sidecar
docs/whitepaper.md # Protocol specification
```

## Build

Linux (CI-blessed):

```bash
cargo build --workspace
cargo test --workspace
```

Windows GUI builds via CI on `windows-latest` and is uploaded as the
`pygrove-gui-windows-x86_64` artifact on every push to `main`.

## License

Apache-2.0. See [LICENSE](LICENSE).
