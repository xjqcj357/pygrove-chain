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

Status: **v0.1 scaffold**. The chain does not yet run end-to-end; this is the skeleton that Linux CI builds green. See [crates/](crates/) for layout and [sim/](sim/) for the accordion simulator.

## Layout

```
crates/core        # Block, Tx, SigAlgo tag, canonical CBOR, Blake3-XOF-512
crates/crypto      # Falcon-512, SLH-DSA-128s, algo-tag dispatch
crates/consensus   # RandomX-lite stub, retarget, accordion, reflection, emission
crates/state       # Authenticated KV store, subtree tags, apply_block
crates/vm          # stub for v1.2 Python VM
crates/node        # clap CLI + miner loop
crates/gui         # Slint GUI shell — pygrove-gui wallet
sim/               # Python 3.13 accordion simulator with BTC backtest + adversarial traces
```

## Build

Linux (CI-blessed):

```bash
cargo build --workspace
cargo test --workspace
```

Windows/MSVC is deferred while native `rocksdb` + `fn-dsa` AVX paths are stabilized. Until then, build under WSL2.

## License

Apache-2.0. See [LICENSE](LICENSE).
