# PyGrove Chain

A small proof-of-work blockchain that listens to itself.

It inherits Bitcoin's economic skeleton — 10-minute blocks, 2,016-block retargets, halvings every 210,000 blocks, a 21,000,000-coin hard cap — and adds a measured kind of self-awareness on top. The chain reads its own statistics from a dedicated subtree of its own state. Emission breathes with hashrate and adoption inside that information. The cryptography is post-quantum where it can be, agile where it can't. The design horizon is 127 years.

## Where it lives

The third public testnet (`pygrove-testnet-3`) launched on 2026-05-10 at 03:00 UTC. You can touch it at:

- **Wallet** — [str4w.com](https://str4w.com/), works on any phone or browser
- **Block explorer** — [str4w.com/explorer](https://str4w.com/explorer/)
- **Emission monitor** — [str4w.com/info](https://str4w.com/info/), zooming from one hour to one hundred and twenty-seven years
- **Windows desktop** — `pygrove-gui.exe` from the [latest release](https://github.com/xjqcj357/pygrove-chain/releases)
- **JSON-RPC** — `https://str4w.com/api/testnet/rpc`

The same `pyg1...` address works on every client. Your secret-key file carries between them.

## What's distinctive

The protocol does five things you won't find together anywhere else.

The first is **the Accordion.** Two adaptive bellows — one tracking hashrate ratio period over period, the other tracking the count of unique sybil-guarded active addresses — modulate the halving schedule and difficulty around Bitcoin's curve. When both bellows are pumping, halvings arrive sooner and difficulty doesn't lag. When they deflate, halvings pause. At equilibrium it's pure Bitcoin.

The second is **the Reflection.** A dedicated `reflect/` subtree of the chain state holds rolling statistics — hashrate, active addresses, fee density, emission rate — across short (144 blocks), long (2,016), and epoch (210,000) windows. Consensus reads them to compute the accordion. A future Python contract VM reads them via a `CHAIN_REFLECT` opcode. The chain learns from its own past.

The third is **the ETF of one.** The accordion is steered toward flat fees-per-active-address — a proxy for whether the median user finds the chain affordable. No oracles. The chain rebalances itself on every retarget against a basket whose only constituent is itself.

The fourth is **calendar emission.** Per-block reward is a delta against a wall-clock schedule, capped per block. Even when blocks land a hundred times faster than target during difficulty discovery, cumulative emission tracks the calendar. No premine optics, by construction.

The fifth is **crypto agility from block zero.** Every signature carries a one-byte algorithm tag. Every hash carries one too. Genesis runs Ed25519 on testnet. Falcon-512, SLH-DSA-128s, ML-DSA-65, and SHA3-512 are tag-plumbed and waiting. An `UpgradeCrypto` governance transaction activates new primitives at a future block height — no fork. The chain is meant to outlive its first cryptosuite, and its second, and its third.

## What's actually shipped

The whitepaper specifies the v1.0 protocol. The current testnet is honest about which parts are live.

Live now: calendar emission, ASERT-2D per-block retarget, the eight-percent bits clamp, the twenty-five-percent issuance slew-rate limit, bootstrap-mode caps for the first 2,016 blocks, the reflection subtree, signed transactions with full account state, the mempool, the federated-attestation transaction surface, the mobile and desktop wallets, and the explorer.

Plumbed but not yet wired: Falcon-512, SLH-DSA-128s, ML-DSA-65, the WASM contract VM, the BFT finality gadget, peer-to-peer networking. Each is the work of the next sprint.

Not on testnet by design: real economic value. Mainnet ships when the deferred items are wired and the threat model has passed external review.

## License

Apache-2.0 for the source. CC BY 4.0 for the whitepaper.

Whitepaper at [docs/whitepaper.md](docs/whitepaper.md). Per-tag changelog at [RELEASES.md](RELEASES.md). Current sprint's design ledger at [docs/sprint-plan.md](docs/sprint-plan.md).
