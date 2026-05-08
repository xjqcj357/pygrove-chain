# PyGrove Chain — Release notes

Tagged releases of the protocol, the node, and the GUI client. Most recent at
the top. Each entry follows the same shape:

- **What's in** — concrete shipped changes
- **Genesis seed** (testnet entries) — chain identity at this version
- **Breaking changes** — anything that invalidates a previous client / chain
- **Audit progress** — which checklist items the release closes
- **Known limitations** — what's still deferred and why

The whitepaper at [`docs/whitepaper.md`](docs/whitepaper.md) is the
authoritative protocol spec. This file documents what each *release* contains
versus that spec, so reviewers can see what's actually live without scanning
git log.

---

## v0.2.0-testnet — 2026-05-09

**Phase A — send and receive on `pygrove-testnet-2`.**

Closes the largest gap from the v0.1 audit: `apply_block` is no longer a
missing function. Real account state, signed transactions, an in-process
mempool, and a wallet GUI that ships an Ed25519 keypair on first launch.
testnet-1 was retired pre-launch (the protocol shape changed substantively
underneath; nothing of value lived on it).

### What's in

- **20-byte AccountId, bech32m `pyg1...` addresses.** Derived from
  `blake3(domain || pubkey)[..20]` with the `PGaddr\0` domain tag. Bech32m
  has built-in error detection — a single typo fails the checksum and the
  wallet refuses to send.
- **Account state.** `Account { balance: u128, nonce: u64, pubkey, sig_algo }`
  stored under `Subtree::Accounts`, keyed by raw 20-byte AccountId. CBOR-
  encoded.
- **Signed transactions.** `TxBody` carries `nonce / from / call /
  fee_sat / gas_limit / witness_hash`. Two distinct hashes per tx —
  `signing_hash` (excludes `witness_hash`, the witness signs over this) and
  `body_hash` (everything, committed in `BlockHeader.tx_root`). `Witness`
  segregated parallel-by-index in `BlockBody.witnesses`.
- **`apply_block`** in `pygrove-state`. Validates each tx (sig, balance,
  nonce, witness-hash match, pubkey-derivation match), applies all-or-
  nothing, mints `block_reward + Σ fees` to the miner's coinbase address.
  Two-pass design (validate → apply) so `MemState`'s lack of journaling
  isn't a correctness risk.
- **Mempool.** In-process `Mutex<BTreeMap<TxHash, PendingTx>>` with a
  10,000-tx cap and FIFO eviction. Miner pulls top-N by fee for the next
  block; `confirm()` drops included txs after a block lands.
- **Ed25519 wired** as `sig_algo = 3` for Phase A bringup. Falcon-512 (`1`)
  and SLH-DSA-128s (`2`) still return `NotWired` — they activate via an
  `UpgradeCrypto` event in Phase B, which itself becomes the first real-
  world exercise of the crypto-agility layer the whitepaper specifies.
- **State replay on startup.** `cmd_run` replays every persisted block
  through `apply_block` to rebuild `MemState`. v0.2 swaps to GroveDB
  persistence so this O(N) cost goes away.
- **Tx-aware block submission.** `get_template` returns the txs +
  witnesses the miner should publish back, with `header.tx_root` /
  `header.witness_root` already committed to them. `submit_block`
  validates the body matches and runs `apply_block` in the same atomic
  step as the chainstore append; mempool is confirmed only after success.
- **Wallet in the GUI.** First launch generates an Ed25519 keypair and
  writes it to `%APPDATA%\PyGrove\wallet.json` (Linux: `~/.config/pygrove/`;
  macOS: `~/Library/Application Support/PyGrove/`). Wallet tab shows the
  bech32 address in a selectable read-only field, polls balance + nonce
  every 3 s, and the **Send** form does the full pipeline: parse `pyg1`
  recipient + sat amount + fee, fetch nonce via RPC, build TxBody, sign
  the canonical signing hash, package Witness (Inline pubkey first time
  the account signs, Known after), CBOR-encode both, hex-encode, submit
  via `submit_tx`. **Copy** button puts the address on the clipboard;
  **Regenerate** rolls a fresh keypair in-place (destructive, testnet-only
  convenience).
- **Mining-reward routing.** GUI miner overrides `header.coinbase` with
  `wallet.address.pad_to_32()` before mining, so block rewards land in the
  user's wallet rather than the node's treasury / burn address.
- **New JSON-RPC methods.** `submit_tx`, `get_balance`, `get_account`,
  `get_mempool`. `get_info` extended with `mempool_size` and
  `block_reward_sat`. `get_block` returns a per-tx summary list.
- **Explorer + Janet site updates.** Stats panels gain Mempool size and
  Block reward cells. Block table grows a tx-count column. Surfaces also
  HTML-escape every RPC-derived value defensively (separate hardening
  series; full series shipped with the merge).

### Genesis seed

| | |
|---|---|
| **Chain ID** | `pygrove-testnet-2` |
| **Genesis time** | `2026-05-10 00:00:00 UTC` (`genesis_time_ms = 1778371200000`) |
| **Genesis hash** | `000077e5ac42f9540a69655e9f889e60b44639c7a34e1b8c30bcdb56d388f5d7` |
| **Genesis nonce** | `21044` |
| **Headline** | BTC block 948515 — `00000000…b62fbb…304e` (mined `2026-05-08 22:23:16 UTC`) |
| **Sig algo** | `3` (Ed25519) — Phase A bringup |
| **Hash algo** | `1` (Blake3-XOF-512) |
| **Initial bits** | `0x1f00ffff` |
| **Initial reward** | `5_000_000_000` sat (50 PYG) |

### Breaking changes

- `pygrove-testnet-1` retired pre-launch. Anyone running a testnet-1 node
  cannot peer with testnet-2 — different `chain_id`, different genesis hash,
  different on-the-wire transaction format.
- `BlockBody` now carries `witnesses: Vec<Witness>` parallel to `txs`. Old
  blocks deserialize via `#[serde(default)]` (empty vec) but new blocks
  with txs require both fields present.
- `submit_block` RPC accepts (and now requires) `txs_cbor_hex` +
  `witnesses_cbor_hex` parameters when the block contains transactions.
  Empty arrays for empty blocks remain valid.
- `AccountId` changed shape: was `pub type AccountId = [u8; 6]`, now is a
  20-byte newtype. No deployed code depended on the old form.

### Audit progress

- ✅ **Gap #2** — *`apply_block` doesn't exist.* It does now. Validates
  every tx, applies atomically, mints coinbase, handles two-pass
  validation against mutable state.
- 🟡 **Gap #1** — *No tests anywhere.* Partial. Tests exist for accordion
  regimes, address bech32 round-trip, ed25519 sign/verify, account
  load/save, and `apply_block` happy/sad paths. Property-test coverage,
  cross-platform fixture comparison, and replay-determinism remain
  pending.
- 🟡 **Gap #3** — *Crypto is theatre.* Half-closed. Ed25519 is real;
  Falcon-512 + SLH-DSA-128s remain `NotWired`. The agility layer is wired
  end-to-end (sig_algo dispatch + UpgradeCrypto tx variant) and will be
  first exercised by Phase B.
- ❌ **Gap #4** — *No reorg path.* Still append-only; reorg, fork-choice,
  and competing-tip tracking land with the libp2p layer in v1.0.

### Known limitations

- **Wallet is plaintext** in `wallet.json`. argon2 password encryption +
  BIP-39 mnemonic export are Phase B.
- **Single keypair per wallet.** "Regenerate" overwrites the current key;
  multi-address / HD-wallet derivation is Phase B.
- **No GPU mining yet.** OpenCL Blake3 is the v0.2 plan.
- **No P2P.** A second node cannot peer with the canonical one. Single
  source of truth at `66.42.93.85`.
- **No reorg handling.** A second miner with clock drift could publish a
  block at the same height; whichever lands first wins, and there is no
  re-org path. Solo and multi-miner-on-same-node are the supported modes.
- **Falcon-512 / SLH-DSA still stubs.** `sign`/`verify` return `NotWired`
  for `sig_algo ∈ {1, 2}`. Phase B activates them via UpgradeCrypto.

### Surfaces

- **Public RPC**: `http://66.42.93.85:8545/rpc`
- **Block explorer**: `http://66.42.93.85:8545/`
- **Landing page** (Janet): `http://66.42.93.85:8000/`
- **Windows GUI**: `pygrove-gui-windows-x86_64` artifact from the
  release-artifacts CI run.

---

## v0.1.0-testnet — 2026-04-23

**First public chain, fair-launch ceremony.** Single-node devnet
formalized into a testnet with a no-premine launch protocol. **Retired
pre-launch** (within hours of v0.2.0-testnet's predecessor branch
landing); nothing of value was committed on this chain.

### What's in

- **Fair-launch ceremony.** `submit_block` returns
  `pre-genesis: launch in Ns` for any submission while
  `now() < genesis_time_ms`. Header timestamps must satisfy
  `parent.timestamp_ms <= ts <= now() + 2h` (Bitcoin's clock-skew window).
  Genesis coinbase carries a Bitcoin block hash mined before our deploy
  as proof-of-no-prior-knowledge.
- **Throttled server self-miner.** `PYGROVE_SELF_MINE=1` +
  `PYGROVE_THROTTLE_MS=200` runs a polite ~5 H/s background miner so the
  chain advances even when no one's home; any laptop dominates by 5+
  orders of magnitude.
- **Shared validation gate.** `try_apply_block` is the single source of
  truth that both JSON-RPC `submit_block` and the in-process self-miner
  go through. Pre-genesis lockout, monotonic timestamps, future-time
  tolerance, parent / height / bits / PoW all gate here.
- **Embedded explorer.** Dark-theme single-page block explorer bundled
  via `include_str!` and served at `GET /`. Polls `/rpc` every 2 s.
- **Janet landing page.** ~80 lines of Janet (a Lisp dialect) serving a
  public landing page on `:8000`. Server-side renders chain stats from
  the node container next door over Docker DNS.
- **Q64.64 accordion math.** `r_h`, `r_a`, regime classification with an
  ε equilibrium band.
- **Genesis init / state replay** done by the node container on first
  boot; identical genesis hash from identical `genesis.toml` across any
  operator.

### Genesis seed (retired)

- `chain_id` = `pygrove-testnet-1`
- `genesis_time_ms` = `1777420800000` (2026-04-29 00:00:00 UTC)
- `genesis_hash` = `0000c188d4553398437dcb4ecc754fa37ec91d99c4544fda08451d9485179ba5`
- Headline: BTC block 946923

### Why retired

The send-receive stack (Phase A, → v0.2.0-testnet) reshaped the
transaction encoding (new `fee_sat` field), the BlockBody (parallel
witnesses), the address type (6-byte → 20-byte), and committed values
in the header (`tx_root`, `witness_root` now mandatory). Old blocks
mined under testnet-1 cannot be replayed against the new validator
without a backwards-compatibility shim that wasn't worth writing for a
chain with no economic value.

---

## Pre-tagged work (≤ 2026-04-23)

The repository scaffold and CI bring-up. Documented for reviewers; no
public chain ran in this period.

- Workspace layout: `core / crypto / consensus / state / vm / node / gui`
- Domain-tagged Blake3-XOF-512 hashing
- Compact-bits difficulty encoding (Bitcoin-format)
- Append-only CBOR chain log (replaced by GroveDB in v1.0)
- GitHub Actions CI: clippy / build / test on Ubuntu, Windows GUI
  artifact build, ghcr.io Docker image publish
- Slint GUI shell with Mining tab (header-only submission protocol)

---

## Versioning

Semver-ish:

- `v0.x` covers the testnet rehearsals.
- `v1.0` is mainnet. By that point: VDF finalizer wired, P2P online,
  GroveDB persistence, threshold-key governance, Falcon-512 active.
- Tags ending `-testnet` mark public testnet rounds; tags without a
  suffix (when they exist) mark mainnet.

## License

Apache-2.0 for source code. CC BY 4.0 recommended for the whitepaper.
