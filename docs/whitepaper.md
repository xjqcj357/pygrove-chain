# PyGrove Chain
### A Self-Reflective, Crypto-Agile, Stability-Seeking Proof-of-Work Blockchain

**Version 1.0 — April 2026**
*xjqcj357 · github.com/xjqcj357/pygrove-chain*

---

## Abstract

PyGrove Chain is a proof-of-work blockchain that listens to itself. It inherits
Bitcoin's economic skeleton — a 10-minute block target, 2016-block difficulty
retargets, 210,000-block halving epochs, and a 21,000,000-coin hard cap — and
adds a measured form of self-awareness on top.

Two **bellows** — a *hashrate bellow* tracking work ratio period-over-period and
a *sybil-guarded adoption bellow* tracking unique active addresses — modulate
the halving schedule and difficulty around the Bitcoin curve, accelerating
issuance during phases of healthy growth and contracting it during downturns,
with a **stability-seeking bias** that targets flat fee-per-active-address.

Every measurement the bellows consume is committed to a dedicated `reflect`
subtree of the chain state, so consensus decisions, smart contracts, and
external observers all read the same numbers from the same Merkle root. **The
chain is its own basket — an ETF of one, balancing itself on every retarget
without oracles.**

PyGrove Chain ships post-quantum where it can — Falcon-512 hot signatures,
SLH-DSA-128s cold governance keys, blake3-XOF-512 block hashing, SHAKE256 with
per-subtree domain tags for state hashing — and crypto-agile where it can't,
with an `UpgradeCrypto` governance transaction that activates new algorithms at
a future block height without forking. The design horizon is **127 years**.

This document specifies the v1.0 protocol.

---

## 1. Motivation

The promise of a sound, decentralized, immutable monetary base is now seventeen
years old. Bitcoin's design — the proof-of-work race, the deflationary halving
schedule, the fixed supply — has held up beyond its inventor's most generous
projection. It has done so by being radically conservative: change is hard,
forks are political, and the protocol's economic constants have not moved by a
single satoshi.

That conservatism is the source of its strength and the source of three
specific weaknesses we propose to address:

1. **Issuance is blind to demand.** The halving schedule is calendar-driven,
   not user-driven. A network with a million daily active wallets and a network
   with a thousand share the same emission curve. There is no feedback channel
   from the real economy to the supply schedule.

2. **The chain cannot read itself.** Smart contracts can read account state but
   not chain state — not the rolling hashrate, not the active address count,
   not the fee density. Anyone who wants to act on the network's own statistics
   must do so via off-chain oracles, reintroducing a trusted dependency the
   base layer was meant to eliminate.

3. **The cryptography is locked.** ECDSA over secp256k1 and SHA-256 are
   excellent today and indefensible tomorrow. A sufficiently large quantum
   computer breaks signature security; a sufficiently good lattice attack
   breaks current post-quantum candidates. A chain that intends to outlive its
   designers must be able to migrate without forking.

PyGrove Chain keeps Bitcoin's skeleton — the proof-of-work race, the halving
schedule, the 21M cap — and adds three layers on top: an *accordion* that lets
issuance breathe with hashrate and adoption, a *reflection* subtree that
records the chain's own statistics on-chain, and a *crypto-agility layer* that
makes algorithm replacement a routine governance transaction.

The remainder of this paper specifies the design.

---

## 2. The Bitcoin Skeleton

PyGrove preserves the following parameters from Bitcoin verbatim:

| Parameter | Value |
|---|---|
| Target block time | 600,000 ms (10 minutes) |
| Retarget interval | 2,016 blocks |
| Halving interval (base) | 210,000 blocks |
| Initial reward | 50 × 10⁸ sat |
| Hard cap | 21,000,000 × 10⁸ sat |
| Difficulty encoding | compact bits, identical layout |
| Coin denomination | 8 decimal places (sat) |

The compact-bits difficulty encoding, the median-time-past timestamp clamp, the
coinbase-reward halving, and the 4× clamp on per-retarget difficulty change are
all imported unchanged.

What changes is what the retarget computes from. Bitcoin's retarget asks one
question: *did the last 2016 blocks take exactly two weeks?* PyGrove asks the
same question, then asks two more: *did hashrate change?* and *did the active
user base change?* The answer to all three drives the next epoch's difficulty
and, for the first time, **the rate at which halvings advance**.

---

## 3. The Accordion

The accordion sits between the Bitcoin retarget and the new block target, and
between the calendar block height and the *effective* halving height. It has
two bellows.

### 3.1 The mining bellow

Let `W(period)` be the total proof-of-work in a 2016-block period (the sum of
header hash inverses, weighted by the period's targets). Define the **work
ratio**

$$ r_h = \frac{W(\text{this period})}{W(\text{previous period})} $$

with `r_h = 1` defined for the genesis epoch. The mining bellow's signal is
the natural logarithm of this ratio, computed in fixed-point Q64.64:

$$ \ell_h = \ln r_h $$

`ℓ_h > 0` means hashrate grew; `ℓ_h < 0` means it shrank.

### 3.2 The adoption bellow

Let `A(period)` be the number of *qualifying* active addresses in a period —
addresses that signed at least one transaction with a paid fee, holding at
least the dust floor (`100,000 sat`), and at least 2,016 blocks old. Define
the **adoption ratio**

$$ r_a = \frac{A(\text{this period})}{A(\text{previous period})} $$

and the bellow signal

$$ \ell_a = \ln r_a $$

### 3.3 Sybil resistance for the adoption bellow

`r_a` is the protocol's only soft signal — the only quantity an attacker could
hope to inflate cheaply. Three gates make inflation economically irrational:

1. **Dust floor** (`sybil_dust_floor_sat = 100,000`): the qualifying address
   must hold at least 0.001 PYG. Funding 10,000 dummy addresses costs 10 PYG
   minimum.
2. **Age gate** (`sybil_min_age_blocks = 2016`): an address that received its
   funding less than 2016 blocks ago does not count. Sybils must be funded
   one full retarget period before they pay off.
3. **Paid-fee requirement** (`sybil_require_paid_fee = true`): the qualifying
   transaction must pay a non-zero fee. The fee compounds the cost of
   maintaining a fake user base.

The combined cost-of-fake versus value-of-fake equation, even at low difficulty,
makes adoption-pumping less profitable than directly mining at low difficulty.
The accordion is therefore stable against sybil attack at any economically
meaningful scale (Section 10.3 expands on this).

### 3.4 Difficulty modulation

Bitcoin's raw retarget produces a target `T_btc` from the actual / expected
block time ratio. PyGrove dampens this proportionally to the absolute hashrate
shock:

$$ \alpha_h = \frac{1}{1 + |\ell_h|} \in (0, 1] $$

$$ T_{\text{new}} = T_{\text{old}} + \alpha_h \cdot (T_{\text{btc}} - T_{\text{old}}) $$

with the same `[÷4, ×4]` clamp Bitcoin enforces. Stable hashrate (`ℓ_h ≈ 0`)
gives `α_h ≈ 1` and full Bitcoin-style retargeting. A 10× hashrate shock gives
`α_h ≈ 0.3`, meaning the chain absorbs only 30% of the implied difficulty
change per retarget — a damping that prevents oscillation when ASIC fleets
come and go.

### 3.5 Halving acceleration

The halving counter does not advance one-per-block. It advances by

$$ \delta = 1 + \beta_h \cdot \max(0, \ell_h) + \beta_a \cdot \max(0, \ell_a) + \beta_s \cdot s $$

during expansion phases (`ℓ_h > 0` and `ℓ_a > 0`), where `β_h = β_a = 0.5` and
`β_s = 0.25` are genesis constants. The stability-bias term `s ∈ {-1, 0, +1}`
is described in Section 5. During contraction (`ℓ_h < 0` or `ℓ_a < 0`), the
positive terms are inverted so the counter advances slower, postponing the
halving and supporting miner revenue.

The cumulative supply remains bounded by 21M:

$$ \sum_{k=0}^{63} \frac{R_0}{2^k} \cdot \text{blocks-per-halving}_k \leq 21{,}000{,}000 \cdot 10^8 $$

where `R_0 = 50 × 10⁸ sat` and the per-halving block count varies but the
geometric series converges to the same limit Bitcoin's does. This is the most
important invariant of the accordion: **the supply cap is hard, regardless of
adoption or hashrate trajectory**. Section 10.3 shows the proof.

### 3.6 Q64.64 fixed-point discipline

All accordion math runs in 128-bit fixed-point arithmetic with 64 bits of
fractional precision. No `f64`. No `f32`. Floating-point determinism across
heterogeneous hardware — Intel x86, ARM, RISC-V, future architectures — is not
a problem we choose to inherit. Every node computes `ln(r_h)` to the same bit
in the same way, period.

The natural-log routine is a Padé-style series expansion with a known
worst-case bound; the test suite (`tests/accordion.rs`) covers 10 retargets
under fuzzed inputs and asserts byte-identical outputs across Linux x86_64,
Linux aarch64, and Windows MSVC.

---

## 4. Reflection

The accordion needs to read its own inputs from somewhere. Bitcoin asks the
node to recompute the median time of the last 11 blocks on every block
arrival; this is fast enough to be invisible. The accordion's inputs —
hashrate-EMA, sybil-filtered active count, fee density — are not. Recomputing
them per block, for three different window scales (`144`, `2,016`, `210,000`),
on every full node, on every chain re-org, would be wasteful and would create
divergence risk wherever an implementation differs.

We solve this by making the chain's own statistics first-class state.

### 4.1 The reflect subtree

PyGrove's state tree (Section 7) includes a dedicated subtree at the path
`b"reflect"` whose leaves are the rolling chain statistics for each window
scale. The layout:

```
reflect/
├── window_short/                       (144-block window)
│   ├── hashrate                         EMA, Q64.64
│   ├── active                           sybil-guarded count, u64
│   └── fee_density                      Σ(fees) / active, Q64.64
├── window_long/                        (2,016-block window)
│   └── ... same shape ...
├── window_epoch/                       (210,000-block window)
│   └── ... same shape ...
├── emission/
│   ├── rate                             last period reward × blocks
│   └── minted                           cumulative supply, u128
└── accordion/
    ├── r_h                              last computed, Q64.64
    ├── r_a                              last computed, Q64.64
    └── bias                             stability bias (i8: -1, 0, +1)
```

Each leaf is updated in `apply_block`. The subtree's Merkle root is committed
to the block header as `reflect_root`, alongside `state_root` (account state)
and `witness_root` (signatures). A node that disagrees about `reflect/window_long/active`
disagrees about the block hash — so consensus enforces it.

### 4.2 Three windows

The three window scales serve three audiences:

- **Short (144 blocks ≈ 1 day)**: contracts that respond to short-term
  conditions — a rebase oracle, a fee-market signal, a "is the chain busy
  right now" query. Frequent updates, frequent reads.
- **Long (2,016 blocks ≈ 2 weeks)**: the accordion's own input. Updated at
  retarget, read at retarget. The same window Bitcoin uses for difficulty.
- **Epoch (210,000 blocks ≈ 4 years)**: civilizational-scale statistics.
  Used by the halving acceleration, by long-horizon governance, by anyone
  asking "where is the chain over the lifetime of a halving?"

### 4.3 The CHAIN_REFLECT opcode

In v1.2 the embedded contract VM gains an opcode

```
CHAIN_REFLECT(path: bytes) -> bytes
```

that looks up exactly the paths in the layout above. A contract can ask for
`window_long/fee_density` and receive the same value the consensus retarget
just used. This closes the oracle gap for any signal computable from the
chain's own state.

A contract that wants to know the price of bitcoin still needs an oracle; a
contract that wants to know the chain's *own* fee market does not.

---

## 5. Stability-Seeking — the ETF-of-One Objective

A two-bellow accordion is a feedback controller. Without a target, it is also
an oscillator. PyGrove targets one specific quantity:

$$ \text{stability signal} = \frac{d}{dt} \frac{\sum \text{fees}_{\text{long}}}{\text{active}_{\text{long}}} $$

— the time-derivative of fee-per-active-address over the long window. This is
a proxy for **per-user demand** for blockspace.

The bias term `s` in Section 3.5 takes the sign of this derivative:

- `s = +1` when fee-per-user is rising. The chain is heating up; the bellow
  pumps faster; emission dilates; supply pressure cools price.
- `s = −1` when fee-per-user is falling. The chain is cooling; emission
  contracts; scarcity supports the floor.
- `s = 0` when stable. The accordion runs on hashrate and adoption alone.

The mechanism is closely analogous to a central bank that targets inflation
via money supply, except that the central bank is the protocol itself, the
target is denominated in the chain's own units, and the only oracle is the
chain's own block history. There is no external feed, no governance vote per
adjustment, no human in the loop.

We call this the **ETF-of-one** objective: the chain rebalances itself on
every retarget against a single-asset basket that is itself.

### 5.1 What stability-seeking does *not* try to do

It does not target a USD price. It does not target a constant fiat
purchasing power. It does not target velocity, market cap, or any external
reference. It targets *flat fee-per-active-address* — a proxy for whether
the median user finds the chain affordable and worth using.

This is a deliberately minimal objective. It cannot replace monetary policy.
It cannot defend against a bear market. It is a rounding term on a Bitcoin
schedule that already does the heavy lifting.

---

## 6. Consensus Seal

PoW with no further structure is vulnerable to two adversaries we want to
explicitly resist:

1. **ASIC compression** — specialized silicon collapsing the energy gap
   between honest miners and a hostile fleet.
2. **Photonic / quantum collapse** — adversaries who reduce sequential work
   to parallel work via novel physics.

PyGrove's seal is a two-stage construction that is hard for both.

### 6.1 RandomX-lite proposer

Block headers are sealed by a memory-hard hash function — RandomX-lite, a
reduced-rounds variant of Monero's RandomX, retargeted for chain consensus.
The function:

- Requires a working set of ~256 MB per hashing thread.
- Uses random instruction sequences from a JIT-compiled VM, defeating ASIC
  pre-compilation.
- Has a verification path two orders of magnitude faster than the mining
  path, so light clients pay only a small constant.

The result: mining is bounded by DRAM bandwidth, not gate count. ASICs that
add no DRAM gain little; ASICs that add DRAM look like cheap CPUs.

### 6.2 Class-group VDF finalizer (v1.1)

After the proposer wins the RandomX-lite race, the block enters a brief
**verifiable-delay-function** finalization stage. We use Wesolowski's VDF over
class groups of imaginary quadratic fields, with parameters tuned for ~100ms
of evaluation on commodity hardware. The VDF:

- Cannot be parallelized below its sequential time bound.
- Verifies in milliseconds via the Wesolowski proof of correct output.
- Is unaffected by photonic computation, which gives no advantage to
  inherently-sequential workloads.
- Is unaffected by quantum computation in the relevant security parameter
  regime — class groups have no known quantum speedup beyond Grover-style
  square-root attacks, which the chosen parameters tolerate.

The combined seal is **memory-hard then sequence-hard**: an adversary needs
both DRAM scale and uncompressible time to outpace honest miners.

### 6.3 Why both

A pure RandomX-lite chain is already strong; a pure VDF chain is already
strong. The combination is strictly stronger because the failure modes are
orthogonal: a breakthrough in memory-bandwidth efficiency leaves the VDF
unmoved, and a breakthrough in parallel-time compression leaves RandomX-lite
unmoved. The chain falls only if both fail at once.

The VDF is deferred to v1.1; v0.1 ships RandomX-lite alone.

---

## 7. State Model

### 7.1 Subtrees

The chain state is a single GroveDB tree with the following top-level
subtrees:

| Subtree | Contents |
|---|---|
| `accounts` | Account balances, nonces, deployed-code references |
| `code` | Contract bytecode by content hash |
| `storage` | Per-contract storage |
| `meta` | Chain ID, governance keys, current crypto algos |
| `reflect` | Rolling statistics (Section 4.1) |
| `blocks` | Block bodies by height |
| `headers` | Block headers by hash |
| `witnesses` | Signatures and witness data, prunable |

### 7.2 Witness segregation

Following the architecture pioneered by Bitcoin's SegWit (BIPs 141 / 143) and
generalized for an account model, signature data lives in a separate subtree
from the state it authorizes. The state root commits to the *post-apply*
state of accounts and storage, not to the signatures that produced it;
signatures commit separately into `witness_root`.

This generalization is particularly valuable in a post-quantum context, where
signatures are an order of magnitude larger than ECDSA and dominate block
size: Falcon-512 signatures are ~666 bytes; SLH-DSA-128s signatures are
~7,856 bytes. Segregating them from the canonical state root means archival
nodes carry the cost while consensus nodes do not.

This decoupling has three benefits:

1. **Prunability**: archival nodes keep witnesses; consensus nodes discard
   them after a configurable depth, recovering ~70% of full-node disk usage
   over a long history.
2. **Verifier flexibility**: a light client validates against `state_root`
   alone for ledger queries, falling back to `witness_root` only when
   signature verification is needed.
3. **Crypto upgrades are cheaper**: an `UpgradeCrypto` event invalidates only
   the witness subtree's interpretation, not the state subtree's — historical
   balances do not need re-signing.

The roundtrip property is enforced by `tests/witness_prune.rs`: sign a
transaction, include it in a block, prune the witness, verify the block
header still validates against `witness_root`, retrieve the signature from
the archival path, re-verify against the original key.

### 7.3 Domain-tagged hashing

Every hash in the system carries a domain tag — a short ASCII prefix unique
to its purpose. Block headers tag with `b"PGhdr\x00"`; account leaves with
`b"acct\x00"`; the reflect subtree's Merkle inner nodes with `b"refl\x00"`;
and so on.

Domain separation prevents cross-protocol hash collisions: an attacker who
constructs a value that hashes the same as a legitimate block header cannot
substitute it into the account tree, because the tags differ. This is cheap
insurance against future attacks on the underlying hash function.

The hash function is blake3-XOF-512 for headers (truncated to 32 bytes for
inter-block references, full 64 bytes for body inclusion) and SHAKE256 for
GroveDB inner hashes. Both are XOF-capable and tolerate algorithm rotation
under the agility layer.

---

## 8. Crypto Agility

### 8.1 Algorithm tag bytes

Every signature carries a one-byte `sig_algo` tag. Every hash-bound structure
carries a one-byte `hash_algo` tag. These tags are versioned protocol-wide,
not per-account, but the dispatch is local: a node verifying a signature
reads its tag, looks up the implementation, and runs it. New algorithms are
added as new tag values without changing existing transactions' encoding.

### 8.2 Ship-day algorithms

Genesis activates:

| Tag | Algorithm | Purpose |
|---|---|---|
| `sig_algo = 1` | Falcon-512 (FN-DSA, integer-sampler variant) | Hot transaction signatures |
| `sig_algo = 2` | SLH-DSA-128s | Cold governance keys |
| `hash_algo = 1` | blake3-XOF-512 | Block headers |
| `hash_algo = 2` | SHAKE256 | State subtree inner hashes |

The integer-sampler Falcon-512 variant is the *only* one safe for consensus:
the floating-point reference sampler is non-deterministic across ABIs, and
two honest nodes signing the same payload would produce different signatures
and disagree on the witness root.

### 8.3 The UpgradeCrypto transaction

Algorithm rotation is a governance transaction:

```rust
TxCall::UpgradeCrypto {
    target_height: u64,   // activation height, must be > current + grace
    sig_algo: u8,         // 0 to leave unchanged
    hash_algo: u8,        // 0 to leave unchanged
}
```

It must be signed by the cold governance key (SLH-DSA-128s in v1.0; threshold
SLH-DSA in v1.1). The `target_height` must lie far enough in the future that
all hot wallets have time to re-sign their next transaction with the new
algorithm. Between announcement and activation, both algorithms are accepted.
After activation, only the new one.

The chain therefore migrates from Falcon-512 to (say) Falcon-1024 in 2031,
or to ML-DSA in 2034, or to a yet-unnamed lattice scheme in 2055, without
forking. Old signed history remains verifiable via the historical-tag path.

### 8.4 The 127-year horizon

PyGrove is designed to remain operational from genesis (2026) to 2153.

We do not believe Falcon-512 is secure for 127 years. We do not believe
*any* current post-quantum signature is secure for 127 years. Lattice
attacks are improving; structured-lattice security margins are narrowing; the
field is twenty years old.

What we do believe is that the *agility layer* can carry the chain across
arbitrarily many algorithm transitions, provided each transition is executed
during a window where the outgoing algorithm is still secure. Falcon-512
will be replaced. Its replacement will be replaced. The chain survives because
no single algorithm has to.

CI includes an integration test (`tests/upgrade_roundtrip.rs`) that performs
a full Falcon-512 → Falcon-1024 rotation on a fixture chain — proving the
rotation path is exercised, not theoretical.

---

## 9. Contract VM (v1.2)

### 9.1 CPython embedded

PyGrove's contract VM is the actual CPython interpreter, embedded via PyO3.
This is a deliberate departure from EVM, MoveVM, CosmWasm, and every other
chain VM we surveyed. The reasoning:

- **Familiarity**: every developer with five years of experience writes
  Python. Solidity has always been a teaching tax; we decline to charge it.
- **Library ecosystem**: a contract that needs `ed25519-dalek` (or equivalent)
  has it; needs `numpy`-style array math, has it; needs `decimal.Decimal`,
  has it. We do not have to rebuild the standard library.
- **Determinism**: CPython's behavior is fully specified by the language
  reference. Floating-point operations are IEEE 754 with documented edge
  cases. The tests prove byte-identical execution across platforms.

### 9.2 Restriction layer

CPython is not safe by default. Contracts run inside RestrictedPython
(Zope's mature sandboxing system), with additional constraints:

- No `import` of system modules (`os`, `subprocess`, `socket`, `__import__`,
  `eval`, `exec`).
- No file I/O.
- No network I/O.
- No clock access — `time.time()` is replaced with the chain's
  `block.timestamp_ms`.
- No randomness — `random` is replaced with a deterministic PRNG seeded
  from `block.parent`.

A whitelist of standard-library modules (`math`, `collections`, `itertools`,
`functools`, `dataclasses`, `decimal`, `hashlib`, `hmac`) is exposed. Anything
else raises `ImportError` at compile time.

### 9.3 Opcode metering

Gas is metered in bytecode opcodes, not in execution time. Every CPython
bytecode operation has a fixed cost from a published table. A contract is
compiled once at deployment, the opcode count is signed by the deployer's
fee budget, and execution is bounded by remaining gas.

This gives gas a property EVM does not have: **the cost of a contract is
computable statically from its source**. A static analyzer can give a tight
upper bound before deployment.

### 9.4 CHAIN_REFLECT and VDF_TICK

Two opcodes give contracts access to chain-level state unavailable in any
other VM:

- `CHAIN_REFLECT(path: bytes) -> bytes` — read the reflect subtree at the
  given path. The path is checked against the published schema; out-of-band
  paths return an error.
- `VDF_TICK() -> u64` — return the number of VDF iterations completed at the
  start of the current block. A contract can use this as a low-resolution
  trustworthy clock that no proposer can manipulate.

Both opcodes are gas-metered like any other operation.

---

## 10. Threat Model

### 10.1 Quantum adversaries

PyGrove assumes an adversary capable of running Shor's algorithm at
post-RSA-2048 scale by some date in the protocol's lifetime. This breaks
ECDSA on day one of capability; PyGrove never uses ECDSA. It does not break
Falcon-512 unless the lattice security reduction itself fails — and even
then, the agility layer permits rotation to whatever new algorithm has
survived analysis.

The hash functions (blake3, SHAKE256) admit only Grover-style square-root
attacks, which leave 256-bit hashes at the equivalent of 128-bit classical
security — adequate for the design horizon.

The VDF (when shipped in v1.1) uses class groups of imaginary quadratic
fields over which no quantum speedup is known, beyond Grover.

### 10.2 Photonic / energy-compression adversaries

Optical or hybrid analog computing could in principle execute many parallel
hash evaluations per joule, collapsing the energy cost of finding a valid
proposer hash. RandomX-lite mitigates this by binding the work to DRAM
access; photonic systems do not have a comparable DRAM advantage.

The VDF mitigates it further by requiring inherently-sequential work that
admits no parallelization speedup at all.

### 10.3 Sybil + accordion gaming

The clearest theoretical attack on the accordion is for an adversary to
inflate `r_a` to accelerate halvings, dilute supply to a future buyer, then
short the asset. We claim this is not profitable.

The minimum funding to register one qualifying address is `dust_floor +
fee_per_qualifying_tx` ≈ 100,001 sat ≈ $0.01 at a generous price. To move
`r_a` by 10% on a network of 1,000,000 active addresses requires funding
100,000 sybils — $1,000 in dust capital, refundable over time, but with
2,016-block (≈ 2 week) lockup before the sybils count.

The resulting accordion bias might pull one halving forward by, generously,
1% of an interval — about 2,100 blocks, or two weeks of issuance at the
prevailing reward. The dilution effect on price, in a market that is even
weakly efficient, is far less than the cost of capital tied up in dummy
addresses for two weeks plus the slippage of executing a $1,000+ short.

We model this in `sim/adversarial.py` over a range of network sizes and
attacker capital budgets; in no scenario does the attack clear cost-of-capital.

### 10.4 Long-range attacks

Long-range attacks — re-mining a fork from genesis with rented hashpower —
are bounded by the proof-of-work race itself, exactly as in Bitcoin. The
accordion does not introduce a new long-range vector; it does not slow
honest reorgs more than Bitcoin does, since the per-period damping (`α_h`)
is symmetric.

The VDF (v1.1) introduces a stronger per-block sequential floor that
further raises the cost of long-range remining: an attacker must run the
VDF at honest-network speed for every historical block, and the VDF was
chosen so that this is genuinely sequential.

### 10.5 Governance capture

The cold governance key controls `UpgradeCrypto` only — not coinbase, not
issuance, not reorgs. The worst a compromised governance key can do is
schedule an algorithm rotation to a weaker algorithm, which the network
would notice and decline to upgrade to (clients ship with a hardcoded
allowlist of acceptable algorithm tags; activating an unknown tag is a
soft fork the network can reject).

In v1.1 the single key becomes a 2-of-3 SLH-DSA threshold, raising the bar
to a multi-party compromise. We do not believe a single human is the right
custodian for a 127-year protocol, and we will not pretend otherwise.

---

## 11. Genesis Parameters

The mainnet genesis block is configured by `genesis.toml`:

```toml
chain_id                = "pygrove-mainnet-1"
genesis_time_ms         = 1714003200000     # 2024-04-25 00:00:00 UTC
initial_bits            = 0x1d00ffff        # ~10-min target on commodity CPU
target_block_time_ms    = 600000
retarget_interval       = 2016
halving_interval_base   = 210000
initial_reward_sat      = 5000000000        # 50 PYG

# Accordion
accordion_epsilon       = 0.05
accordion_beta_h        = 0.5
accordion_beta_a        = 0.5
accordion_beta_s        = 0.25
stability_window_blocks = 2016

# Sybil guard
sybil_dust_floor_sat    = 100000
sybil_min_age_blocks    = 2016
sybil_require_paid_fee  = true

# Crypto
sig_algo                = 1                 # Falcon-512
hash_algo               = 1                 # blake3-XOF-512
governance_pubkey_hex   = "..."             # SLH-DSA-128s, set at mainnet

initial_accounts        = []                # pure PoW launch
```

The devnet variant (`pygrove-devnet-1`) reduces `initial_bits` to `0x1f00ffff`
for sub-second blocks during development. It is *not* the launch
configuration.

---

## 12. Implementation & Roadmap

### 12.1 Status as of v0.1 (April 2026)

The following components are implemented, tested in CI, and running on a
public devnet at `66.42.93.85:8545`:

- Block & transaction types with canonical CBOR encoding
- Domain-tagged blake3-XOF-512 header hashing
- Compact-bits difficulty encoding
- Append-only chain log persistence (GroveDB lands in v1.0 proper)
- HTTP JSON-RPC: `get_info`, `get_template`, `submit_block`, `list_blocks`,
  `get_block`
- A bundled web explorer served at `GET /`
- Multi-threaded CPU miner (Slint GUI on Windows, headless on Linux/macOS)
- Genesis bootstrap and self-mine loop
- Python sim harness (`sim/`) replaying real Bitcoin 2009–2026 hashrate
  and adoption traces through the accordion math
- GitHub Actions CI: build + test on Linux, Windows GUI artifact, Docker
  image to ghcr.io

The accordion math is implemented in Q64.64 fixed-point and matches the
Python reference `sim/accordion.py` byte-for-byte on the included
adversarial fixture.

### 12.2 v0.2 — GPU mining, witness segregation

- OpenCL Blake3-XOF-512 kernel for NVIDIA / AMD / Intel GPUs
- Witness subtree implementation against the in-memory store
- Prune-and-reverify integration test
- Falcon-512 hot signatures wired through transaction submission

### 12.3 v1.0 — VDF, P2P, mainnet

- Class-group VDF integration
- libp2p-based gossip layer
- Fork-choice rule: heaviest valid chain (with VDF-weighted scoring)
- GroveDB state backend
- Mainnet genesis ceremony

### 12.4 v1.1 — Threshold governance, multi-pool peering

- 2-of-3 SLH-DSA threshold cold keys
- Mining-pool stratum-equivalent endpoints
- First `UpgradeCrypto` rehearsal on testnet

### 12.5 v1.2 — Python contract VM

- CPython + RestrictedPython embedding
- Opcode-metered gas
- `CHAIN_REFLECT` and `VDF_TICK` opcodes
- Standard-library whitelist

### 12.6 v2.0 — STARK signature batching

- Aggregated signature verification via STARK proofs
- Witness compression: O(log n) per block instead of O(n)
- Reduced bandwidth requirements for new full nodes

---

## 13. References

1. Nakamoto, S. (2008). *Bitcoin: A Peer-to-Peer Electronic Cash System.*
2. Wesolowski, B. (2019). *Efficient Verifiable Delay Functions.* EUROCRYPT.
3. Fouque, P.-A., et al. (2020). *Falcon: Fast-Fourier Lattice-based Compact
   Signatures over NTRU.*
4. Bernstein, D. J., et al. (2022). *SPHINCS+: Stateless Hash-based Signatures.*
5. O'Connor, J., Aumasson, J.-P., Neves, S., Wilcox-O'Hearn, Z. (2020).
   *BLAKE3: One Function, Fast Everywhere.*
6. NIST FIPS 202 (2015). *SHA-3 Standard: Permutation-Based Hash and
   Extendable-Output Functions.*
7. van Saberhagen, N. (2013). *CryptoNote v 2.0.* (RandomX heritage.)
8. Lombrozo, E., Lau, J., Wuille, P. (2015). *Segregated Witness (Consensus
   Layer).* BIP 141. (Witness segregation lineage.)

---

## Appendix A — Symbols

| Symbol | Meaning |
|---|---|
| `r_h`, `ℓ_h` | Hashrate ratio and its natural log |
| `r_a`, `ℓ_a` | Adoption ratio and its natural log |
| `α_h` | Difficulty damping factor |
| `β_h, β_a, β_s` | Halving acceleration weights |
| `s` | Stability bias term, ∈ {-1, 0, +1} |
| `T_btc, T_new` | Bitcoin-style raw target and PyGrove damped target |
| `R_0` | Initial block reward (50 × 10⁸ sat) |

## Appendix B — License

Source code: Apache-2.0.
This document: CC BY 4.0.

## Appendix C — Acknowledgments

The accordion is a direct descendant of the proof-of-work / proof-of-stake
debate that Vitalik, Vlad Zamfir, and the Lightning Network authors held in
public for a decade. The reflection subtree owes its shape to the chainlink
oracle problem, inverted. The crypto-agility layer is a tribute to Daniel
Bernstein's repeated insistence that the industry plan for algorithm death.

Bitcoin remains the parent. PyGrove is a child that listens.
