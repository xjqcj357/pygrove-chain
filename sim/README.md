# PyGrove Accordion Simulator

Pure-Python reference for the accordion math in `crates/consensus/src/accordion.rs`.

```bash
python -m pip install numpy
python backtest.py
```

Prints a one-line report per scenario:

- `bitcoin_history` — replays approximate 2009–2026 traces through the accordion and asks whether the supply stays under 21M and halvings happen in a sane order.
- `bubble`, `plateau`, `renaissance`, `crash` — synthetic adversarial traces for stress-testing.

The Rust crate is authoritative. This file exists so humans can sanity-check the schedule without a Rust toolchain.
