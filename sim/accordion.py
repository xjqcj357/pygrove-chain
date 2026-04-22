"""Accordion — executable reference for the consensus/accordion.rs math.

The Rust crate is authoritative; this file exists so humans can read, plot, and
stress-test the schedule without a Rust toolchain.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class Params:
    epsilon: float = 0.05
    beta_h: float = 0.5
    beta_a: float = 0.5
    beta_s: float = 0.25


@dataclass
class State:
    halving_progress: float = 0.0
    minted_sat: int = 0
    old_target_hi: int = 0


def regime(lh: float, la: float, eps: float) -> str:
    if abs(lh) <= eps and abs(la) <= eps:
        return "equilibrium"
    if lh >= 0 and la >= 0:
        return "growth"
    return "contraction"


def evaluate(r_h: float, r_a: float, stability_bias: int, p: Params) -> dict:
    """Mirror crates/consensus/src/accordion.rs::evaluate."""
    lh = math.log(r_h) if r_h > 0 else 0.0
    la = math.log(r_a) if r_a > 0 else 0.0
    reg = regime(lh, la, p.epsilon)
    alpha_h = 1.0 / (1.0 + abs(lh))
    if reg == "equilibrium":
        advance = 1.0
    elif reg == "growth":
        advance = (
            1.0
            + p.beta_h * max(0.0, lh)
            + p.beta_a * max(0.0, la)
            + p.beta_s * stability_bias
        )
    else:
        advance = 1.0 / (1.0 + p.beta_h * max(0.0, -lh) + p.beta_a * max(0.0, -la))
    return {"regime": reg, "alpha_h": alpha_h, "advance": advance, "lh": lh, "la": la}


if __name__ == "__main__":
    p = Params()
    for r_h, r_a, bias in [
        (1.0, 1.0, 0),
        (2.0, 2.0, 1),
        (0.5, 0.5, -1),
        (1.5, 0.8, 0),
    ]:
        out = evaluate(r_h, r_a, bias, p)
        print(f"r_h={r_h:>4} r_a={r_a:>4} bias={bias:>2} -> {out}")
