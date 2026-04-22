"""Replay traces through the accordion and emit a supply / emission summary."""

from __future__ import annotations

from accordion import Params, evaluate
from btc_history import year_over_year
from adversarial import bubble, plateau, renaissance, crash


HALVING_BASE = 210_000
INITIAL_REWARD = 50 * 10**8
SUPPLY_CAP = 21_000_000 * 10**8


def simulate(trace, retarget_interval: int = 2016) -> dict:
    p = Params()
    halving_progress = 0.0
    minted = 0
    halvings = 0
    regimes = {"equilibrium": 0, "growth": 0, "contraction": 0}
    for r_h, r_a, bias in _normalize(trace):
        out = evaluate(r_h, r_a, bias, p)
        regimes[out["regime"]] += 1
        for _ in range(retarget_interval):
            halving_progress += out["advance"]
            while halving_progress >= (halvings + 1) * HALVING_BASE:
                halvings += 1
            reward = INITIAL_REWARD >> min(halvings, 63)
            if minted + reward > SUPPLY_CAP:
                reward = max(0, SUPPLY_CAP - minted)
            minted += reward
    return {
        "minted_sat": minted,
        "minted_btc_equivalent": minted / 10**8,
        "halvings": halvings,
        "regimes": regimes,
        "supply_cap_respected": minted <= SUPPLY_CAP,
    }


def _normalize(trace):
    for entry in trace:
        if len(entry) == 3:
            yield entry
        else:
            _, r_h, r_a = entry
            yield r_h, r_a, 0


if __name__ == "__main__":
    scenarios = {
        "bitcoin_history": year_over_year(),
        "bubble": bubble(50),
        "plateau": plateau(50),
        "renaissance": renaissance(50),
        "crash": crash(50),
    }
    for name, trace in scenarios.items():
        r = simulate(trace)
        print(
            f"{name:>18s}  "
            f"minted={r['minted_btc_equivalent']:>12,.0f}  "
            f"halvings={r['halvings']:>3}  "
            f"cap_ok={r['supply_cap_respected']}  "
            f"regimes={r['regimes']}"
        )
