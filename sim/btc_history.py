"""Real BTC 2009–2026 traces for backtesting the accordion.

Data is approximate — year-end snapshots from commonly cited aggregate sources (Chainalysis,
Triple-A, Crypto.com). The point is shape, not precision. If the accordion can't produce
sensible emission against this, the design is broken.
"""

from __future__ import annotations

# (year, holders_estimate, hashrate_EH_s)
HUMAN_SUPPLY_CURVE: list[tuple[int, int, float]] = [
    (2009, 10, 0.000_000_001),
    (2010, 1_000, 0.000_001),
    (2011, 50_000, 0.01),
    (2013, 2_000_000, 1.0),
    (2015, 4_000_000, 300.0),
    (2017, 20_000_000, 7_000.0),
    (2019, 40_000_000, 70_000.0),
    (2021, 110_000_000, 160_000.0),
    (2023, 130_000_000, 400_000.0),
    (2024, 140_000_000, 600_000.0),
    (2026, 150_000_000, 800_000.0),
]


def year_over_year() -> list[tuple[int, float, float]]:
    """Return (year, r_h, r_a) computed from the snapshot table."""
    out = []
    for prev, cur in zip(HUMAN_SUPPLY_CURVE, HUMAN_SUPPLY_CURVE[1:]):
        y0, h0, hr0 = prev
        y1, h1, hr1 = cur
        r_a = (h1 / h0) ** (1.0 / (y1 - y0))
        r_h = (hr1 / hr0) ** (1.0 / (y1 - y0))
        for _ in range(y1 - y0):
            out.append((y0 + 1, r_h, r_a))
    return out
