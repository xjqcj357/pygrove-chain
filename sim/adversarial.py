"""Synthetic adversarial traces for the accordion.

Each trace yields (r_h, r_a, stability_bias) tuples per retarget period. Feed them into
accordion.evaluate to observe regime, dampening, and halving acceleration.
"""

from __future__ import annotations

import math


def bubble(periods: int) -> list[tuple[float, float, int]]:
    """Hyper-growth, then collapse."""
    out = []
    for i in range(periods):
        t = i / periods
        if t < 0.7:
            out.append((1.0 + 0.6 * t, 1.0 + 0.9 * t, 1))
        else:
            out.append((max(0.2, 1.0 - (t - 0.7) * 3), max(0.3, 1.0 - (t - 0.7) * 2.5), -1))
    return out


def plateau(periods: int) -> list[tuple[float, float, int]]:
    return [(1.0, 1.0, 0) for _ in range(periods)]


def renaissance(periods: int) -> list[tuple[float, float, int]]:
    """Slow steady compounding."""
    out = []
    for i in range(periods):
        g = 1.0 + 0.02 * math.sin(i / 8) + 0.05
        out.append((g, g * 1.1, 1))
    return out


def crash(periods: int) -> list[tuple[float, float, int]]:
    return [(0.7, 0.6, -1) for _ in range(periods)]
