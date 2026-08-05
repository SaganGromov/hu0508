"""Funcoes estatisticas pequenas usadas pelo backtest VPN."""

import math
from bisect import bisect_right


Z95 = 1.959963984540054


def wilson_interval(successes, trials, z=Z95):
    """Intervalo de Wilson bilateral para uma proporcao."""
    x = int(successes)
    n = int(trials)
    if n <= 0:
        return (None, None)
    if x < 0 or x > n:
        raise ValueError("successes deve estar entre 0 e trials")
    phat = x / float(n)
    denom = 1.0 + (z * z) / n
    centre = phat + (z * z) / (2.0 * n)
    margin = z * math.sqrt((phat * (1.0 - phat) / n) + ((z * z) / (4.0 * n * n)))
    return (max(0.0, (centre - margin) / denom), min(1.0, (centre + margin) / denom))


def wilson_upper_bound(successes, trials, z=Z95):
    """Limite superior de Wilson 95% para uma proporcao."""
    return wilson_interval(successes, trials, z)[1]


def rule_of_three_upper(trials):
    """Aproximacao 95% superior quando zero eventos foram observados."""
    n = int(trials)
    if n <= 0:
        return None
    return min(1.0, 3.0 / n)


def percentile_of(sorted_values, value):
    """Percentil empirico (CDF inclusiva) de value em sorted_values."""
    vals = list(sorted_values)
    if not vals:
        return None
    return bisect_right(vals, value) / float(len(vals))


def jaccard(left, right):
    """Indice de Jaccard entre dois conjuntos."""
    a = set(left)
    b = set(right)
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / float(len(union))


def cohen_kappa(pairs):
    """Cohen kappa para pares (rotulo_a, rotulo_b)."""
    items = list(pairs)
    n = len(items)
    if n == 0:
        return None
    labels = sorted(set([a for a, _ in items] + [b for _, b in items]))
    agree = sum(1 for a, b in items if a == b) / float(n)
    pa = {label: 0 for label in labels}
    pb = {label: 0 for label in labels}
    for a, b in items:
        pa[a] += 1
        pb[b] += 1
    expected = sum((pa[label] / float(n)) * (pb[label] / float(n)) for label in labels)
    if expected == 1.0:
        return 1.0 if agree == 1.0 else None
    return (agree - expected) / (1.0 - expected)


def chapman_estimate(n1, n2, m):
    """Estimador Chapman para captura-recaptura; None quando m=0."""
    n1 = int(n1)
    n2 = int(n2)
    m = int(m)
    if m <= 0:
        return None
    return (((n1 + 1.0) * (n2 + 1.0)) / (m + 1.0)) - 1.0
