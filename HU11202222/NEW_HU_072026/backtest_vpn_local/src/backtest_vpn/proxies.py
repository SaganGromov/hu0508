"""Proxy labels da Fase A."""

import math
import statistics
from collections import defaultdict
from datetime import timedelta, datetime

from . import stats
from .db2 import fetch_all
from .rules import qualified, ts_params

ADMISSIBILITY = {
    "R1": {"P2", "P3", "P4"},
    "R2": {"P1", "P2", "P3", "P4"},
    "R3": {"P1", "P2", "P3", "P4"},
    "R4": {"P1", "P2", "P3"},
    "R5": {"P1", "P3", "P4"},
    "R6": {"P1", "P3", "P4"},
}

PROXY_NAMES = {
    "P1": "velocity_concurrency",
    "P2": "vpn_physical_contradiction",
    "P3": "dormancy_break",
    "P4": "machine_like_regularity",
}


def is_admissible(rule_id, proxy_id):
    if proxy_id not in ADMISSIBILITY.get(rule_id, set()):
        raise ValueError("Proxy {0} nao e admissivel para {1}".format(proxy_id, rule_id))
    return True


def _parse_ts(value):
    if isinstance(value, datetime):
        return value
    text = str(value)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d-%H.%M.%S.%f", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(text[:len(datetime.now().strftime(fmt))], fmt)
        except Exception:
            pass
    return datetime.fromisoformat(text.replace("T", " ")[:19])


def _wilson(x, n):
    lo, hi = stats.wilson_interval(x, n)
    return {"value": (x / float(n)) if n else None, "ci95": [lo, hi], "successes": x, "trials": n}


def _p1_velocity(conn, cfg):
    # A self-join no periodo completo pode ser pesada. Para esta rodada Phase-A-only,
    # registramos a definição e adiamos para extract caso o operador habilite Phase B.
    return {
        "name": PROXY_NAMES["P1"],
        "status": "deferred",
        "computed_on": "extract",
        "note": "self-join de velocidade adiado: Phase B/extract foi pulada nesta rodada",
        "users": [],
        "evidence_sample": [],
    }


def _p2_r5(cfg):
    return {
        "name": PROXY_NAMES["P2"],
        "status": "deferred_r5_skipped",
        "computed_on": "db2",
        "note": "R5 física não configurada; proxy P2 não executado",
        "users": [],
        "evidence_sample": [],
    }


def _p3_dormancy(conn, cfg, base_stats, pseudonymizer=None):
    vpn = cfg.vpn_table
    lookback_start = cfg.start - timedelta(days=cfg.dormancy_days)
    sql = (
        "SELECT DISTINCT TRIM({user}) AS USER_KEY FROM {table} "
        "WHERE {ts} >= ? AND {ts} < ?"
    ).format(user=vpn.user_column, table=qualified(vpn.schema, vpn.table), ts=vpn.timestamp_column)
    rows = fetch_all(conn, sql, (lookback_start.strftime("%Y-%m-%d %H:%M:%S"), cfg.start.strftime("%Y-%m-%d %H:%M:%S")))
    seen = {row.get("USER_KEY") for row in rows}
    users = {u for u, s in base_stats.items() if s.get("events", 0) >= 20 and u not in seen}
    sample = []
    for u in sorted(users, key=lambda x: "" if x is None else str(x))[:cfg.sample_limit]:
        s = base_stats[u]
        sample.append({"user": pseudonymizer.pseudonymize(u) if pseudonymizer else u, "events": s.get("events"), "first_ts": s.get("first_ts")})
    return {
        "name": PROXY_NAMES["P3"], "status": "measured", "computed_on": "db2",
        "dormancy_days": cfg.dormancy_days, "count": len(users), "users": users,
        "evidence_sample": sample,
    }


def _p4_regularity(conn, cfg, base_stats, pseudonymizer=None):
    vpn = cfg.vpn_table
    candidates = [u for u, s in base_stats.items() if u is not None and s.get("events", 0) >= 30]
    users = set()
    samples = []
    for offset in range(0, len(candidates), 500):
        chunk = candidates[offset:offset + 500]
        if not chunk:
            continue
        placeholders = ",".join(["?"] * len(chunk))
        sql = (
            "SELECT TRIM({user}) AS USER_KEY, {ts} AS TS FROM {table} "
            "WHERE {ts} >= ? AND {ts} < ? AND TRIM({user}) IN ({ph}) "
            "ORDER BY TRIM({user}), {ts}"
        ).format(user=vpn.user_column, ts=vpn.timestamp_column, table=qualified(vpn.schema, vpn.table), ph=placeholders)
        params = list(ts_params(cfg.start, cfg.end)) + chunk
        rows = fetch_all(conn, sql, params)
        grouped = defaultdict(list)
        for row in rows:
            grouped[row.get("USER_KEY")].append(_parse_ts(row.get("TS")))
        for user, timestamps in grouped.items():
            if len(timestamps) < 30:
                continue
            deltas = [(timestamps[i] - timestamps[i - 1]).total_seconds() for i in range(1, len(timestamps)) if (timestamps[i] - timestamps[i - 1]).total_seconds() > 0]
            if len(deltas) < 5:
                continue
            mean = sum(deltas) / len(deltas)
            if mean <= 0:
                continue
            cv = statistics.pstdev(deltas) / mean if len(deltas) > 1 else 0.0
            if cv < 0.1:
                users.add(user)
                if len(samples) < cfg.sample_limit:
                    samples.append({"user": pseudonymizer.pseudonymize(user) if pseudonymizer else user, "events": len(timestamps), "delta_cv": cv})
    return {
        "name": PROXY_NAMES["P4"], "status": "measured", "computed_on": "db2_python",
        "definition": "events>=30 and inter-arrival CV<0.1", "count": len(users), "users": users,
        "evidence_sample": samples,
    }


def _public_proxy(proxy, pseudonymizer=None):
    clean = dict(proxy)
    users = clean.pop("users", set())
    clean["count"] = clean.get("count", len(users))
    clean["user_sample"] = [pseudonymizer.pseudonymize(u) if pseudonymizer else u for u in sorted(users, key=lambda x: "" if x is None else str(x))[:100]]
    return clean


def compute_proxy_agreement(rule_id, flagged_users, proxies):
    admissible = sorted(ADMISSIBILITY[rule_id])
    usable = [pid for pid in admissible if proxies.get(pid, {}).get("status") == "measured"]
    votes = defaultdict(set)
    for pid in usable:
        for user in proxies[pid].get("users", set()):
            votes[user].add(pid)
    pseudo_positive = {user for user, fired in votes.items() if len(fired) >= 2}
    flagged = set(flagged_users)
    a = len(flagged & pseudo_positive)
    b = len(flagged)
    c = len(pseudo_positive)
    return {
        "admissible_proxies": admissible,
        "usable_proxies": usable,
        "flagged_and_proxy_positive": a,
        "flagged_total": b,
        "proxy_positive_total": c,
        "agreement_precision_surrogate": _wilson(a, b),
        "agreement_recall_surrogate": _wilson(a, c),
        "status": "estimated" if usable else "deferred",
        "assumptions": ["proxies independent of rule trigger columns", "pseudo-positives are plausibly-malicious, not confirmed"],
        "note": None if usable else "menos de dois proxies admissiveis medidos nesta rodada",
    }


def run_proxies(conn, cfg, base_stats, flag_sets, pseudonymizer=None):
    proxies = {
        "P1": _p1_velocity(conn, cfg),
        "P2": _p2_r5(cfg),
        "P3": _p3_dormancy(conn, cfg, base_stats, pseudonymizer=pseudonymizer),
        "P4": _p4_regularity(conn, cfg, base_stats, pseudonymizer=pseudonymizer),
    }
    agreement = {}
    for rid, users in flag_sets.items():
        agreement[rid] = compute_proxy_agreement(rid, users, proxies)
    public = {pid: _public_proxy(proxy, pseudonymizer=pseudonymizer) for pid, proxy in proxies.items()}
    public["admissibility_matrix"] = {rid: sorted(vals) for rid, vals in ADMISSIBILITY.items()}
    return public, agreement
