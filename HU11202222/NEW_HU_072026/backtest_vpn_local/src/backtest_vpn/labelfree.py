"""Metricas label-free da Fase A para o backtest VPN."""

import math
import statistics
import time
from collections import defaultdict
from datetime import date, datetime

from . import stats
from .db2 import fetch_all
from .rules import qualified, ts_params

RULES = {
    "R1": "ips_distintos_acima_do_limite",
    "R2": "hostnames_distintos_acima_do_limite",
    "R3": "dispositivos_distintos_acima_do_limite",
    "R4": "logins_diarios_acima_do_limite",
    "R5": "vpn_ativa_com_login_em_rede_fisica_mta",
    "R6": "vpn_ativa_com_login_em_rede_fisica_mta_multiplos_dispositivos",
}

FAMILIES = {
    "R1": "contagem",
    "R2": "contagem",
    "R3": "contagem",
    "R4": "volume",
    "R5": "contradicao",
    "R6": "contradicao",
}


def _log(metric, start):
    print("[labelfree] {0} ... ok ({1:.1f}s)".format(metric, time.time() - start))


def _int(value, default=0):
    if value is None:
        return default
    return int(value)


def _float(value):
    if value is None:
        return None
    return float(value)


def _day_value(value):
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value)
    return datetime.strptime(text[:10], "%Y-%m-%d").date()


def _bucket_from_day(value):
    day = _day_value(value)
    iso = day.isocalendar()
    return "{0:04d}-{1:02d}".format(iso[0], iso[1])


def _mean_cv(values):
    vals = [float(v) for v in values]
    if not vals:
        return (0.0, 0.0)
    mean = sum(vals) / len(vals)
    if mean == 0.0 or len(vals) == 1:
        return (mean, 0.0)
    return (mean, statistics.pstdev(vals) / mean)


def _wilson_payload(x, n):
    lo, hi = stats.wilson_interval(x, n)
    return {"value": (x / float(n)) if n else None, "ci95": [lo, hi], "successes": x, "trials": n}


def _knee(sweep):
    if len(sweep) < 3:
        return {"threshold": None, "status": "measured", "note": "grade insuficiente"}
    logs = [math.log1p(max(0, int(row["flagged"]))) for row in sweep]
    diffs = []
    for i in range(1, len(logs) - 1):
        diffs.append((abs(logs[i + 1] - 2 * logs[i] + logs[i - 1]), i))
    best, idx = max(diffs)
    if best < 0.05:
        return {"threshold": None, "status": "measured", "note": "sem cotovelo claro; limiar arbitrario"}
    return {"threshold": sweep[idx]["threshold"], "status": "measured", "note": "maior segunda diferenca em log(1+flagged)"}


def fetch_base_stats(conn, cfg):
    vpn = cfg.vpn_table
    sql = (
        "SELECT TRIM(u.{user}) AS USER_KEY, COUNT(1) AS EVENTS, "
        "COUNT(DISTINCT NULLIF(TRIM({src}), '')) AS D_SRC_IP, "
        "COUNT(DISTINCT NULLIF(TRIM({corp}), '')) AS D_CORP_IP, "
        "COUNT(DISTINCT NULLIF(TRIM({host}), '')) AS D_HOST, "
        "COUNT(DISTINCT NULLIF(TRIM({dev}), '')) AS D_DEV, "
        "COUNT(DISTINCT DATE({ts})) AS ACTIVE_DAYS, "
        "MIN({ts}) AS FIRST_TS, MAX({ts}) AS LAST_TS "
        "FROM {table} u WHERE {ts} >= ? AND {ts} < ? "
        "GROUP BY TRIM(u.{user})"
    ).format(
        user=vpn.user_column,
        src=vpn.source_ip_column,
        corp=vpn.corporate_ip_column,
        host=vpn.hostname_column,
        dev=vpn.device_column,
        ts=vpn.timestamp_column,
        table=qualified(vpn.schema, vpn.table),
    )
    rows = fetch_all(conn, sql, ts_params(cfg.start, cfg.end))
    out = {}
    for row in rows:
        key = row.get("USER_KEY")
        out[key] = {
            "user_key": key,
            "events": _int(row.get("EVENTS")),
            "distinct_source_ips": _int(row.get("D_SRC_IP")),
            "distinct_corporate_ips": _int(row.get("D_CORP_IP")),
            "distinct_hostnames": _int(row.get("D_HOST")),
            "distinct_devices": _int(row.get("D_DEV")),
            "active_days": _int(row.get("ACTIVE_DAYS")),
            "first_ts": row.get("FIRST_TS"),
            "last_ts": row.get("LAST_TS"),
            "max_daily_logins": 0,
        }
    return out


def fetch_daily_counts(conn, cfg):
    vpn = cfg.vpn_table
    sql = (
        "SELECT TRIM({user}) AS USER_KEY, DATE({ts}) AS D, COUNT(1) AS LOGINS "
        "FROM {table} WHERE {ts} >= ? AND {ts} < ? "
        "GROUP BY TRIM({user}), DATE({ts})"
    ).format(user=vpn.user_column, ts=vpn.timestamp_column, table=qualified(vpn.schema, vpn.table))
    return fetch_all(conn, sql, ts_params(cfg.start, cfg.end))


def _flag_sets(base_stats, daily_rows, cfg):
    limit = cfg.distinct_limit
    daily_limit = cfg.daily_login_limit
    r1 = {u for u, s in base_stats.items() if max(s["distinct_source_ips"], s["distinct_corporate_ips"]) > limit}
    r2 = {u for u, s in base_stats.items() if s["distinct_hostnames"] > limit}
    r3 = {u for u, s in base_stats.items() if s["distinct_devices"] > limit}
    r4_user_days = [(row.get("USER_KEY"), row.get("D")) for row in daily_rows if _int(row.get("LOGINS")) > daily_limit]
    r4 = {u for u, _ in r4_user_days}
    return {"R1": r1, "R2": r2, "R3": r3, "R4": r4, "R5": set(), "R6": set()}, r4_user_days


def _precision_ceiling(rate):
    rows = []
    for pi in (0.0001, 0.001, 0.01):
        rows.append({
            "pi": pi,
            "ceiling": None if rate in (None, 0) else min(1.0, pi / rate),
            "status": "bounded",
            "assumptions": ["fraud prevalence <= {0}".format(pi)],
        })
    return rows


def _percentile_extremity(base_stats, flagged, stat_name):
    population = sorted(s[stat_name] for s in base_stats.values())
    values = [stats.percentile_of(population, base_stats[u][stat_name]) for u in flagged if u in base_stats]
    if not values:
        return {"median": None, "min": None, "status": "measured"}
    return {"median": statistics.median(values), "min": min(values), "status": "measured"}


def _threshold_sweeps(base_stats, daily_rows, cfg):
    total_users = max(1, len([u for u in base_stats.keys() if u is not None]))
    total_user_days = max(1, len(daily_rows))
    daily_counts = [_int(row.get("LOGINS")) for row in daily_rows]
    sweeps = {}
    rulespec = {
        "R1": (cfg.sweep_distinct_limits, lambda s, k: max(s["distinct_source_ips"], s["distinct_corporate_ips"]) > k, total_users),
        "R2": (cfg.sweep_distinct_limits, lambda s, k: s["distinct_hostnames"] > k, total_users),
        "R3": (cfg.sweep_distinct_limits, lambda s, k: s["distinct_devices"] > k, total_users),
    }
    for rid, (grid, pred, denom) in rulespec.items():
        rows = []
        for k in grid:
            n = sum(1 for s in base_stats.values() if pred(s, k))
            rows.append({"threshold": k, "flagged": n, "rate": n / float(denom), "status": "measured"})
        sweeps[rid] = {"rows": rows, "suggested_threshold": _knee(rows)}
    r4_rows = []
    for k in cfg.sweep_daily_limits:
        n = sum(1 for count in daily_counts if count > k)
        r4_rows.append({"threshold": k, "flagged": n, "rate": n / float(total_user_days), "status": "measured"})
    sweeps["R4"] = {"rows": r4_rows, "suggested_threshold": _knee(r4_rows)}
    sweeps["R5"] = {"rows": [], "suggested_threshold": None, "status": "skipped", "note": "R5 não configurada; sweep de janela pulado"}
    sweeps["R6"] = {"rows": [], "suggested_threshold": None, "status": "skipped", "note": "R6 depende de R5; sweep de janela pulado"}
    return sweeps


def _temporal_stability(conn, cfg, daily_rows):
    vpn = cfg.vpn_table
    series = {rid: defaultdict(int) for rid in RULES}
    for row in daily_rows:
        if _int(row.get("LOGINS")) > cfg.daily_login_limit:
            series["R4"][_bucket_from_day(row.get("D"))] += 1
    try:
        fetch_all(conn, "SELECT VARCHAR_FORMAT(CURRENT TIMESTAMP, 'IYYY-IW') AS WK FROM SYSIBM.SYSDUMMY1", ())
        sql = (
            "SELECT VARCHAR_FORMAT({ts}, 'IYYY-IW') AS BUCKET, TRIM({user}) AS USER_KEY, "
            "COUNT(DISTINCT NULLIF(TRIM({src}), '')) AS D_SRC_IP, "
            "COUNT(DISTINCT NULLIF(TRIM({corp}), '')) AS D_CORP_IP, "
            "COUNT(DISTINCT NULLIF(TRIM({host}), '')) AS D_HOST, "
            "COUNT(DISTINCT NULLIF(TRIM({dev}), '')) AS D_DEV "
            "FROM {table} WHERE {ts} >= ? AND {ts} < ? "
            "GROUP BY VARCHAR_FORMAT({ts}, 'IYYY-IW'), TRIM({user})"
        ).format(ts=vpn.timestamp_column, user=vpn.user_column, src=vpn.source_ip_column, corp=vpn.corporate_ip_column, host=vpn.hostname_column, dev=vpn.device_column, table=qualified(vpn.schema, vpn.table))
        rows = fetch_all(conn, sql, ts_params(cfg.start, cfg.end))
        per_bucket_sets = {"R1": defaultdict(set), "R2": defaultdict(set), "R3": defaultdict(set)}
        for row in rows:
            bucket = str(row.get("BUCKET"))
            user = row.get("USER_KEY")
            if max(_int(row.get("D_SRC_IP")), _int(row.get("D_CORP_IP"))) > cfg.distinct_limit:
                per_bucket_sets["R1"][bucket].add(user)
            if _int(row.get("D_HOST")) > cfg.distinct_limit:
                per_bucket_sets["R2"][bucket].add(user)
            if _int(row.get("D_DEV")) > cfg.distinct_limit:
                per_bucket_sets["R3"][bucket].add(user)
        for rid in ("R1", "R2", "R3"):
            for bucket, users in per_bucket_sets[rid].items():
                series[rid][bucket] = len(users)
    except Exception as exc:
        out = {}
        r4_buckets = sorted(series["R4"].keys())
        r4_vals = [series["R4"].get(bucket, 0) for bucket in r4_buckets]
        mean, cv = _mean_cv(r4_vals)
        note = "consulta semanal distinta excedeu limite/ficou indisponivel: {0}".format(exc)
        for rid in ("R1", "R2", "R3"):
            out[rid] = {"buckets": [], "mean": None, "cv": None, "verdict": "pending_extract", "status": "deferred", "note": note}
        out["R4"] = {
            "buckets": [{"bucket": bucket, "flagged": series["R4"].get(bucket, 0), "status": "measured"} for bucket in r4_buckets],
            "mean": mean,
            "cv": cv,
            "verdict": "unstable" if cv > 0.5 else "stable",
            "status": "measured",
            "note": "R4 calculada a partir da agregacao diaria; R1-R3 pendentes de extract.",
        }
        out["R5"] = {"buckets": [], "mean": None, "cv": None, "verdict": "skipped", "status": "skipped", "note": "R5 não configurada"}
        out["R6"] = {"buckets": [], "mean": None, "cv": None, "verdict": "skipped", "status": "skipped", "note": "R6 depende de R5"}
        return out
    out = {}
    all_buckets = sorted(set().union(*[set(s.keys()) for s in series.values()]))
    for rid in RULES:
        if rid in ("R5", "R6"):
            out[rid] = {"buckets": [], "mean": None, "cv": None, "verdict": "skipped", "status": "skipped", "note": "{0} nao aplicavel para estabilidade temporal semanal".format(rid)}
            continue
        vals = [series[rid].get(bucket, 0) for bucket in all_buckets]
        mean, cv = _mean_cv(vals)
        out[rid] = {
            "buckets": [{"bucket": bucket, "flagged": series[rid].get(bucket, 0), "status": "measured"} for bucket in all_buckets],
            "mean": mean,
            "cv": cv,
            "verdict": "unstable" if cv > 0.5 else "stable",
            "status": "measured",
        }
    return out


def _negative_controls(base_stats, flag_sets, r4_user_days, cfg):
    primary = {u for u, s in base_stats.items() if s["events"] >= cfg.clean_cohort_min_events and s["distinct_hostnames"] == 1 and s["distinct_devices"] == 1 and s["distinct_corporate_ips"] <= 1 and s["active_days"] >= 10}
    alternative = {u for u, s in base_stats.items() if s["distinct_source_ips"] == 1 and s["distinct_corporate_ips"] <= 1 and s["events"] >= cfg.clean_cohort_min_events and s["active_days"] >= 10}
    r4_users = {u for u, _ in r4_user_days}
    out = {}
    for rid in RULES:
        if rid in ("R5", "R6"):
            out[rid] = {"cohort": "primary", "size": 0, "flagged": 0, "fpr_bound": None, "fpr_bound_wilson95_upper": None, "status": "skipped", "note": "{0} nao aplicavel em cohort negativo".format(rid)}
            continue
        cohort = alternative if rid in ("R2", "R3") else primary
        flagged_set = r4_users if rid == "R4" else flag_sets[rid]
        flagged = len(cohort & flagged_set)
        size = len(cohort)
        upper = stats.wilson_upper_bound(flagged, size) if size else None
        out[rid] = {
            "cohort": "alternative_ips_pinned" if rid in ("R2", "R3") else "primary_one_machine_steady",
            "size": size,
            "flagged": flagged,
            "fpr_bound": (flagged / float(size)) if size else None,
            "fpr_bound_wilson95_upper": upper,
            "rule_of_three_floor": stats.rule_of_three_upper(size) if size and size < 200 else None,
            "status": "bounded",
            "assumptions": ["cohort fraud prevalence ~ 0"],
        }
    return out


def _cross_rule(flag_sets, r4_user_days, pseudonymizer=None):
    ids = list(RULES.keys())
    sets = {rid: set(flag_sets.get(rid, set())) for rid in ids}
    matrix = []
    jac = []
    for a in ids:
        mrow = {"rule": a}
        jrow = {"rule": a}
        for b in ids:
            mrow[b] = len(sets[a] & sets[b])
            jrow[b] = stats.jaccard(sets[a], sets[b])
        matrix.append(mrow)
        jac.append(jrow)
    convergent = []
    union_users = set().union(*sets.values()) if sets else set()
    for user in sorted(union_users, key=lambda x: "" if x is None else str(x)):
        fired = [rid for rid in ids if user in sets[rid]]
        if len({FAMILIES[rid] for rid in fired}) >= 2:
            convergent.append({
                "user": pseudonymizer.pseudonymize(user) if pseudonymizer else user,
                "rules": fired,
                "families": sorted({FAMILIES[rid] for rid in fired}),
            })
    family_count = sets["R1"] | sets["R2"] | sets["R3"]
    family_vol = sets["R4"] | sets["R5"] | sets["R6"]
    m = len(family_count & family_vol)
    estimate = stats.chapman_estimate(len(family_count), len(family_vol), m)
    lp = {"status": "estimated", "assumptions": ["independent detection families"], "n1": len(family_count), "n2": len(family_vol), "m": m}
    if estimate is None:
        lp.update({"population_estimate": None, "union_recall_estimate": None, "note": "no overlap; estimator undefined"})
    else:
        union_n = len(family_count | family_vol)
        lp.update({"population_estimate": estimate, "union_recall_estimate": union_n / estimate if estimate else None})
    return {"overlap_matrix": matrix, "jaccard": jac, "convergent_users": convergent[:100], "convergent_total": len(convergent), "lincoln_petersen": lp}


def run_labelfree(conn, cfg, legacy_metrics=None, legacy_cases=None, pseudonymizer=None):
    """Executa as metricas label-free e retorna um dicionario consolidavel."""
    started = time.time()
    base_stats = fetch_base_stats(conn, cfg)
    _log("base_stats", started)

    started = time.time()
    daily_rows = fetch_daily_counts(conn, cfg)
    for row in daily_rows:
        user = row.get("USER_KEY")
        if user in base_stats:
            base_stats[user]["max_daily_logins"] = max(base_stats[user]["max_daily_logins"], _int(row.get("LOGINS")))
    _log("daily_counts", started)

    total_users = int((legacy_metrics or {}).get("total_users_analyzed") or len([u for u in base_stats if u is not None]))
    total_user_days = max(1, len(daily_rows))
    flag_sets, r4_user_days = _flag_sets(base_stats, daily_rows, cfg)
    r5_case = None
    r6_case = None
    if legacy_cases:
        for case in legacy_cases:
            case_name = case.get("name") if isinstance(case, dict) else getattr(case, "name", None)
            case_status = case.get("status") if isinstance(case, dict) else getattr(case, "status", None)
            if case_name == RULES["R5"]:
                r5_case = case
                if case_status == "ok":
                    sample = case.get("sample") if isinstance(case, dict) else getattr(case, "sample", [])
                    users = set()
                    for row in sample or []:
                        u = None
                        if isinstance(row, dict):
                            u = row.get("USER_KEY") or row.get("user_key") or row.get("user")
                        if u is not None:
                            users.add(str(u))
                    flag_sets["R5"] = users
                else:
                    flag_sets["R5"] = set()
            elif case_name == RULES["R6"]:
                r6_case = case
                if case_status == "ok":
                    sample = case.get("sample") if isinstance(case, dict) else getattr(case, "sample", [])
                    users = set()
                    for row in sample or []:
                        u = None
                        if isinstance(row, dict):
                            u = row.get("USER_KEY") or row.get("user_key") or row.get("user")
                        if u is not None:
                            users.add(str(u))
                    flag_sets["R6"] = users
                else:
                    flag_sets["R6"] = set()

    started = time.time()
    sweeps = _threshold_sweeps(base_stats, daily_rows, cfg)
    temporal = _temporal_stability(conn, cfg, daily_rows)
    negative = _negative_controls(base_stats, flag_sets, r4_user_days, cfg)
    cross = _cross_rule(flag_sets, r4_user_days, pseudonymizer=pseudonymizer)
    _log("derived_metrics", started)

    rules_payload = {}
    stat_map = {"R1": "distinct_ip_max", "R2": "distinct_hostnames", "R3": "distinct_devices", "R4": "max_daily_logins"}
    for s in base_stats.values():
        s["distinct_ip_max"] = max(s["distinct_source_ips"], s["distinct_corporate_ips"])
    for rid in RULES:
        if rid in ("R5", "R6"):
            case_obj = r5_case if rid == "R5" else r6_case
            r5_status = None
            r5_count = 0
            r5_note = "Caso {0} nao configurado nesta execucao.".format(rid)
            if case_obj is not None:
                r5_status = case_obj.get("status") if isinstance(case_obj, dict) else getattr(case_obj, "status", None)
                r5_count = case_obj.get("count") if isinstance(case_obj, dict) else getattr(case_obj, "count", 0)
                r5_note = case_obj.get("note") if isinstance(case_obj, dict) else getattr(case_obj, "note", r5_note)
            if r5_status == "ok":
                flagged_users = len(flag_sets[rid])
                rate = flagged_users / float(total_users) if total_users else None
                rules_payload[rid] = {
                    "name": RULES[rid], "flagged": int(r5_count or 0),
                    "flagged_users": flagged_users,
                    "alert_rate": rate,
                    "user_alert_rate": rate,
                    "percentile_extremity": {"median": None, "min": None, "status": "not_applicable"},
                    "precision_ceiling": _precision_ceiling(rate),
                    "threshold_sweep": [], "suggested_threshold": None,
                    "temporal_stability": temporal[rid], "negative_control": negative[rid],
                    "proxy_agreement": None, "injected_recall": {"status": "not_run", "value": None},
                    "adjudicated_precision": {"status": "not_run", "value": None},
                    "true_rates": "not_available_without_validated_labels",
                    "status": "ok", "note": r5_note,
                    "status_tags": {
                        "flagged": "measured", "alert_rate": "measured",
                        "user_alert_rate": "measured",
                        "threshold_sweep": "not_applicable",
                        "temporal_stability.cv": temporal[rid].get("status", "skipped"),
                        "negative_control.fpr_bound_wilson95_upper": negative[rid].get("status", "skipped"),
                    },
                }
            else:
                rules_payload[rid] = {
                    "name": RULES[rid], "flagged": 0, "alert_rate": 0.0,
                    "percentile_extremity": {"median": None, "min": None, "status": "skipped"},
                    "precision_ceiling": _precision_ceiling(0.0),
                    "threshold_sweep": [], "suggested_threshold": None,
                    "temporal_stability": temporal[rid], "negative_control": negative[rid],
                    "proxy_agreement": None, "injected_recall": {"status": "not_run", "value": None},
                    "adjudicated_precision": {"status": "not_run", "value": None},
                    "true_rates": "not_available_without_validated_labels",
                    "status": "skipped", "note": r5_note,
                    "status_tags": {"flagged": "skipped", "alert_rate": "skipped", "threshold_sweep": "skipped", "temporal_stability.cv": "skipped", "negative_control.fpr_bound_wilson95_upper": "skipped"},
                }
            continue
        if rid == "R4":
            flagged = len(r4_user_days)
            user_flagged = len(flag_sets[rid])
            rate = flagged / float(total_user_days)
        else:
            flagged = len(flag_sets[rid])
            user_flagged = flagged
            rate = flagged / float(total_users) if total_users else None
        rules_payload[rid] = {
            "name": RULES[rid],
            "flagged": flagged,
            "flagged_users": user_flagged,
            "alert_rate": rate,
            "user_alert_rate": user_flagged / float(total_users) if total_users else None,
            "percentile_extremity": _percentile_extremity(base_stats, flag_sets[rid], stat_map[rid]),
            "precision_ceiling": _precision_ceiling(rate),
            "threshold_sweep": sweeps[rid]["rows"],
            "suggested_threshold": sweeps[rid]["suggested_threshold"],
            "temporal_stability": temporal[rid],
            "negative_control": negative[rid],
            "proxy_agreement": None,
            "injected_recall": {"status": "not_run", "value": None},
            "adjudicated_precision": {"status": "not_run", "value": None},
            "true_rates": "not_available_without_validated_labels",
            "status_tags": {
                "flagged": "measured", "alert_rate": "measured", "user_alert_rate": "measured",
                "percentile_extremity.median": "measured", "percentile_extremity.min": "measured",
                "precision_ceiling": "bounded", "threshold_sweep": "measured", "suggested_threshold": "measured",
                "temporal_stability.cv": temporal[rid].get("status", "measured"),
                "negative_control.fpr_bound": "bounded", "negative_control.fpr_bound_wilson95_upper": "bounded",
                "injected_recall": "not_run", "adjudicated_precision": "not_run",
            },
        }
    return {"rules": rules_payload, "cross_rule": cross, "base_stats": base_stats, "daily_rows": daily_rows, "flag_sets": flag_sets, "r4_user_days": r4_user_days}
