"""Consolidacao do results_bundle da metodologia next-best-thing."""

import copy
import subprocess
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path

from . import report

METHODOLOGY_VERSION = "next-best-thing/1.0"
RULE_IDS_BY_NAME = {
    "ips_distintos_acima_do_limite": "R1",
    "hostnames_distintos_acima_do_limite": "R2",
    "dispositivos_distintos_acima_do_limite": "R3",
    "logins_diarios_acima_do_limite": "R4",
    "vpn_ativa_com_login_em_rede_fisica_mta": "R5",
    "vpn_ativa_com_login_em_rede_fisica_mta_multiplos_dispositivos": "R6",
}


def git_commit(repo_root):
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo_root), text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
        return result.stdout.strip()
    except Exception:
        return "unknown"


def strip_sensitive_parameters(params):
    blocked = {"credentials_file", "output_dir"}
    clean = {}
    for key, value in (params or {}).items():
        if key in blocked:
            continue
        if key == "jdbc_url":
            clean[key] = "db2://redacted"
            continue
        clean[key] = value
    return clean


def _case_to_dict(case):
    if is_dataclass(case):
        return asdict(case)
    return dict(case)


def _pseudonymize_obj(value, pseudonymizer):
    if isinstance(value, list):
        return [_pseudonymize_obj(item, pseudonymizer) for item in value]
    if isinstance(value, dict):
        out = {}
        for key, val in value.items():
            if key.upper().endswith("USER_KEY") or key.lower() in ("user", "user_key"):
                out[key] = pseudonymizer.pseudonymize(val)
            else:
                out[key] = _pseudonymize_obj(val, pseudonymizer)
        return out
    return value


def legacy_summary(legacy_metrics, legacy_cases, pseudonymizer):
    cases = []
    counts = {}
    for case in legacy_cases or []:
        cd = _case_to_dict(case)
        rid = RULE_IDS_BY_NAME.get(cd.get("name"))
        if rid:
            counts[rid] = cd.get("count", 0)
        cases.append(_pseudonymize_obj(cd, pseudonymizer))
    return {
        "metrics": dict(legacy_metrics or {}),
        "cases": cases,
        "case_counts": counts,
        "true_rates": "not_available_without_validated_labels",
        "status_tags": {
            "total_events_analyzed": "measured",
            "total_users_analyzed": "measured",
            "vpn_classified_cases": "measured",
            "false_positive_rate": "not_available_without_validated_labels",
            "false_negative_rate": "not_available_without_validated_labels",
        },
    }


def build_results_bundle(cfg, parameters, legacy_metrics, legacy_cases, labelfree_payload, proxies_payload, proxy_agreement, pseudonymizer, repo_root, generated_at=None):
    generated_at = generated_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rules = copy.deepcopy(labelfree_payload["rules"])
    for rid, agreement in (proxy_agreement or {}).items():
        if rid in rules:
            rules[rid]["proxy_agreement"] = agreement
            rules[rid].setdefault("status_tags", {})["proxy_agreement.agreement_precision_surrogate"] = agreement.get("status", "estimated")
            rules[rid].setdefault("status_tags", {})["proxy_agreement.agreement_recall_surrogate"] = agreement.get("status", "estimated")
    payload = {
        "bundle_version": 1,
        "methodology_version": METHODOLOGY_VERSION,
        "generated_at": generated_at,
        "git_commit": git_commit(repo_root),
        "parameters": strip_sensitive_parameters(parameters),
        "pseudonymization": {"algorithm": "HMAC-SHA256", "key_id": pseudonymizer.key_id},
        "summary": legacy_summary(legacy_metrics, legacy_cases, pseudonymizer),
        "rules": rules,
        "cross_rule": labelfree_payload.get("cross_rule", {}),
        "proxies": proxies_payload or {},
        "injection": {"status": "not_run", "injected_recall": None, "note": "Phase B pulada nesta rodada"},
        "adjudication": {"status": "not_run", "adjudicated_precision": None, "note": "Phase C pulada nesta rodada"},
        "limitations": [
            "Nao existem rotulos validados de fraude; true FP/FN permanecem not_available_without_validated_labels.",
            "Geolocalização de IP não estava disponível; P1 usa a definição sem geolocalizacao, mas foi deferida para extract nesta rodada.",
            "Fase B (injeção sintetica) e Fase C (adjudicação) não foram executadas nesta rodada.",
            "As estimativas de proxy são sinais surrogate, não precisão/recall reais.",
        ],
    }
    return payload


def write_results_bundle(output_dir, stamp, payload):
    path = Path(output_dir) / "results_bundle_{0}.json".format(stamp)
    report.write_json(path, payload)
    return path


def sanitize_for_html(value):
    """Remove credenciais, URLs internas e caminhos antes do data island HTML."""
    if isinstance(value, dict):
        out = {}
        for key, val in value.items():
            lower = key.lower()
            if any(token in lower for token in ("credential", "password", "secret")):
                continue
            if lower in ("output_dir", "path", "file", "credentials_file") or lower.endswith("_path") or lower.endswith("_file"):
                continue
            if lower == "jdbc_url":
                out[key] = "db2://redacted"
            else:
                out[key] = sanitize_for_html(val)
        return out
    if isinstance(value, list):
        return [sanitize_for_html(item) for item in value]
    if isinstance(value, str):
        if value.startswith("/") or value.startswith("~") or "://" in value:
            return "redacted"
    return value
