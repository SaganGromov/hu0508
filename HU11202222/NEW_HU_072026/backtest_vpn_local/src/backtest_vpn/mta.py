"""Correlacao com DB2PEP.MTA_AUT_CLI_TRAN para detectar sessao autenticada
paralela a uma sessao VPN ativa (login em rede fisica).

O modulo e desenhado para operar dentro dos limites do ambiente DB2 for z/OS
disponivel:

* ASUTIME (~9 segundos de CPU por statement, SQL0905N): todo predicado usa
  a chave primaria `CD_IDFR_MTA` como bracketing, filtra por
  `IN_SCS_EXEA_ETP='s'` e por uma lista curta de `NM_ETP`, e limita as
  linhas retornadas via `FETCH FIRST`.
* SUBSTR(varchar_col, 1, N) nao funciona nessa instancia; onde e preciso
  truncar `JS_INF_CLI` para o transporte, usamos `LEFT(col, N)`.
* JSON_VALUE / JSON_QUERY nao estao disponiveis: o parse do JSON de
  `JS_INF_CLI` (`username` e `ipCliente`) e feito em Python.
"""

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, List, Optional, Tuple

from .db2 import fetch_all

DEFAULT_SCHEMA = "DB2PEP"
DEFAULT_TABLE = "MTA_AUT_CLI_TRAN"
DEFAULT_DECISION_NODES = (
    "BBShowUserAttributesNode",
    "BBPasswordDecisionNode",
    "BBTOTPDecisionNode",
    "BBOfdDecisionNode",
)
DEFAULT_IP_CIDRS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
)
_IDENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_USERNAME_RE = re.compile(r'"username"\s*:\s*"([^"\\]{1,64})"')
_IPCLIENTE_RE = re.compile(r'"ipCliente"\s*:\s*"([0-9a-fA-F:.]{3,45})"')
_TS_FORMAT = "%Y-%m-%d %H:%M:%S"


@dataclass(frozen=True)
class MtaConfig:
    """Parametros para consulta em MTA_AUT_CLI_TRAN."""

    schema: str = DEFAULT_SCHEMA
    table: str = DEFAULT_TABLE
    decision_nodes: Tuple[str, ...] = DEFAULT_DECISION_NODES
    success_flag: str = "s"
    ip_networks: Tuple[ipaddress._BaseNetwork, ...] = field(
        default_factory=lambda: tuple(ipaddress.ip_network(c) for c in DEFAULT_IP_CIDRS)
    )
    delta_minutes: int = 15
    max_users_per_run: int = 300
    users_per_batch: int = 12
    fetch_first_rows: int = 400
    rate_calibration_id_span: int = 4000
    chunk_hours: int = 24


def _norm_identifier(value, label):
    text = str(value or "").strip()
    if not text or not _IDENT_RE.match(text):
        raise ValueError("{0}: identificador SQL invalido: {1!r}".format(label, value))
    return text.upper()


def _norm_node_name(value):
    text = str(value or "").strip()
    if not text or not re.match(r"^[A-Za-z][A-Za-z0-9_]{1,63}$", text):
        raise ValueError("Nome de NM_ETP invalido: {0!r}".format(value))
    return text


def _parse_cidrs(text):
    if not text:
        return tuple(ipaddress.ip_network(c) for c in DEFAULT_IP_CIDRS)
    parts = [p.strip() for p in str(text).split(",") if p.strip()]
    return tuple(ipaddress.ip_network(p, strict=False) for p in parts)


def load_mta_config_from_env(env=None):
    """Le a MtaConfig a partir de variaveis de ambiente (todas opcionais).

    Retorna sempre um MtaConfig com defaults sensatos.
    """
    env = os.environ if env is None else env
    schema = _norm_identifier(env.get("MTA_SCHEMA", DEFAULT_SCHEMA), "MTA_SCHEMA")
    table = _norm_identifier(env.get("MTA_TABLE", DEFAULT_TABLE), "MTA_TABLE")
    nodes_raw = env.get("MTA_DECISION_NODES") or ",".join(DEFAULT_DECISION_NODES)
    nodes = tuple(_norm_node_name(n) for n in nodes_raw.split(",") if n.strip())
    networks = _parse_cidrs(env.get("PHYSICAL_IP_CIDRS"))
    delta = int(env.get("MTA_DELTA_MINUTES", 15))
    if delta <= 0 or delta > 720:
        raise ValueError("MTA_DELTA_MINUTES deve estar entre 1 e 720.")
    max_users = int(env.get("MTA_MAX_USERS", 300))
    if max_users <= 0:
        raise ValueError("MTA_MAX_USERS deve ser positivo.")
    per_batch = int(env.get("MTA_USERS_PER_BATCH", 12))
    if per_batch <= 0 or per_batch > 40:
        raise ValueError("MTA_USERS_PER_BATCH deve estar entre 1 e 40.")
    chunk_hours = int(env.get("MTA_CHUNK_HOURS", 24))
    if chunk_hours <= 0 or chunk_hours > 168:
        raise ValueError("MTA_CHUNK_HOURS deve estar entre 1 e 168.")
    return MtaConfig(
        schema=schema,
        table=table,
        decision_nodes=nodes,
        ip_networks=networks,
        delta_minutes=delta,
        max_users_per_run=max_users,
        users_per_batch=per_batch,
        chunk_hours=chunk_hours,
    )


def qualified(mta):
    return "{0}.{1}".format(mta.schema, mta.table)


# ---------------------------------------------------------------------------
# JSON parsing (client-side)
# ---------------------------------------------------------------------------


def extract_username(js_inf_cli):
    """Retorna o valor de `username` embutido em JS_INF_CLI.

    Faz duas tentativas: JSON estruturado (rapido e preciso) e, se falhar,
    regex tolerante a JSON parcial/truncado.
    """
    if not js_inf_cli:
        return None
    text = str(js_inf_cli)
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                obj = item.get("object") if isinstance(item.get("object"), dict) else None
                if obj and obj.get("username"):
                    return str(obj["username"]).strip() or None
                if item.get("username"):
                    return str(item["username"]).strip() or None
    m = _USERNAME_RE.search(text)
    return m.group(1) if m else None


def extract_ip_cliente(js_inf_cli):
    """Retorna o valor de `ipCliente` embutido em JS_INF_CLI, ou None."""
    if not js_inf_cli:
        return None
    text = str(js_inf_cli)
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("ipCliente"):
                return str(item["ipCliente"]).strip() or None
    m = _IPCLIENTE_RE.search(text)
    return m.group(1) if m else None


def ip_in_networks(ip_text, networks):
    """True se `ip_text` for um IP valido dentro de uma das redes fornecidas."""
    if not ip_text or not networks:
        return False
    try:
        ip = ipaddress.ip_address(str(ip_text).strip())
    except ValueError:
        return False
    for net in networks:
        if ip.version == net.version and ip in net:
            return True
    return False


def dedup_matches(rows):
    """Deduplica por CD_UNCO_TRAN mantendo o TS_TRAN mais antigo do fluxo."""
    best = {}
    for r in rows:
        key = r.get("cd_unco_tran")
        if key is None or str(key).strip().lower() == "null":
            key = ("no_flow", r.get("cd_idfr_mta"))
        cur = best.get(key)
        if cur is None or (r.get("ts_tran") and (cur.get("ts_tran") is None or r["ts_tran"] < cur["ts_tran"])):
            best[key] = r
    return sorted(best.values(), key=lambda x: (x.get("ts_tran") or datetime.max))


# ---------------------------------------------------------------------------
# PK <-> timestamp bracketing (MTA has no TS_TRAN index)
# ---------------------------------------------------------------------------


def _fetch_scalar(conn, sql, params=()):
    rows = fetch_all(conn, sql, params)
    if not rows:
        return None
    row = rows[0]
    return next(iter(row.values()))


def _fetch_min_max_id(conn, mta):
    row_min = _fetch_scalar(conn, "SELECT MIN(CD_IDFR_MTA) FROM {0}".format(qualified(mta)))
    row_max = _fetch_scalar(conn, "SELECT MAX(CD_IDFR_MTA) FROM {0}".format(qualified(mta)))
    if row_min is None or row_max is None:
        return None, None
    return int(row_min), int(row_max)


def _fetch_ts_at_or_after(conn, mta, pk):
    """Retorna o TS_TRAN do primeiro registro com CD_IDFR_MTA >= pk (ou None)."""
    sql = (
        "SELECT TS_TRAN FROM {0} WHERE CD_IDFR_MTA >= ? "
        "ORDER BY CD_IDFR_MTA ASC FETCH FIRST 1 ROW ONLY"
    ).format(qualified(mta))
    return _fetch_scalar(conn, sql, (pk,))


def estimate_pk_window(conn, mta, ts_lo, ts_hi, safety=0.20):
    """Aproxima [id_lo, id_hi] cobrindo o intervalo [ts_lo, ts_hi].

    Estrategia: amostra 3 ancoras (min, meio, max), estima taxa de linhas
    por segundo, e projeta a janela por PK. Adiciona `safety` de margem em
    cada lado. Nunca retorna janela vazia; se algo falhar, devolve
    (min_id, max_id) do inteiro da tabela.
    """
    if ts_hi <= ts_lo:
        raise ValueError("ts_hi deve ser maior que ts_lo")
    id_min, id_max = _fetch_min_max_id(conn, mta)
    if id_min is None:
        return None, None
    id_mid = id_min + (id_max - id_min) // 2
    try:
        ts_at_min = _fetch_ts_at_or_after(conn, mta, id_min)
        ts_at_mid = _fetch_ts_at_or_after(conn, mta, id_mid)
        ts_at_max = _fetch_ts_at_or_after(conn, mta, id_max)
    except Exception:
        return id_min, id_max
    anchors = [
        (id_min, ts_at_min),
        (id_mid, ts_at_mid),
        (id_max, ts_at_max),
    ]
    anchors = [(i, t) for i, t in anchors if t is not None]
    if len(anchors) < 2:
        return id_min, id_max

    def project(target_ts):
        # linear interpolation between the two closest anchors
        anchors_sorted = sorted(anchors, key=lambda p: p[1])
        if target_ts <= anchors_sorted[0][1]:
            lo_i, lo_t = anchors_sorted[0]
            hi_i, hi_t = anchors_sorted[1]
        elif target_ts >= anchors_sorted[-1][1]:
            lo_i, lo_t = anchors_sorted[-2]
            hi_i, hi_t = anchors_sorted[-1]
        else:
            for k in range(len(anchors_sorted) - 1):
                if anchors_sorted[k][1] <= target_ts <= anchors_sorted[k + 1][1]:
                    lo_i, lo_t = anchors_sorted[k]
                    hi_i, hi_t = anchors_sorted[k + 1]
                    break
        span_secs = max(1.0, (hi_t - lo_t).total_seconds())
        rate = float(hi_i - lo_i) / span_secs  # ids per second
        rate = max(rate, 1.0)
        delta_secs = (target_ts - lo_t).total_seconds()
        return int(lo_i + rate * delta_secs)

    id_lo = project(ts_lo)
    id_hi = project(ts_hi)
    total_span = max(1, id_hi - id_lo)
    margin = int(total_span * safety) + 1000
    id_lo = max(id_min, id_lo - margin)
    id_hi = min(id_max, id_hi + margin)
    if id_lo > id_hi:
        id_lo, id_hi = id_min, id_max
    return id_lo, id_hi


# ---------------------------------------------------------------------------
# MTA query: batched LIKE by username, PK+TS bracketed
# ---------------------------------------------------------------------------


def _ts_str(ts):
    return ts.strftime(_TS_FORMAT)


def _like_pattern_username(username):
    # Match "username":"<user>" tolerating spaces after ':'
    return '%"username":"' + str(username).strip() + '"%'


def find_mta_matches_for_users(
    conn, mta, users, id_lo, id_hi, ts_lo, ts_hi, node_names=None, limit=None
):
    """Consulta MTA_AUT_CLI_TRAN por um lote de usernames.

    Aplica todos os filtros seguros (PK, TS, sucesso, NM_ETP). O filtro
    OR-de-LIKEs por username evita escanear a tabela inteira; a PK bracket
    protege o ASUTIME.
    """
    if not users:
        return []
    node_names = tuple(node_names or mta.decision_nodes)
    if not node_names:
        raise ValueError("Nenhum NM_ETP configurado para filtro.")
    limit = int(limit or mta.fetch_first_rows)
    like_clauses = " OR ".join(["JS_INF_CLI LIKE ?"] * len(users))
    node_marks = ", ".join(["?"] * len(node_names))
    sql = (
        "SELECT CD_IDFR_MTA, CD_UNCO_TRAN, CD_CLI_TRAN, TS_TRAN, NM_ETP, IN_SCS_EXEA_ETP, "
        "LEFT(JS_INF_CLI, 1500) AS JS_INF_CLI "
        "FROM {tbl} "
        "WHERE CD_IDFR_MTA BETWEEN ? AND ? "
        "AND TS_TRAN BETWEEN ? AND ? "
        "AND IN_SCS_EXEA_ETP = ? "
        "AND NM_ETP IN ({nodes}) "
        "AND ({likes}) "
        "FETCH FIRST {n} ROWS ONLY"
    ).format(
        tbl=qualified(mta),
        nodes=node_marks,
        likes=like_clauses,
        n=limit,
    )
    params = [id_lo, id_hi, _ts_str(ts_lo), _ts_str(ts_hi), mta.success_flag]
    params.extend(node_names)
    params.extend(_like_pattern_username(u) for u in users)
    rows = fetch_all(conn, sql, params)
    out = []
    for row in rows:
        js = row.get("JS_INF_CLI")
        username = extract_username(js)
        ip = extract_ip_cliente(js)
        nm_etp = str(row.get("NM_ETP") or "").strip()
        cd_unco = str(row.get("CD_UNCO_TRAN") or "").strip() or None
        ts = row.get("TS_TRAN")
        out.append({
            "cd_idfr_mta": int(row.get("CD_IDFR_MTA")) if row.get("CD_IDFR_MTA") is not None else None,
            "cd_unco_tran": cd_unco,
            "cd_cli_tran": (str(row.get("CD_CLI_TRAN")).strip() if row.get("CD_CLI_TRAN") is not None else None),
            "ts_tran": ts,
            "nm_etp": nm_etp,
            "username": username,
            "ip_cliente": ip,
        })
    return out


def match_vpn_events(conn, mta, vpn_events_by_user, delta_minutes=None):
    """Correlaciona eventos VPN com sessoes fisicas em MTA.

    `vpn_events_by_user` deve ser dict[str, list[dict(ts, cptv_ip)]].
    Retorna dict[str, list[match]] onde cada match contem:
        - ts_vpn, cptv_ip, ts_mta, ip_cliente, cd_unco_tran, nm_etp

    Estrategia:
        1. Para cada usuario, calcula [ts_lo, ts_hi] = [min_ts-D, max_ts+D].
        2. Agrupa usuarios em lotes cujas janelas se sobrepoem para
           amortizar a bracket de PK.
        3. Para cada lote, chama find_mta_matches_for_users e cruza no
           lado Python (dedup, CIDR, ip != cptv_ip, janela por evento).
    """
    delta = timedelta(minutes=delta_minutes if delta_minutes else mta.delta_minutes)
    # Truncate universe of users per policy.
    users = list(vpn_events_by_user.keys())[: mta.max_users_per_run]
    per_batch = max(1, mta.users_per_batch)
    result = {u: [] for u in users}
    for start in range(0, len(users), per_batch):
        batch = users[start : start + per_batch]
        batch_events = []
        for u in batch:
            batch_events.extend(vpn_events_by_user.get(u, []))
        if not batch_events:
            continue
        ts_lo = min(ev["ts"] for ev in batch_events) - delta
        ts_hi = max(ev["ts"] for ev in batch_events) + delta
        id_lo, id_hi = estimate_pk_window(conn, mta, ts_lo, ts_hi)
        if id_lo is None:
            continue
        rows = find_mta_matches_for_users(
            conn, mta, batch, id_lo, id_hi, ts_lo, ts_hi
        )
        rows = dedup_matches(rows)
        for r in rows:
            u = r.get("username")
            if not u or u not in result:
                continue
            ip = r.get("ip_cliente")
            if not ip_in_networks(ip, mta.ip_networks):
                continue
            ts_mta = r.get("ts_tran")
            if ts_mta is None:
                continue
            for ev in vpn_events_by_user.get(u, []):
                cptv = str(ev.get("cptv_ip") or "").strip()
                # R5: procuramos IPs DIFERENTES para o mesmo usuario nas duas
                # tabelas dentro da janela — indica presenca simultanea em duas
                # redes distintas (VPN + fisica), sinal de sessao paralela.
                if not cptv or ip == cptv:
                    continue
                if abs((ts_mta - ev["ts"]).total_seconds()) <= delta.total_seconds():
                    result[u].append({
                        "ts_vpn": ev["ts"],
                        "cptv_ip": cptv,
                        "ts_mta": ts_mta,
                        "ip_cliente": ip,
                        "cd_unco_tran": r.get("cd_unco_tran"),
                        "cd_cli_tran": r.get("cd_cli_tran"),
                        "cd_idfr_mta": r.get("cd_idfr_mta"),
                        "nm_etp": r.get("nm_etp"),
                    })
    return result
