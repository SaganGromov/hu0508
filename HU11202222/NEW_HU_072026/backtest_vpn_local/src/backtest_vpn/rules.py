"""Casos do backtest de VPN executados contra o DB2 (somente leitura).

Todos os identificadores SQL (schema, tabela, coluna) usados aqui ja passaram
pela regex de identificadores em config.normalize_identifier antes de serem
interpolados. Valores literais (datas, limites de HAVING, valor de rede) sao
sempre enviados via binding `?`.
"""

from dataclasses import dataclass, field
from typing import List

from .db2 import fetch_all
from . import mta as mta_mod

RATE_NOT_AVAILABLE = "not_available_without_validated_labels"

_TS_FORMAT = "%Y-%m-%d %H:%M:%S"


@dataclass
class BacktestCaseResult:
    name: str
    status: str
    count: int
    sample: List[dict]
    note: str = ""


def qualified(schema, table):
    """Retorna o nome qualificado 'schema.table'."""
    return "{0}.{1}".format(schema, table)


def ts_params(start, end):
    """Retorna (start, end) como strings 'YYYY-MM-DD HH:MM:SS' para binding."""
    return (start.strftime(_TS_FORMAT), end.strftime(_TS_FORMAT))


def get_table_columns(conn, schema, table):
    """Lista as colunas da tabela em ordem de COLNO.

    Tenta SYSCAT.COLUMNS (DB2 LUW) primeiro; em caso de falha, usa
    SYSIBM.SYSCOLUMNS (DB2 z/OS).
    """
    syscat_sql = (
        "SELECT COLNAME FROM SYSCAT.COLUMNS "
        "WHERE TABSCHEMA = ? AND TABNAME = ? "
        "ORDER BY COLNO"
    )
    sysibm_sql = (
        "SELECT NAME AS COLNAME FROM SYSIBM.SYSCOLUMNS "
        "WHERE TBCREATOR = ? AND TBNAME = ? "
        "ORDER BY COLNO"
    )
    try:
        rows = fetch_all(conn, syscat_sql, (schema, table))
    except Exception:
        rows = fetch_all(conn, sysibm_sql, (schema, table))
    return [str(row["COLNAME"]).strip().upper() for row in rows]


def validate_columns(conn, schema, table, required_columns):
    """Garante que todas as colunas exigidas existem na tabela.

    Levanta ValueError nomeando as colunas ausentes e listando as
    disponiveis, em vez de deixar um SQL0206N opaco estourar depois.
    """
    available = get_table_columns(conn, schema, table)
    if not available:
        raise ValueError(
            "Tabela {0} nao encontrada no catalogo"
            " (SYSCAT.COLUMNS / SYSIBM.SYSCOLUMNS).".format(qualified(schema, table))
        )
    missing = [col for col in required_columns if col not in available]
    if missing:
        raise ValueError(
            "Colunas ausentes em {0}: {1}. Colunas disponiveis: {2}".format(
                qualified(schema, table), ", ".join(missing), ", ".join(available)
            )
        )


def validate_configured_tables(conn, cfg):
    """Valida as colunas da tabela VPN e, se configurada, da tabela fisica."""
    vpn = cfg.vpn_table
    validate_columns(
        conn,
        vpn.schema,
        vpn.table,
        [
            vpn.user_column,
            vpn.timestamp_column,
            vpn.source_ip_column,
            vpn.corporate_ip_column,
            vpn.hostname_column,
            vpn.device_column,
        ],
    )
    physical = cfg.physical_table
    if physical is not None:
        required = [physical.user_column, physical.timestamp_column]
        if physical.network_column:
            required.append(physical.network_column)
        validate_columns(conn, physical.schema, physical.table, required)


def run_summary(conn, cfg):
    """Resumo do periodo: total de eventos e de usuarios distintos."""
    vpn = cfg.vpn_table
    sql = (
        "SELECT COUNT(1) AS TOTAL_EVENTS, "
        "COUNT(DISTINCT TRIM({user})) AS TOTAL_USERS "
        "FROM {table} "
        "WHERE {ts} >= ? AND {ts} < ?"
    ).format(
        user=vpn.user_column,
        table=qualified(vpn.schema, vpn.table),
        ts=vpn.timestamp_column,
    )
    row = fetch_all(conn, sql, ts_params(cfg.start, cfg.end))[0]
    total_events = int(row["TOTAL_EVENTS"])
    # Toda linha da tabela de autenticacao analisada e um evento de VPN,
    # portanto os casos classificados como VPN equivalem ao total de eventos.
    return {
        "total_events_analyzed": total_events,
        "total_users_analyzed": int(row["TOTAL_USERS"]),
        "vpn_classified_cases": total_events,
        "false_positive_rate": RATE_NOT_AVAILABLE,
        "false_negative_rate": RATE_NOT_AVAILABLE,
    }


def _distinct_expr(column):
    return "COUNT(DISTINCT NULLIF(TRIM({0}), ''))".format(column)


def _count_wrapping(conn, base_sql, params, alias):
    count_sql = "SELECT COUNT(1) AS {0} FROM ({1}) AS Q".format(alias, base_sql)
    return int(fetch_all(conn, count_sql, params)[0][alias])


def run_distinct_limit_case(conn, cfg, name, columns, note):
    """Usuários com mais de cfg.distinct_limit valores distintos nas colunas."""
    vpn = cfg.vpn_table
    metrics = ", ".join(
        "{expr} AS DISTINCT_{col}".format(expr=_distinct_expr(col), col=col)
        for col in columns
    )
    having = " OR ".join(
        "{expr} > ?".format(expr=_distinct_expr(col)) for col in columns
    )
    base_sql = (
        "SELECT TRIM({user}) AS USER_KEY, COUNT(1) AS EVENTS, {metrics}, "
        "MAX({ts}) AS LAST_SEEN "
        "FROM {table} "
        "WHERE {ts} >= ? AND {ts} < ? "
        "GROUP BY TRIM({user}) "
        "HAVING {having}"
    ).format(
        user=vpn.user_column,
        metrics=metrics,
        table=qualified(vpn.schema, vpn.table),
        ts=vpn.timestamp_column,
        having=having,
    )
    start_s, end_s = ts_params(cfg.start, cfg.end)
    params = (start_s, end_s) + tuple(cfg.distinct_limit for _ in columns)
    qualifying_users = _count_wrapping(conn, base_sql, params, "QUALIFYING_USERS")
    sample_sql = base_sql + (
        " ORDER BY EVENTS DESC FETCH FIRST {0} ROWS ONLY".format(cfg.sample_limit)
    )
    sample = fetch_all(conn, sample_sql, params)
    return BacktestCaseResult(
        name=name, status="ok", count=qualifying_users, sample=sample, note=note
    )


def run_daily_volume_case(conn, cfg):
    """Usuários com mais de cfg.daily_login_limit logins no mesmo dia."""
    vpn = cfg.vpn_table
    base_sql = (
        "SELECT TRIM({user}) AS USER_KEY, DATE({ts}) AS LOGIN_DATE, "
        "COUNT(1) AS LOGIN_COUNT "
        "FROM {table} "
        "WHERE {ts} >= ? AND {ts} < ? "
        "GROUP BY TRIM({user}), DATE({ts}) "
        "HAVING COUNT(1) > ?"
    ).format(
        user=vpn.user_column,
        table=qualified(vpn.schema, vpn.table),
        ts=vpn.timestamp_column,
    )
    start_s, end_s = ts_params(cfg.start, cfg.end)
    params = (start_s, end_s, cfg.daily_login_limit)
    qualifying = _count_wrapping(conn, base_sql, params, "QUALIFYING_USER_DAYS")
    sample_sql = base_sql + (
        " ORDER BY LOGIN_COUNT DESC FETCH FIRST {0} ROWS ONLY".format(cfg.sample_limit)
    )
    sample = fetch_all(conn, sample_sql, params)
    return BacktestCaseResult(
        name="logins_diarios_acima_do_limite",
        status="ok",
        count=qualifying,
        sample=sample,
        note=(
            "Pares usuario+dia com mais de {0} logins no mesmo dia.".format(
                cfg.daily_login_limit
            )
        ),
    )


def run_active_vpn_plus_physical_login_case(conn, cfg):
    """Politica da HU: sessao VPN ativa + login em rede fisica do BB.

    Apenas simula a elegibilidade da regra sobre dados historicos; nenhuma
    acao e executada no LDAP. A "sessao ativa" e aproximada por uma janela
    parametrizada (--active-window-hours) apos o evento de VPN.
    """
    case_name = "vpn_ativa_com_login_em_rede_fisica"
    physical = cfg.physical_table
    if physical is None:
        return BacktestCaseResult(
            name=case_name,
            status="skipped",
            count=0,
            sample=[],
            note=(
                "Tabela de login em rede física não configurada"
                " (--physical-table / PHYSICAL_TABLE); caso não executado."
                " Os demais casos foram executados normalmente."
            ),
        )
    vpn = cfg.vpn_table
    network_filter = ""
    start_s, end_s = ts_params(cfg.start, cfg.end)
    params = [start_s, end_s]
    if physical.network_column and physical.network_value:
        network_filter = " AND TRIM(P.{0}) = ?".format(physical.network_column)
        params.append(physical.network_value)
    base_sql = (
        "SELECT TRIM(V.{vuser}) AS USER_KEY, "
        "V.{vts} AS VPN_TS, P.{pts} AS PHYSICAL_TS "
        "FROM {vtable} V "
        "JOIN {ptable} P "
        "ON TRIM(V.{vuser}) = TRIM(P.{puser}) "
        "AND P.{pts} >= V.{vts} "
        "AND P.{pts} < V.{vts} + {hours} HOURS "
        "WHERE P.{pts} >= ? AND P.{pts} < ?{network_filter}"
    ).format(
        vuser=vpn.user_column,
        vts=vpn.timestamp_column,
        vtable=qualified(vpn.schema, vpn.table),
        ptable=qualified(physical.schema, physical.table),
        puser=physical.user_column,
        pts=physical.timestamp_column,
        hours=cfg.active_window_hours,
        network_filter=network_filter,
    )
    eligible = _count_wrapping(conn, base_sql, params, "ELIGIBLE_MATCHES")
    sample_sql = base_sql + (
        " ORDER BY VPN_TS DESC FETCH FIRST {0} ROWS ONLY".format(cfg.sample_limit)
    )
    sample = fetch_all(conn, sample_sql, params)
    return BacktestCaseResult(
        name=case_name,
        status="ok",
        count=eligible,
        sample=sample,
        note=(
            "Eventos de VPN com login em rede fisica do BB para a mesma chave"
            " em ate {0} hora(s); simulacao de elegibilidade apenas,"
            " sem acao no LDAP.".format(cfg.active_window_hours)
        ),
    )


def run_vpn_plus_mta_physical_case(conn, cfg):
    """Deteccao 'VPN ativa + login em rede fisica' via DB2PEP.MTA_AUT_CLI_TRAN.

    Para cada evento VPN em `AUT_CPTV` no periodo, procura em
    `MTA_AUT_CLI_TRAN` um fluxo de autenticacao bem-sucedido (dedup por
    `CD_UNCO_TRAN`) para o mesmo usuário, dentro de uma janela +/- Delta
    minutos e cujo `ipCliente` extraido de `JS_INF_CLI`:

      * pertenca a uma faixa privada configurada (default 10/8, 172.16/12,
        192.168/16); e
      * seja DIFERENTE do IP corporativo tunelado pela VPN
        (`CD_END_LGC_CPTV`), evidenciando presenca simultanea em duas
        redes distintas para o mesmo funcionario — sinal forte de sessao
        paralela em rede fisica enquanto a VPN esta ativa.

    Nada e alterado no LDAP: apenas simulacao label-free de elegibilidade
    de encerramento de sessao.
    """
    case_name = "vpn_ativa_com_login_em_rede_fisica_mta"
    mta_cfg = getattr(cfg, "mta_table", None)
    if mta_cfg is None:
        return BacktestCaseResult(
            name=case_name,
            status="skipped",
            count=0,
            sample=[],
            note=(
                "Deteccao via DB2PEP.MTA_AUT_CLI_TRAN desligada"
                " (--no-mta-physical); caso não executado."
            ),
        )
    vpn = cfg.vpn_table
    start_s, end_s = ts_params(cfg.start, cfg.end)
    events_sql = (
        "SELECT TRIM({user}) AS USER_KEY, {ts} AS VPN_TS, "
        "TRIM({corp}) AS CPTV_IP "
        "FROM {tbl} WHERE {ts} >= ? AND {ts} < ? "
        "AND {user} IS NOT NULL AND TRIM({user}) <> '' "
        "ORDER BY {ts} ASC"
    ).format(
        user=vpn.user_column,
        ts=vpn.timestamp_column,
        corp=vpn.corporate_ip_column,
        tbl=qualified(vpn.schema, vpn.table),
    )
    rows = fetch_all(conn, events_sql, (start_s, end_s))
    vpn_events = {}
    for row in rows:
        user = row.get("USER_KEY")
        ts = row.get("VPN_TS")
        if not user or ts is None:
            continue
        vpn_events.setdefault(str(user), []).append({
            "ts": ts,
            "cptv_ip": row.get("CPTV_IP"),
        })
    if not vpn_events:
        return BacktestCaseResult(
            name=case_name,
            status="ok",
            count=0,
            sample=[],
            note=(
                "Nenhum evento VPN no período; nada a correlacionar em DB2PEP.MTA_AUT_CLI_TRAN."
            ),
        )
    from datetime import timedelta as _td
    chunk_hours = int(getattr(mta_cfg, "chunk_hours", 24) or 24)
    chunk_delta = _td(hours=chunk_hours)
    total_users = len(vpn_events)
    matches_by_user = {}
    cur = cfg.start
    while cur < cfg.end:
        nxt = min(cur + chunk_delta, cfg.end)
        chunk_events = {}
        for u, evs in vpn_events.items():
            bucket = [ev for ev in evs if cur <= ev["ts"] < nxt]
            if bucket:
                chunk_events[u] = bucket
        if chunk_events:
            chunk_hits = mta_mod.match_vpn_events(conn, mta_cfg, chunk_events)
            for u, hits in chunk_hits.items():
                if hits:
                    matches_by_user.setdefault(u, []).extend(hits)
        cur = nxt
    flat = []
    users_hit = set()
    for user, hits in matches_by_user.items():
        for h in hits:
            flat.append({
                "USER_KEY": user,
                "VPN_TS": h["ts_vpn"],
                "VPN_CPTV_IP": h["cptv_ip"],
                "MTA_TS": h["ts_mta"],
                "MTA_IP_CLIENTE": h["ip_cliente"],
                "MTA_CD_IDFR_MTA": h.get("cd_idfr_mta"),
                "MTA_CD_UNCO_TRAN": h["cd_unco_tran"],
                "MTA_CD_CLI_TRAN": h.get("cd_cli_tran"),
                "MTA_NM_ETP": h["nm_etp"],
            })
            users_hit.add(user)
    flat.sort(key=lambda x: x["VPN_TS"], reverse=True)
    sample = flat[: cfg.sample_limit]
    inspected = total_users
    truncated_note = ""
    if mta_cfg.max_users_per_run and total_users > mta_cfg.max_users_per_run:
        truncated_note = (
            " Inspeção por chunk de {0}h limitada a {1} usuários"
            " (universo total: {2} usuários; parâmetro MTA_MAX_USERS)."
        ).format(chunk_hours, mta_cfg.max_users_per_run, total_users)
    return BacktestCaseResult(
        name=case_name,
        status="ok",
        count=len(flat),
        sample=sample,
        note=(
            "Fluxos bem-sucedidos em DB2PEP.MTA_AUT_CLI_TRAN (nodes {node_names}) para o mesmo usuário da"
            " VPN, dentro de +/-{d} min, com ipCliente em {cidrs} e distinto"
            " do IP tunelado; dedup por CD_UNCO_TRAN. Usuários distintos"
            " sinalizados: {u}.{trunc}"
        ).format(
            node_names=", ".join(mta_cfg.decision_nodes),
            d=mta_cfg.delta_minutes,
            cidrs=", ".join(str(n) for n in mta_cfg.ip_networks),
            u=len(users_hit),
            trunc=truncated_note,
        ),
    )


def run_backtest_cases(conn, cfg):
    """Valida as tabelas, calcula as metricas e executa os 5 casos."""
    validate_configured_tables(conn, cfg)
    metrics = run_summary(conn, cfg)
    vpn = cfg.vpn_table
    cases = [
        run_distinct_limit_case(
            conn,
            cfg,
            name="ips_distintos_acima_do_limite",
            columns=[vpn.source_ip_column, vpn.corporate_ip_column],
            note=(
                "Usuários com mais de {0} IPs distintos (origem ou corporativo)"
                " no período.".format(cfg.distinct_limit)
            ),
        ),
        run_distinct_limit_case(
            conn,
            cfg,
            name="hostnames_distintos_acima_do_limite",
            columns=[vpn.hostname_column],
            note=(
                "Usuários com mais de {0} hostnames distintos"
                " no período.".format(cfg.distinct_limit)
            ),
        ),
        run_distinct_limit_case(
            conn,
            cfg,
            name="dispositivos_distintos_acima_do_limite",
            columns=[vpn.device_column],
            note=(
                "Usuários com mais de {0} identificadores de dispositivo"
                " distintos no período.".format(cfg.distinct_limit)
            ),
        ),
        run_daily_volume_case(conn, cfg),
        run_active_vpn_plus_physical_login_case(conn, cfg),
        run_vpn_plus_mta_physical_case(conn, cfg),
    ]
    cases.append(_synthesize_r6_case(conn, cfg, cases[-1]))
    return metrics, cases


def _synthesize_r6_case(conn, cfg, r5_case):
    """R6: R5 (VPN + MTA em IPs distintos) + multiplos hostnames/dispositivos.

    Toma o conjunto de usuarios sinalizados por R5 (via case.sample) e
    consulta a tabela VPN para descobrir quantos hostnames e dispositivos
    distintos cada usuario apresenta no periodo. Sao mantidos apenas os
    usuarios que excedem `cfg.distinct_limit` em pelo menos uma das metricas,
    caracterizando uso simultaneo/paralelo de multiplos dispositivos.
    """
    case_name = "vpn_ativa_com_login_em_rede_fisica_mta_multiplos_dispositivos"
    r5_users = []
    seen = set()
    for row in (r5_case.sample or []):
        uk = row.get("USER_KEY")
        if not uk:
            continue
        uk = str(uk).strip()
        if uk and uk not in seen:
            seen.add(uk)
            r5_users.append(uk)
    if r5_case.status != "ok" or not r5_users:
        return BacktestCaseResult(
            name=case_name,
            status="skipped",
            count=0,
            sample=[],
            note=(
                "R6 depende de R5 estar disponivel e ter usuarios sinalizados"
                " (universo vazio; caso nao executado)."
            ),
        )
    vpn = cfg.vpn_table
    placeholders = ",".join(["?"] * len(r5_users))
    sql = (
        "SELECT TRIM({user}) AS USER_KEY, "
        "COUNT(DISTINCT {host}) AS DISTINCT_HOSTNAMES, "
        "COUNT(DISTINCT {dev}) AS DISTINCT_DEVICES, "
        "COUNT(1) AS EVENTS "
        "FROM {tbl} "
        "WHERE {ts} >= ? AND {ts} < ? "
        "AND TRIM({user}) IN ({ph}) "
        "GROUP BY TRIM({user}) "
        "HAVING COUNT(DISTINCT {host}) > ? OR COUNT(DISTINCT {dev}) > ?"
    ).format(
        user=vpn.user_column,
        host=vpn.hostname_column,
        dev=vpn.device_column,
        tbl=qualified(vpn.schema, vpn.table),
        ts=vpn.timestamp_column,
        ph=placeholders,
    )
    start_s, end_s = ts_params(cfg.start, cfg.end)
    params = (
        (start_s, end_s)
        + tuple(r5_users)
        + (cfg.distinct_limit, cfg.distinct_limit)
    )
    try:
        rows = fetch_all(conn, sql, params)
    except Exception as exc:
        return BacktestCaseResult(
            name=case_name,
            status="skipped",
            count=0,
            sample=[],
            note="Falha ao consultar hostnames/dispositivos para R6: {0}".format(exc),
        )
    per_user = {}
    for row in rows:
        uk = row.get("USER_KEY")
        if uk is None:
            continue
        per_user[str(uk).strip()] = row
    sample = []
    for r5_row in (r5_case.sample or []):
        uk = str(r5_row.get("USER_KEY") or "").strip()
        counts = per_user.get(uk)
        if not counts:
            continue
        enriched = dict(r5_row)
        enriched["DISTINCT_HOSTNAMES"] = counts.get("DISTINCT_HOSTNAMES")
        enriched["DISTINCT_DEVICES"] = counts.get("DISTINCT_DEVICES")
        enriched["TOTAL_EVENTS_VPN"] = counts.get("EVENTS")
        sample.append(enriched)
    sample = sample[: cfg.sample_limit]
    return BacktestCaseResult(
        name=case_name,
        status="ok",
        count=len(per_user),
        sample=sample,
        note=(
            "R5 restrito a usuarios com mais de {lim} hostnames OU mais de"
            " {lim} dispositivos distintos no periodo — indica sessao paralela"
            " com multiplos equipamentos simultaneos. Usuarios distintos: {u}."
        ).format(lim=cfg.distinct_limit, u=len(per_user)),
    )
