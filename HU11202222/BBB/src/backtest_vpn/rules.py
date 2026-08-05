from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .config import BacktestConfig, PhysicalLoginTableConfig, VpnTableConfig
from .db2 import fetch_all


@dataclass(frozen=True)
class BacktestCaseResult:
    name: str
    status: str
    count: int
    sample: list[dict[str, Any]]
    note: str = ""


def qualified(schema: str, table: str) -> str:
    return f"{schema}.{table}"


def get_table_columns(conn, schema: str, table: str) -> list[str]:
    queries = [
        (
            """
            SELECT COLNAME
            FROM SYSCAT.COLUMNS
            WHERE TABSCHEMA = ?
              AND TABNAME = ?
            ORDER BY COLNO
            """,
            "COLNAME",
        ),
        (
            """
            SELECT NAME AS COLNAME
            FROM SYSIBM.SYSCOLUMNS
            WHERE TBCREATOR = ?
              AND TBNAME = ?
            ORDER BY COLNO
            """,
            "COLNAME",
        ),
    ]
    last_error: Exception | None = None
    for sql, key in queries:
        try:
            rows = fetch_all(conn, sql, (schema, table))
            if rows:
                return [str(row[key]).strip().upper() for row in rows]
        except Exception as exc:
            last_error = exc
    if last_error:
        raise RuntimeError(f"Nao foi possivel consultar colunas de {schema}.{table}: {last_error}")
    return []


def validate_columns(conn, schema: str, table: str, required_columns: list[str]) -> None:
    available = get_table_columns(conn, schema, table)
    if not available:
        raise ValueError(f"Tabela {schema}.{table} nao encontrada ou sem colunas visiveis no catalogo DB2.")

    available_set = set(available)
    missing = [column for column in required_columns if column not in available_set]
    if missing:
        preview = ", ".join(available[:80])
        raise ValueError(
            f"Colunas ausentes em {schema}.{table}: {', '.join(missing)}. "
            f"Colunas disponiveis: {preview}"
        )


def validate_configured_tables(conn, cfg: BacktestConfig) -> None:
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
    if cfg.physical_table:
        physical = cfg.physical_table
        required = [physical.user_column, physical.timestamp_column]
        if physical.network_column:
            required.append(physical.network_column)
        validate_columns(conn, physical.schema, physical.table, required)


def ts_params(start: datetime, end: datetime) -> tuple[str, str]:
    return (
        start.strftime("%Y-%m-%d %H:%M:%S"),
        end.strftime("%Y-%m-%d %H:%M:%S"),
    )


def run_summary(conn, cfg: BacktestConfig) -> dict[str, int]:
    table = cfg.vpn_table
    full_table = qualified(table.schema, table.table)
    sql = f"""
        SELECT
            COUNT(1) AS TOTAL_EVENTS,
            COUNT(DISTINCT TRIM({table.user_column})) AS TOTAL_USERS
        FROM {full_table}
        WHERE {table.timestamp_column} >= ?
          AND {table.timestamp_column} < ?
    """
    row = fetch_all(conn, sql, ts_params(cfg.start, cfg.end))[0]
    total_events = int(row.get("TOTAL_EVENTS") or 0)
    total_users = int(row.get("TOTAL_USERS") or 0)
    return {
        "total_events_analyzed": total_events,
        "total_users_analyzed": total_users,
        "vpn_classified_cases": total_events,
        "false_positive_rate": "not_available_without_validated_labels",
        "false_negative_rate": "not_available_without_validated_labels",
    }


def run_distinct_limit_case(
    conn,
    cfg: BacktestConfig,
    name: str,
    columns: list[str],
    note: str,
) -> BacktestCaseResult:
    table = cfg.vpn_table
    full_table = qualified(table.schema, table.table)
    select_counts = ",\n".join(
        f"COUNT(DISTINCT NULLIF(TRIM({column}), '')) AS DISTINCT_{idx}"
        for idx, column in enumerate(columns, start=1)
    )
    having = " OR ".join(
        f"COUNT(DISTINCT NULLIF(TRIM({column}), '')) > {cfg.distinct_limit}"
        for column in columns
    )
    sql = f"""
        SELECT
            TRIM({table.user_column}) AS USER_KEY,
            COUNT(1) AS EVENTS,
            {select_counts}
        FROM {full_table}
        WHERE {table.timestamp_column} >= ?
          AND {table.timestamp_column} < ?
          AND {table.user_column} IS NOT NULL
        GROUP BY TRIM({table.user_column})
        HAVING {having}
        ORDER BY EVENTS DESC
        FETCH FIRST {cfg.sample_limit} ROWS ONLY
    """
    rows = fetch_all(conn, sql, ts_params(cfg.start, cfg.end))
    count_sql = f"SELECT COUNT(1) AS QTD FROM ({sql}) AS CASES"
    count = int(fetch_all(conn, count_sql, ts_params(cfg.start, cfg.end))[0].get("QTD") or 0)
    return BacktestCaseResult(name=name, status="ok", count=count, sample=rows, note=note)


def run_daily_volume_case(conn, cfg: BacktestConfig) -> BacktestCaseResult:
    table = cfg.vpn_table
    full_table = qualified(table.schema, table.table)
    sql = f"""
        SELECT
            TRIM({table.user_column}) AS USER_KEY,
            DATE({table.timestamp_column}) AS EVENT_DATE,
            COUNT(1) AS LOGIN_COUNT
        FROM {full_table}
        WHERE {table.timestamp_column} >= ?
          AND {table.timestamp_column} < ?
          AND {table.user_column} IS NOT NULL
        GROUP BY TRIM({table.user_column}), DATE({table.timestamp_column})
        HAVING COUNT(1) > {cfg.daily_login_limit}
        ORDER BY LOGIN_COUNT DESC
        FETCH FIRST {cfg.sample_limit} ROWS ONLY
    """
    rows = fetch_all(conn, sql, ts_params(cfg.start, cfg.end))
    count_sql = f"SELECT COUNT(1) AS QTD FROM ({sql}) AS CASES"
    count = int(fetch_all(conn, count_sql, ts_params(cfg.start, cfg.end))[0].get("QTD") or 0)
    return BacktestCaseResult(
        name="Quantidade de logins VPN por dia acima do limite",
        status="ok",
        count=count,
        sample=rows,
        note=f"Limite atual: {cfg.daily_login_limit} eventos por usuario/dia.",
    )


def run_active_vpn_plus_physical_login_case(conn, cfg: BacktestConfig) -> BacktestCaseResult:
    physical = cfg.physical_table
    if physical is None:
        return BacktestCaseResult(
            name="VPN ativa + login atual em rede fisica BB",
            status="skipped",
            count=0,
            sample=[],
            note="Informe --physical-table para executar esta politica.",
        )

    vpn = cfg.vpn_table
    network_filter, params_tail = build_physical_network_filter(physical)
    sql = f"""
        SELECT
            TRIM(v.{vpn.user_column}) AS USER_KEY,
            v.{vpn.timestamp_column} AS VPN_TIMESTAMP,
            p.{physical.timestamp_column} AS PHYSICAL_TIMESTAMP,
            TRIM(v.{vpn.source_ip_column}) AS VPN_SOURCE_IP,
            TRIM(v.{vpn.corporate_ip_column}) AS VPN_CORPORATE_IP,
            TRIM(v.{vpn.hostname_column}) AS VPN_HOSTNAME
        FROM {qualified(vpn.schema, vpn.table)} v
        JOIN {qualified(physical.schema, physical.table)} p
          ON TRIM(v.{vpn.user_column}) = TRIM(p.{physical.user_column})
         AND p.{physical.timestamp_column} >= v.{vpn.timestamp_column}
         AND p.{physical.timestamp_column} < v.{vpn.timestamp_column} + {cfg.active_window_hours} HOURS
        WHERE p.{physical.timestamp_column} >= ?
          AND p.{physical.timestamp_column} < ?
          AND v.{vpn.user_column} IS NOT NULL
          AND p.{physical.user_column} IS NOT NULL
          {network_filter}
        ORDER BY p.{physical.timestamp_column} DESC
        FETCH FIRST {cfg.sample_limit} ROWS ONLY
    """
    params = (*ts_params(cfg.start, cfg.end), *params_tail)
    rows = fetch_all(conn, sql, params)
    count_sql = f"SELECT COUNT(1) AS QTD FROM ({sql}) AS CASES"
    count = int(fetch_all(conn, count_sql, params)[0].get("QTD") or 0)
    return BacktestCaseResult(
        name="VPN ativa + login atual em rede fisica BB",
        status="ok",
        count=count,
        sample=rows,
        note="Simula elegibilidade para encerramento de sessao VPN no LDAP; nenhuma acao real executada.",
    )


def build_physical_network_filter(physical: PhysicalLoginTableConfig) -> tuple[str, tuple[str, ...]]:
    if physical.network_column and physical.network_value:
        return f"AND TRIM(p.{physical.network_column}) = ?", (physical.network_value,)
    return "", ()


def run_backtest_cases(conn, cfg: BacktestConfig) -> tuple[dict[str, int], list[BacktestCaseResult]]:
    validate_configured_tables(conn, cfg)
    metrics = run_summary(conn, cfg)
    vpn: VpnTableConfig = cfg.vpn_table
    cases = [
        run_distinct_limit_case(
            conn,
            cfg,
            "Mais de N IPs por usuario",
            [vpn.source_ip_column, vpn.corporate_ip_column],
            f"Limite atual: mais de {cfg.distinct_limit} IPs distintos.",
        ),
        run_distinct_limit_case(
            conn,
            cfg,
            "Mais de N hostnames por usuario",
            [vpn.hostname_column],
            f"Limite atual: mais de {cfg.distinct_limit} hostnames distintos.",
        ),
        run_distinct_limit_case(
            conn,
            cfg,
            "Mais de N dispositivos por usuario",
            [vpn.device_column],
            f"Limite atual: mais de {cfg.distinct_limit} dispositivos distintos.",
        ),
        run_daily_volume_case(conn, cfg),
        run_active_vpn_plus_physical_login_case(conn, cfg),
    ]
    return metrics, cases
