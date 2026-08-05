from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from .config import (
    DEFAULT_CREDENTIALS_FILE,
    DEFAULT_JDBC_URL,
    BacktestConfig,
    Db2ConnectionConfig,
    PhysicalLoginTableConfig,
    VpnTableConfig,
    load_credentials,
    load_dotenv_file,
    normalize_identifier,
    parse_datetime,
    parse_jdbc_url,
    resolve_path,
)
from .report import write_json, write_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Executa backtest preliminar de VPN no DB2.")
    parser.add_argument("--jdbc-url", default=None)
    parser.add_argument("--credentials-file", default=None)
    parser.add_argument("--schema", default=None)
    parser.add_argument("--table", default=None)
    parser.add_argument("--start", required=True, help="Inicio do periodo: YYYY-MM-DD ou YYYY-MM-DD HH:MM:SS")
    parser.add_argument("--end", required=True, help="Fim exclusivo do periodo: YYYY-MM-DD ou YYYY-MM-DD HH:MM:SS")
    parser.add_argument("--user-column", default=None)
    parser.add_argument("--timestamp-column", default=None)
    parser.add_argument("--source-ip-column", default=None)
    parser.add_argument("--corporate-ip-column", default=None)
    parser.add_argument("--hostname-column", default=None)
    parser.add_argument("--device-column", default=None)
    parser.add_argument("--physical-schema", default=None)
    parser.add_argument("--physical-table", default=None)
    parser.add_argument("--physical-user-column", default=None)
    parser.add_argument("--physical-timestamp-column", default=None)
    parser.add_argument("--physical-network-column", default=None)
    parser.add_argument("--physical-network-value", default=None)
    parser.add_argument("--active-window-hours", type=int, default=8)
    parser.add_argument("--distinct-limit", type=int, default=2)
    parser.add_argument("--daily-login-limit", type=int, default=10)
    parser.add_argument("--sample-limit", type=int, default=50)
    parser.add_argument("--output-dir", default="reports")
    return parser


def env_or_arg(args, attr: str, env_name: str, default: str | None = None) -> str | None:
    value = getattr(args, attr)
    if value is not None:
        return value
    import os

    return os.getenv(env_name, default)


def build_config(args: argparse.Namespace, app_dir: Path) -> BacktestConfig:
    import os

    jdbc_url = env_or_arg(args, "jdbc_url", "DB2_JDBC_URL", DEFAULT_JDBC_URL)
    credentials_file = env_or_arg(
        args, "credentials_file", "DB2_CREDENTIALS_FILE", DEFAULT_CREDENTIALS_FILE
    )
    if jdbc_url is None or credentials_file is None:
        raise ValueError("JDBC URL e arquivo de credenciais sao obrigatorios.")

    host, port, database = parse_jdbc_url(jdbc_url)
    username, password = load_credentials(resolve_path(credentials_file, app_dir))

    db2_config = Db2ConnectionConfig(
        hostname=host,
        port=port,
        database=database,
        username=username,
        password=password,
    )

    vpn_table = VpnTableConfig(
        schema=normalize_identifier(env_or_arg(args, "schema", "DB2_SCHEMA", "DB2PEP") or "", "schema"),
        table=normalize_identifier(env_or_arg(args, "table", "DB2_TABLE", "AUT_CPTV") or "", "table"),
        user_column=normalize_identifier(env_or_arg(args, "user_column", "VPN_USER_COLUMN", "CD_USU_AUT") or "", "user column"),
        timestamp_column=normalize_identifier(env_or_arg(args, "timestamp_column", "VPN_TIMESTAMP_COLUMN", "TS_TRAN") or "", "timestamp column"),
        source_ip_column=normalize_identifier(env_or_arg(args, "source_ip_column", "VPN_SOURCE_IP_COLUMN", "CD_END_LGC_OGM") or "", "source IP column"),
        corporate_ip_column=normalize_identifier(env_or_arg(args, "corporate_ip_column", "VPN_CORPORATE_IP_COLUMN", "CD_END_LGC_CPTV") or "", "corporate IP column"),
        hostname_column=normalize_identifier(env_or_arg(args, "hostname_column", "VPN_HOSTNAME_COLUMN", "NM_DSVO") or "", "hostname column"),
        device_column=normalize_identifier(env_or_arg(args, "device_column", "VPN_DEVICE_COLUMN", "CD_IDFC_DSVO") or "", "device column"),
    )

    physical_table_name = env_or_arg(args, "physical_table", "PHYSICAL_TABLE")
    physical_table = None
    if physical_table_name:
        physical_table = PhysicalLoginTableConfig(
            schema=normalize_identifier(
                env_or_arg(args, "physical_schema", "PHYSICAL_SCHEMA", vpn_table.schema) or "",
                "physical schema",
            ),
            table=normalize_identifier(physical_table_name, "physical table"),
            user_column=normalize_identifier(
                env_or_arg(args, "physical_user_column", "PHYSICAL_USER_COLUMN", vpn_table.user_column) or "",
                "physical user column",
            ),
            timestamp_column=normalize_identifier(
                env_or_arg(args, "physical_timestamp_column", "PHYSICAL_TIMESTAMP_COLUMN", vpn_table.timestamp_column) or "",
                "physical timestamp column",
            ),
            network_column=(
                normalize_identifier(
                    env_or_arg(args, "physical_network_column", "PHYSICAL_NETWORK_COLUMN") or "",
                    "physical network column",
                )
                if env_or_arg(args, "physical_network_column", "PHYSICAL_NETWORK_COLUMN")
                else None
            ),
            network_value=env_or_arg(args, "physical_network_value", "PHYSICAL_NETWORK_VALUE"),
        )

    if args.active_window_hours <= 0 or args.active_window_hours > 168:
        raise ValueError("--active-window-hours deve ficar entre 1 e 168.")
    if args.distinct_limit < 1 or args.daily_login_limit < 1 or args.sample_limit < 1:
        raise ValueError("Limites devem ser inteiros positivos.")

    start = parse_datetime(args.start)
    end = parse_datetime(args.end)
    if end <= start:
        raise ValueError("--end deve ser maior que --start.")

    output_dir = resolve_path(args.output_dir, app_dir)
    os.makedirs(output_dir, exist_ok=True)

    return BacktestConfig(
        db2=db2_config,
        vpn_table=vpn_table,
        physical_table=physical_table,
        start=start,
        end=end,
        active_window_hours=args.active_window_hours,
        distinct_limit=args.distinct_limit,
        daily_login_limit=args.daily_login_limit,
        sample_limit=args.sample_limit,
        output_dir=output_dir,
    )


def main() -> int:
    app_dir = Path(__file__).resolve().parents[2]
    load_dotenv_file(app_dir / ".env")
    args = build_parser().parse_args()
    cfg = build_config(args, app_dir)

    conn = None
    try:
        from .db2 import close, connect
        from .rules import run_backtest_cases

        conn = connect(cfg.db2)
        metrics, cases = run_backtest_cases(conn, cfg)
    finally:
        if conn is not None:
            close(conn)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_base = cfg.output_dir / f"backtest_vpn_{timestamp}"
    payload = {
        "generated_at": datetime.now().isoformat(sep=" "),
        "parameters": {
            "start": cfg.start.strftime("%Y-%m-%d %H:%M:%S"),
            "end": cfg.end.strftime("%Y-%m-%d %H:%M:%S"),
            "vpn_table": f"{cfg.vpn_table.schema}.{cfg.vpn_table.table}",
            "physical_table": (
                f"{cfg.physical_table.schema}.{cfg.physical_table.table}"
                if cfg.physical_table
                else None
            ),
            "active_window_hours": cfg.active_window_hours,
            "distinct_limit": cfg.distinct_limit,
            "daily_login_limit": cfg.daily_login_limit,
            "sample_limit": cfg.sample_limit,
        },
        "metrics": metrics,
        "cases": [asdict(case) for case in cases],
    }

    write_json(report_base.with_suffix(".json"), payload)
    write_markdown(report_base.with_suffix(".md"), payload)
    print(f"Relatorios gerados: {report_base.with_suffix('.json')} e {report_base.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
