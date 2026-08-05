"""CLI do backtest local de VPN sobre DB2."""

import argparse
import os
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from . import config as cfg_mod
from . import db2, report, rules


def build_parser():
    parser = argparse.ArgumentParser(
        prog="backtest-vpn",
        description=(
            "Backtest local (somente leitura) das regras de deteccao de VPN"
            " sobre dados historicos em DB2."
        ),
    )
    parser.add_argument("--start", required=True, help="Inicio do periodo (YYYY-MM-DD ou 'YYYY-MM-DD HH:MM:SS')")
    parser.add_argument("--end", required=True, help="Fim exclusivo do periodo (YYYY-MM-DD ou 'YYYY-MM-DD HH:MM:SS')")
    parser.add_argument("--jdbc-url", help="URL JDBC do DB2 (env DB2_JDBC_URL)")
    parser.add_argument("--credentials-file", help="Arquivo JSON de credenciais (env DB2_CREDENTIALS_FILE)")
    parser.add_argument("--schema", help="Schema da tabela VPN (env DB2_SCHEMA)")
    parser.add_argument("--table", help="Tabela VPN (env DB2_TABLE)")
    parser.add_argument("--user-column", help="Coluna da chave do usuario (env VPN_USER_COLUMN)")
    parser.add_argument("--timestamp-column", help="Coluna de timestamp (env VPN_TIMESTAMP_COLUMN)")
    parser.add_argument("--source-ip-column", help="Coluna de IP de origem (env VPN_SOURCE_IP_COLUMN)")
    parser.add_argument("--corporate-ip-column", help="Coluna de IP corporativo (env VPN_CORPORATE_IP_COLUMN)")
    parser.add_argument("--hostname-column", help="Coluna de hostname (env VPN_HOSTNAME_COLUMN)")
    parser.add_argument("--device-column", help="Coluna de ID de dispositivo (env VPN_DEVICE_COLUMN)")
    parser.add_argument("--physical-schema", help="Schema da tabela de login fisico (env PHYSICAL_SCHEMA)")
    parser.add_argument("--physical-table", help="Tabela de login fisico (env PHYSICAL_TABLE); sem ela o caso 6 e pulado")
    parser.add_argument("--physical-user-column", help="Coluna de usuario na tabela fisica (env PHYSICAL_USER_COLUMN)")
    parser.add_argument("--physical-timestamp-column", help="Coluna de timestamp na tabela fisica (env PHYSICAL_TIMESTAMP_COLUMN)")
    parser.add_argument("--physical-network-column", help="Coluna de rede na tabela fisica (env PHYSICAL_NETWORK_COLUMN)")
    parser.add_argument("--physical-network-value", help="Valor esperado da coluna de rede (env PHYSICAL_NETWORK_VALUE)")
    parser.add_argument("--active-window-hours", type=int, default=8, help="Janela de sessao ativa em horas (1..168, padrao 8)")
    parser.add_argument("--distinct-limit", type=int, default=2, help="Limite de valores distintos por usuario (padrao 2)")
    parser.add_argument("--daily-login-limit", type=int, default=10, help="Limite de logins por usuario por dia (padrao 10)")
    parser.add_argument("--sample-limit", type=int, default=50, help="Tamanho maximo das amostras (padrao 50)")
    parser.add_argument("--output-dir", default="reports", help="Diretorio de saida dos relatorios (padrao: reports)")
    return parser


def _opt(cli_value, env_name, default=None):
    """CLI vence; depois a variavel de ambiente; por fim o default."""
    if cli_value is not None and str(cli_value).strip() != "":
        return cli_value
    env_value = os.environ.get(env_name)
    if env_value is not None and env_value.strip() != "":
        return env_value
    return default


def _build_config(args, base_dir):
    jdbc_url = _opt(args.jdbc_url, "DB2_JDBC_URL", cfg_mod.DEFAULT_JDBC_URL)
    credentials_file = _opt(
        args.credentials_file, "DB2_CREDENTIALS_FILE", cfg_mod.DEFAULT_CREDENTIALS_FILE
    )

    schema = cfg_mod.normalize_identifier(
        _opt(args.schema, "DB2_SCHEMA", "DB2PEP"), "--schema"
    )
    table = cfg_mod.normalize_identifier(
        _opt(args.table, "DB2_TABLE", "AUT_CPTV"), "--table"
    )
    user_column = cfg_mod.normalize_identifier(
        _opt(args.user_column, "VPN_USER_COLUMN", "CD_USU_AUT"), "--user-column"
    )
    timestamp_column = cfg_mod.normalize_identifier(
        _opt(args.timestamp_column, "VPN_TIMESTAMP_COLUMN", "TS_TRAN"),
        "--timestamp-column",
    )
    source_ip_column = cfg_mod.normalize_identifier(
        _opt(args.source_ip_column, "VPN_SOURCE_IP_COLUMN", "CD_END_LGC_OGM"),
        "--source-ip-column",
    )
    corporate_ip_column = cfg_mod.normalize_identifier(
        _opt(args.corporate_ip_column, "VPN_CORPORATE_IP_COLUMN", "CD_END_LGC_CPTV"),
        "--corporate-ip-column",
    )
    hostname_column = cfg_mod.normalize_identifier(
        _opt(args.hostname_column, "VPN_HOSTNAME_COLUMN", "NM_DSVO"),
        "--hostname-column",
    )
    device_column = cfg_mod.normalize_identifier(
        _opt(args.device_column, "VPN_DEVICE_COLUMN", "CD_IDFC_DSVO"),
        "--device-column",
    )

    start = cfg_mod.parse_datetime(args.start)
    end = cfg_mod.parse_datetime(args.end)
    if end <= start:
        raise ValueError("--end deve ser maior que --start.")

    if not 1 <= args.active_window_hours <= 168:
        raise ValueError("--active-window-hours deve estar entre 1 e 168.")
    for label, value in (
        ("--distinct-limit", args.distinct_limit),
        ("--daily-login-limit", args.daily_login_limit),
        ("--sample-limit", args.sample_limit),
    ):
        if value <= 0:
            raise ValueError("{0} deve ser um inteiro positivo.".format(label))

    physical = None
    physical_table_raw = _opt(args.physical_table, "PHYSICAL_TABLE")
    if physical_table_raw:
        physical_schema = cfg_mod.normalize_identifier(
            _opt(args.physical_schema, "PHYSICAL_SCHEMA", schema), "--physical-schema"
        )
        physical_table = cfg_mod.normalize_identifier(
            physical_table_raw, "--physical-table"
        )
        physical_user_column = cfg_mod.normalize_identifier(
            _opt(args.physical_user_column, "PHYSICAL_USER_COLUMN", user_column),
            "--physical-user-column",
        )
        physical_timestamp_column = cfg_mod.normalize_identifier(
            _opt(
                args.physical_timestamp_column,
                "PHYSICAL_TIMESTAMP_COLUMN",
                timestamp_column,
            ),
            "--physical-timestamp-column",
        )
        network_column_raw = _opt(
            args.physical_network_column, "PHYSICAL_NETWORK_COLUMN"
        )
        network_value = _opt(args.physical_network_value, "PHYSICAL_NETWORK_VALUE")
        if bool(network_column_raw) != bool(network_value):
            raise ValueError(
                "--physical-network-column e --physical-network-value"
                " devem ser informados juntos."
            )
        network_column = (
            cfg_mod.normalize_identifier(
                network_column_raw, "--physical-network-column"
            )
            if network_column_raw
            else None
        )
        physical = cfg_mod.PhysicalLoginTableConfig(
            schema=physical_schema,
            table=physical_table,
            user_column=physical_user_column,
            timestamp_column=physical_timestamp_column,
            network_column=network_column,
            network_value=network_value,
        )

    host, port, database = cfg_mod.parse_jdbc_url(jdbc_url)
    credentials_path = cfg_mod.resolve_path(credentials_file, base_dir)
    username, password = cfg_mod.load_credentials(credentials_path)

    return (
        cfg_mod.BacktestConfig(
            db2=cfg_mod.Db2ConnectionConfig(
                hostname=host,
                port=port,
                database=database,
                username=username,
                password=password,
            ),
            vpn_table=cfg_mod.VpnTableConfig(
                schema=schema,
                table=table,
                user_column=user_column,
                timestamp_column=timestamp_column,
                source_ip_column=source_ip_column,
                corporate_ip_column=corporate_ip_column,
                hostname_column=hostname_column,
                device_column=device_column,
            ),
            physical_table=physical,
            start=start,
            end=end,
            active_window_hours=args.active_window_hours,
            distinct_limit=args.distinct_limit,
            daily_login_limit=args.daily_login_limit,
            sample_limit=args.sample_limit,
            output_dir=cfg_mod.resolve_path(args.output_dir, base_dir),
        ),
        jdbc_url,
        credentials_path,
    )


def _parameters_payload(cfg, jdbc_url, credentials_path):
    """Parametros para reprodutibilidade do relatorio. Nunca inclui credenciais."""
    physical = None
    if cfg.physical_table is not None:
        physical = {
            "schema": cfg.physical_table.schema,
            "table": cfg.physical_table.table,
            "user_column": cfg.physical_table.user_column,
            "timestamp_column": cfg.physical_table.timestamp_column,
            "network_column": cfg.physical_table.network_column,
            "network_value": cfg.physical_table.network_value,
        }
    return {
        "start": cfg.start.strftime("%Y-%m-%d %H:%M:%S"),
        "end": cfg.end.strftime("%Y-%m-%d %H:%M:%S"),
        "jdbc_url": jdbc_url,
        "credentials_file": str(credentials_path),
        "vpn_schema": cfg.vpn_table.schema,
        "vpn_table": cfg.vpn_table.table,
        "user_column": cfg.vpn_table.user_column,
        "timestamp_column": cfg.vpn_table.timestamp_column,
        "source_ip_column": cfg.vpn_table.source_ip_column,
        "corporate_ip_column": cfg.vpn_table.corporate_ip_column,
        "hostname_column": cfg.vpn_table.hostname_column,
        "device_column": cfg.vpn_table.device_column,
        "physical_table_config": physical,
        "active_window_hours": cfg.active_window_hours,
        "distinct_limit": cfg.distinct_limit,
        "daily_login_limit": cfg.daily_login_limit,
        "sample_limit": cfg.sample_limit,
        "output_dir": str(cfg.output_dir),
    }


def main(argv=None):
    base_dir = Path.cwd()
    cfg_mod.load_dotenv_file(base_dir / ".env")
    args = build_parser().parse_args(argv)

    try:
        cfg, jdbc_url, credentials_path = _build_config(args, base_dir)
    except ValueError as exc:
        print("Erro de configuracao: {0}".format(exc), file=sys.stderr)
        return 2

    conn = db2.connect(cfg.db2)
    try:
        metrics, cases = rules.run_backtest_cases(conn, cfg)
    except ValueError as exc:
        print("Erro de validacao: {0}".format(exc), file=sys.stderr)
        return 2
    finally:
        db2.close(conn)

    payload = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "parameters": _parameters_payload(cfg, jdbc_url, credentials_path),
        "metrics": metrics,
        "cases": [asdict(case) for case in cases],
    }

    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = cfg.output_dir / "backtest_vpn_{0}.json".format(stamp)
    md_path = cfg.output_dir / "backtest_vpn_{0}.md".format(stamp)
    report.write_json(json_path, payload)
    report.write_markdown(md_path, payload)

    print("Relatorios gerados: {0} {1}".format(json_path, md_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
