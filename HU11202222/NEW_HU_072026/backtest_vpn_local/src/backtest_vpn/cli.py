"""CLI do backtest local de VPN sobre DB2."""

import argparse
import os
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from . import bundle as bundle_mod
from . import config as cfg_mod
from . import db2, htmlreport, labelfree, mta as mta_mod, proxies, pseudonym, report, rules

KNOWN_SUBCOMMANDS = {"run", "labelfree", "full", "report-html", "extract", "parity", "inject", "adjudicate", "bundle"}


def _parse_int_list(text):
    if isinstance(text, list):
        return text
    return [int(part.strip()) for part in str(text).split(",") if part.strip()]


def _add_common_flags(parser, require_period=True):
    parser.add_argument("--start", required=require_period, help="Inicio do periodo (YYYY-MM-DD ou 'YYYY-MM-DD HH:MM:SS')")
    parser.add_argument("--end", required=require_period, help="Fim exclusivo do periodo (YYYY-MM-DD ou 'YYYY-MM-DD HH:MM:SS')")
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
    parser.add_argument("--physical-table", help="Tabela de login fisico (env PHYSICAL_TABLE); sem ela R5 e pulado")
    parser.add_argument("--physical-user-column", help="Coluna de usuario na tabela fisica (env PHYSICAL_USER_COLUMN)")
    parser.add_argument("--physical-timestamp-column", help="Coluna de timestamp na tabela fisica (env PHYSICAL_TIMESTAMP_COLUMN)")
    parser.add_argument("--physical-network-column", help="Coluna de rede na tabela fisica (env PHYSICAL_NETWORK_COLUMN)")
    parser.add_argument("--physical-network-value", help="Valor esperado da coluna de rede (env PHYSICAL_NETWORK_VALUE)")
    parser.add_argument("--no-mta-physical", action="store_true", help="Desliga a deteccao 'VPN + rede fisica' via MTA_AUT_CLI_TRAN")
    parser.add_argument("--mta-schema", help="Schema da tabela MTA (env MTA_SCHEMA, padrao DB2PEP)")
    parser.add_argument("--mta-table", help="Tabela MTA (env MTA_TABLE, padrao MTA_AUT_CLI_TRAN)")
    parser.add_argument("--mta-decision-nodes", help="Lista CSV de NM_ETP considerados 'login efetivo' (env MTA_DECISION_NODES)")
    parser.add_argument("--physical-ip-cidrs", help="Faixas privadas consideradas 'rede fisica' (env PHYSICAL_IP_CIDRS)")
    parser.add_argument("--mta-delta-minutes", type=int, help="Δ em minutos ao redor de cada evento VPN (env MTA_DELTA_MINUTES, padrao 15)")
    parser.add_argument("--mta-max-users", type=int, help="Maximo de usuarios distintos verificados por rodada (env MTA_MAX_USERS, padrao 300)")
    parser.add_argument("--mta-users-per-batch", type=int, help="Usuarios agrupados por statement em MTA (env MTA_USERS_PER_BATCH, padrao 12)")
    parser.add_argument("--mta-chunk-hours", type=int, help="Tamanho em horas dos chunks temporais para respeitar ASUTIME (env MTA_CHUNK_HOURS, padrao 24)")
    parser.add_argument("--active-window-hours", type=int, default=8, help="Janela de sessao ativa em horas (1..168, padrao 8)")
    parser.add_argument("--distinct-limit", type=int, default=2, help="Limite de valores distintos por usuario (padrao 2)")
    parser.add_argument("--daily-login-limit", type=int, default=10, help="Limite de logins por usuario por dia (padrao 10)")
    parser.add_argument("--sample-limit", type=int, default=50, help="Tamanho maximo das amostras (padrao 50)")
    parser.add_argument("--output-dir", default="reports", help="Diretorio de saida dos relatorios (padrao: reports)")
    parser.add_argument("--sweep-distinct-limits", default="1,2,3,5,8,13,21")
    parser.add_argument("--sweep-daily-limits", default="5,10,20,50,100")
    parser.add_argument("--sweep-window-hours", default="1,2,4,8,12,24")
    parser.add_argument("--stability-granularity", default="week")
    parser.add_argument("--velocity-minutes", type=int, default=5)
    parser.add_argument("--dormancy-days", type=int, default=60)
    parser.add_argument("--seed", type=int, default=20260719)
    parser.add_argument("--clean-cohort-min-events", type=int, default=20)
    parser.add_argument("--pseudonym-key", default=".pseudonym_key")
    parser.add_argument(
        "--no-pseudonymize",
        action="store_true",
        help="Desativa a pseudonimizacao HMAC (mostra as matriculas explicitamente no bundle).",
    )


def build_parser():
    parser = argparse.ArgumentParser(prog="backtest-vpn", description="Backtest local (somente leitura) das regras de deteccao de VPN sobre dados historicos em DB2.")
    sub = parser.add_subparsers(dest="command")
    run_p = sub.add_parser("run", help="Relatorio legado")
    _add_common_flags(run_p)
    lab_p = sub.add_parser("labelfree", help="Fase A: metricas label-free e proxies")
    _add_common_flags(lab_p)
    full_p = sub.add_parser("full", help="Executa run legado + labelfree + bundle")
    _add_common_flags(full_p)
    html_p = sub.add_parser("report-html", help="Gera HTML standalone e fragmento a partir do bundle")
    html_p.add_argument("--bundle", required=True)
    html_p.add_argument("--out-dir", default="reports/html")
    group = html_p.add_mutually_exclusive_group()
    group.add_argument("--standalone-only", action="store_true")
    group.add_argument("--fragment-only", action="store_true")
    html_p.add_argument("--lang", default="pt-BR")
    html_p.add_argument("--title", default="Relatorio Backtest VPN")
    for name in ("extract", "parity", "inject", "bundle"):
        p = sub.add_parser(name, help="Stub nao implementado nesta rodada")
        p.add_argument("args", nargs="*")
    adj = sub.add_parser("adjudicate", help="Stub nao implementado nesta rodada")
    adj.add_argument("args", nargs="*")
    return parser


def _opt(cli_value, env_name, default=None):
    if cli_value is not None and str(cli_value).strip() != "":
        return cli_value
    env_value = os.environ.get(env_name)
    if env_value is not None and env_value.strip() != "":
        return env_value
    return default


def _build_config(args, base_dir):
    jdbc_url = _opt(args.jdbc_url, "DB2_JDBC_URL", cfg_mod.DEFAULT_JDBC_URL)
    credentials_file = _opt(args.credentials_file, "DB2_CREDENTIALS_FILE", cfg_mod.DEFAULT_CREDENTIALS_FILE)

    schema = cfg_mod.normalize_identifier(_opt(args.schema, "DB2_SCHEMA", "DB2PEP"), "--schema")
    table = cfg_mod.normalize_identifier(_opt(args.table, "DB2_TABLE", "AUT_CPTV"), "--table")
    user_column = cfg_mod.normalize_identifier(_opt(args.user_column, "VPN_USER_COLUMN", "CD_USU_AUT"), "--user-column")
    timestamp_column = cfg_mod.normalize_identifier(_opt(args.timestamp_column, "VPN_TIMESTAMP_COLUMN", "TS_TRAN"), "--timestamp-column")
    source_ip_column = cfg_mod.normalize_identifier(_opt(args.source_ip_column, "VPN_SOURCE_IP_COLUMN", "CD_END_LGC_OGM"), "--source-ip-column")
    corporate_ip_column = cfg_mod.normalize_identifier(_opt(args.corporate_ip_column, "VPN_CORPORATE_IP_COLUMN", "CD_END_LGC_CPTV"), "--corporate-ip-column")
    hostname_column = cfg_mod.normalize_identifier(_opt(args.hostname_column, "VPN_HOSTNAME_COLUMN", "NM_DSVO"), "--hostname-column")
    device_column = cfg_mod.normalize_identifier(_opt(args.device_column, "VPN_DEVICE_COLUMN", "CD_IDFC_DSVO"), "--device-column")

    start = cfg_mod.parse_datetime(args.start)
    end = cfg_mod.parse_datetime(args.end)
    if end <= start:
        raise ValueError("--end deve ser maior que --start.")
    if not 1 <= args.active_window_hours <= 168:
        raise ValueError("--active-window-hours deve estar entre 1 e 168.")
    for label, value in (("--distinct-limit", args.distinct_limit), ("--daily-login-limit", args.daily_login_limit), ("--sample-limit", args.sample_limit), ("--velocity-minutes", args.velocity_minutes), ("--dormancy-days", args.dormancy_days), ("--clean-cohort-min-events", args.clean_cohort_min_events)):
        if value <= 0:
            raise ValueError("{0} deve ser um inteiro positivo.".format(label))

    physical = None
    physical_table_raw = _opt(args.physical_table, "PHYSICAL_TABLE")
    if physical_table_raw:
        physical_schema = cfg_mod.normalize_identifier(_opt(args.physical_schema, "PHYSICAL_SCHEMA", schema), "--physical-schema")
        physical_table = cfg_mod.normalize_identifier(physical_table_raw, "--physical-table")
        physical_user_column = cfg_mod.normalize_identifier(_opt(args.physical_user_column, "PHYSICAL_USER_COLUMN", user_column), "--physical-user-column")
        physical_timestamp_column = cfg_mod.normalize_identifier(_opt(args.physical_timestamp_column, "PHYSICAL_TIMESTAMP_COLUMN", timestamp_column), "--physical-timestamp-column")
        network_column_raw = _opt(args.physical_network_column, "PHYSICAL_NETWORK_COLUMN")
        network_value = _opt(args.physical_network_value, "PHYSICAL_NETWORK_VALUE")
        if bool(network_column_raw) != bool(network_value):
            raise ValueError("--physical-network-column e --physical-network-value devem ser informados juntos.")
        network_column = cfg_mod.normalize_identifier(network_column_raw, "--physical-network-column") if network_column_raw else None
        physical = cfg_mod.PhysicalLoginTableConfig(physical_schema, physical_table, physical_user_column, physical_timestamp_column, network_column, network_value)

    host, port, database = cfg_mod.parse_jdbc_url(jdbc_url)
    credentials_path = cfg_mod.resolve_path(credentials_file, base_dir)
    username, password = cfg_mod.load_credentials(credentials_path)

    mta_cfg = None
    if not getattr(args, "no_mta_physical", False):
        env_overrides = {}
        for arg_name, env_name in (
            ("mta_schema", "MTA_SCHEMA"),
            ("mta_table", "MTA_TABLE"),
            ("mta_decision_nodes", "MTA_DECISION_NODES"),
            ("physical_ip_cidrs", "PHYSICAL_IP_CIDRS"),
            ("mta_delta_minutes", "MTA_DELTA_MINUTES"),
            ("mta_max_users", "MTA_MAX_USERS"),
            ("mta_users_per_batch", "MTA_USERS_PER_BATCH"),
            ("mta_chunk_hours", "MTA_CHUNK_HOURS"),
        ):
            value = getattr(args, arg_name, None)
            if value is not None and str(value) != "":
                env_overrides[env_name] = str(value)
        merged_env = dict(os.environ)
        merged_env.update(env_overrides)
        mta_cfg = mta_mod.load_mta_config_from_env(env=merged_env)

    cfg = cfg_mod.BacktestConfig(
        db2=cfg_mod.Db2ConnectionConfig(hostname=host, port=port, database=database, username=username, password=password),
        vpn_table=cfg_mod.VpnTableConfig(schema=schema, table=table, user_column=user_column, timestamp_column=timestamp_column, source_ip_column=source_ip_column, corporate_ip_column=corporate_ip_column, hostname_column=hostname_column, device_column=device_column),
        physical_table=physical,
        start=start,
        end=end,
        active_window_hours=args.active_window_hours,
        distinct_limit=args.distinct_limit,
        daily_login_limit=args.daily_login_limit,
        sample_limit=args.sample_limit,
        output_dir=cfg_mod.resolve_path(args.output_dir, base_dir),
        sweep_distinct_limits=_parse_int_list(args.sweep_distinct_limits),
        sweep_daily_limits=_parse_int_list(args.sweep_daily_limits),
        sweep_window_hours=_parse_int_list(args.sweep_window_hours),
        stability_granularity=args.stability_granularity,
        velocity_minutes=args.velocity_minutes,
        dormancy_days=args.dormancy_days,
        seed=args.seed,
        clean_cohort_min_events=args.clean_cohort_min_events,
        mta_table=mta_cfg,
    )
    return cfg, jdbc_url, credentials_path


def _parameters_payload(cfg, jdbc_url, credentials_path):
    physical = None
    if cfg.physical_table is not None:
        physical = {
            "schema": cfg.physical_table.schema, "table": cfg.physical_table.table,
            "user_column": cfg.physical_table.user_column, "timestamp_column": cfg.physical_table.timestamp_column,
            "network_column": cfg.physical_table.network_column, "network_value": cfg.physical_table.network_value,
        }
    mta = None
    if cfg.mta_table is not None:
        mta = {
            "schema": cfg.mta_table.schema,
            "table": cfg.mta_table.table,
            "decision_nodes": list(cfg.mta_table.decision_nodes),
            "delta_minutes": cfg.mta_table.delta_minutes,
            "max_users_per_run": cfg.mta_table.max_users_per_run,
            "users_per_batch": cfg.mta_table.users_per_batch,
            "physical_ip_cidrs": [str(n) for n in cfg.mta_table.ip_networks],
        }
    return {
        "start": cfg.start.strftime("%Y-%m-%d %H:%M:%S"), "end": cfg.end.strftime("%Y-%m-%d %H:%M:%S"),
        "jdbc_url": jdbc_url, "credentials_file": str(credentials_path),
        "vpn_schema": cfg.vpn_table.schema, "vpn_table": cfg.vpn_table.table,
        "user_column": cfg.vpn_table.user_column, "timestamp_column": cfg.vpn_table.timestamp_column,
        "source_ip_column": cfg.vpn_table.source_ip_column, "corporate_ip_column": cfg.vpn_table.corporate_ip_column,
        "hostname_column": cfg.vpn_table.hostname_column, "device_column": cfg.vpn_table.device_column,
        "physical_table_config": physical, "active_window_hours": cfg.active_window_hours,
        "mta_table_config": mta,
        "distinct_limit": cfg.distinct_limit, "daily_login_limit": cfg.daily_login_limit,
        "sample_limit": cfg.sample_limit, "output_dir": str(cfg.output_dir),
        "sweep_distinct_limits": cfg.sweep_distinct_limits, "sweep_daily_limits": cfg.sweep_daily_limits,
        "sweep_window_hours": cfg.sweep_window_hours, "stability_granularity": cfg.stability_granularity,
        "velocity_minutes": cfg.velocity_minutes, "dormancy_days": cfg.dormancy_days,
        "seed": cfg.seed, "clean_cohort_min_events": cfg.clean_cohort_min_events,
    }


def _connect_and_run_cases(cfg):
    conn = db2.connect(cfg.db2)
    try:
        metrics, cases = rules.run_backtest_cases(conn, cfg)
    finally:
        db2.close(conn)
    return metrics, cases


def _write_legacy_reports(cfg, params, metrics, cases, stamp, generated_at):
    payload = {"generated_at": generated_at, "parameters": params, "metrics": metrics, "cases": [asdict(case) for case in cases]}
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = cfg.output_dir / "backtest_vpn_{0}.json".format(stamp)
    md_path = cfg.output_dir / "backtest_vpn_{0}.md".format(stamp)
    report.write_json(json_path, payload)
    report.write_markdown(md_path, payload)
    print("Relatorios gerados: {0} {1}".format(json_path, md_path))
    return json_path, md_path


def _run_bundle(cfg, params, metrics, cases, base_dir, stamp, generated_at, no_pseudonymize=False):
    if no_pseudonymize:
        pz = pseudonym.IdentityPseudonymizer()
    else:
        key_path = cfg_mod.resolve_path(getattr(cfg, "pseudonym_key", ".pseudonym_key"), base_dir) if hasattr(cfg, "pseudonym_key") else base_dir / ".pseudonym_key"
        key = pseudonym.load_or_create_key(key_path, repo_dir=base_dir)
        pz = pseudonym.Pseudonymizer(key)
    conn = db2.connect(cfg.db2)
    try:
        lf = labelfree.run_labelfree(conn, cfg, legacy_metrics=metrics, legacy_cases=cases, pseudonymizer=pz)
        try:
            proxy_payload, agreement = proxies.run_proxies(conn, cfg, lf["base_stats"], lf["flag_sets"], pseudonymizer=pz)
        except Exception as exc:
            msg = str(exc)
            if "CLI0106E" in msg or "Connection is closed" in msg:
                print("[bundle] conexao DB2 caiu apos labelfree; reabrindo para proxies... ({0})".format(msg.splitlines()[0]))
                try:
                    db2.close(conn)
                except Exception:
                    pass
                conn = db2.connect(cfg.db2)
                proxy_payload, agreement = proxies.run_proxies(conn, cfg, lf["base_stats"], lf["flag_sets"], pseudonymizer=pz)
            else:
                raise
    finally:
        db2.close(conn)
    lf_public = {k: v for k, v in lf.items() if k not in ("base_stats", "daily_rows", "flag_sets", "r4_user_days")}
    repo_root = base_dir.parent
    payload = bundle_mod.build_results_bundle(cfg, params, metrics, cases, lf_public, proxy_payload, agreement, pz, repo_root, generated_at=generated_at)
    path = bundle_mod.write_results_bundle(cfg.output_dir, stamp, payload)
    print("Bundle gerado: {0}".format(path))
    return path


def _command_run(args, base_dir):
    cfg, jdbc_url, credentials_path = _build_config(args, base_dir)
    metrics, cases = _connect_and_run_cases(cfg)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _write_legacy_reports(cfg, _parameters_payload(cfg, jdbc_url, credentials_path), metrics, cases, stamp, generated_at)
    return 0


def _command_labelfree(args, base_dir, write_legacy=False):
    cfg, jdbc_url, credentials_path = _build_config(args, base_dir)
    metrics, cases = _connect_and_run_cases(cfg)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    params = _parameters_payload(cfg, jdbc_url, credentials_path)
    if write_legacy:
        _write_legacy_reports(cfg, params, metrics, cases, stamp, generated_at)
    _run_bundle(cfg, params, metrics, cases, base_dir, stamp, generated_at, no_pseudonymize=bool(getattr(args, "no_pseudonymize", False)))
    return 0


def _command_report_html(args):
    standalone = not args.fragment_only
    fragment = not args.standalone_only
    paths = htmlreport.write_html_report(args.bundle, out_dir=args.out_dir, standalone=standalone, fragment=fragment, title=args.title)
    print("HTML gerado: {0}".format(" ".join(str(p) for p in paths.values())))
    return 0


def main(argv=None):
    base_dir = Path.cwd()
    cfg_mod.load_dotenv_file(base_dir / ".env")
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in KNOWN_SUBCOMMANDS and "--start" in argv:
        argv.insert(0, "run")
    args = build_parser().parse_args(argv)
    if not args.command:
        build_parser().print_help()
        return 2
    if args.command in ("extract", "parity", "inject", "adjudicate", "bundle"):
        print("skipped: not implemented in this handoff run")
        return 0
    try:
        if args.command == "run":
            return _command_run(args, base_dir)
        if args.command == "labelfree":
            return _command_labelfree(args, base_dir, write_legacy=False)
        if args.command == "full":
            return _command_labelfree(args, base_dir, write_legacy=True)
        if args.command == "report-html":
            return _command_report_html(args)
    except ValueError as exc:
        print("Erro de configuracao: {0}".format(exc), file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
