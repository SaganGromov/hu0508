#!/usr/bin/env python3
"""SELECT * FROM DB2PEP.MTA_AUT_CLI_TRAN WHERE CD_UNCO_TRAN = ?

Usa as credenciais em ~/HU11202222/gravar_dados_vpn/db2_credentials.json
e o mesmo DSN default do backtest (b2db2g5.plexbs2.bb.com.br:61250/B2DB2G5).

A tabela é enorme e o único índice útil é o PK ``CD_IDFR_MTA`` — nem
``TS_TRAN`` nem ``CD_UNCO_TRAN`` estão indexados, então uma consulta
com filtro só nesses campos estoura ``SQL0905N`` (ASUTIME=9s).

Estratégia adotada aqui: reaproveitar o ``estimate_pk_window`` do
``backtest_vpn.mta`` para traduzir uma janela de tempo em uma janela
de PK e restringir a varredura a esse intervalo. Depois filtramos
``CD_UNCO_TRAN`` em memória (o filtro no SQL também é aplicado para
já reduzir o volume trazido).

Rodar dentro do venv que tem ibm_db + backtest_vpn instalados:
    /home/wsl/HU11202222/NEW_HU_072026/backtest_vpn_local/.venv/bin/python \
        /home/wsl/HU11202222/NEW_HU_072026/query_cd_unco_tran.py \
        --cd 2702446a-3d49-40b0-8016-1f486e4d9cf9 \
        --since "2026-07-20 12:00:00" --until "2026-07-23 00:00:00"
"""
import argparse
import json
import sys
from datetime import datetime, timedelta

import ibm_db

from backtest_vpn import config as cfg_mod
from backtest_vpn import mta as mta_mod
from backtest_vpn.db2 import connect as db2_connect, fetch_all

CRED_FILE = "/home/wsl/HU11202222/gravar_dados_vpn/db2_credentials.json"
DEFAULT_TARGET = "2702446a-3d49-40b0-8016-1f486e4d9cf9"


def _parse_ts(text):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    raise ValueError("timestamp inválido: {0!r}".format(text))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cd", default=DEFAULT_TARGET, help="CD_UNCO_TRAN")
    ap.add_argument("--since", default=None, help="TS_TRAN >= (YYYY-MM-DD [HH:MM:SS])")
    ap.add_argument("--until", default=None, help="TS_TRAN <  (YYYY-MM-DD [HH:MM:SS])")
    ap.add_argument("--days", type=int, default=14,
                    help="Janela padrão em dias se --since/--until não vierem")
    ap.add_argument("--chunk-hours", type=int, default=4,
                    help="Tamanho de cada sub-janela para não estourar ASUTIME")
    args = ap.parse_args()

    ts_hi = _parse_ts(args.until) if args.until else datetime.now()
    ts_lo = _parse_ts(args.since) if args.since else (ts_hi - timedelta(days=args.days))

    username, password = cfg_mod.load_credentials(CRED_FILE)
    host, port, database = cfg_mod.parse_jdbc_url(cfg_mod.DEFAULT_JDBC_URL)
    db2_cfg = cfg_mod.Db2ConnectionConfig(
        hostname=host, port=port, database=database,
        username=username, password=password,
    )
    conn = db2_connect(db2_cfg)
    try:
        mta = mta_mod.MtaConfig(schema="DB2PEP", table="MTA_AUT_CLI_TRAN")

        chunk = timedelta(hours=args.chunk_hours)
        matches = []
        total_scanned = 0
        cursor = ts_lo
        while cursor < ts_hi:
            sub_hi = min(cursor + chunk, ts_hi)
            pk_lo, pk_hi = mta_mod.estimate_pk_window(conn, mta, cursor, sub_hi)
            if pk_lo is None:
                cursor = sub_hi
                continue
            sql = (
                "SELECT * FROM DB2PEP.MTA_AUT_CLI_TRAN "
                "WHERE CD_IDFR_MTA BETWEEN ? AND ? "
                "AND TS_TRAN >= ? AND TS_TRAN < ? "
                "AND CD_UNCO_TRAN = ?"
            )
            print("[chunk] {0} → {1}  PK[{2},{3}]".format(
                cursor.isoformat(), sub_hi.isoformat(), pk_lo, pk_hi), file=sys.stderr)
            rows = fetch_all(conn, sql, (pk_lo, pk_hi,
                                         cursor.strftime("%Y-%m-%d %H:%M:%S"),
                                         sub_hi.strftime("%Y-%m-%d %H:%M:%S"),
                                         args.cd))
            total_scanned += len(rows)
            for r in rows:
                matches.append({k: (str(v) if v is not None else None) for k, v in r.items()})
            cursor = sub_hi

        print(json.dumps(matches, indent=2, ensure_ascii=False))
        print("[{0} linha(s) casadas · janela {1} → {2}]".format(
            len(matches), ts_lo.isoformat(), ts_hi.isoformat()), file=sys.stderr)
    finally:
        ibm_db.close(conn)


if __name__ == "__main__":
    main()
