#!/usr/bin/env python3
"""Busca tentativas repetidas de login na tabela DB2PEP.AUT_CPTV (VPN) no dia de hoje.

Usa as credenciais existentes em ../gravar_dados_vpn/db2_credentials.json (mesmo
formato usado pelos demais scripts do projeto: {"username":..., "password":...}).

Nenhuma credencial é impressa. Somente resultados agregados sao mostrados.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal
from pathlib import Path

try:
    import ibm_db
except ImportError:
    print("ERRO: pacote 'ibm_db' nao encontrado. Instale com: pip install ibm_db",
          file=sys.stderr)
    sys.exit(2)


DEFAULT_JDBC_URL = "jdbc:db2://b2db2g5.plexbs2.bb.com.br:61250/B2DB2G5"
DEFAULT_CREDENTIALS = Path(__file__).resolve().parent / "db2_credentials.json"

SCHEMA = "DB2PEP"
TABLE = "AUT_CPTV"
USER_COL = "CD_USU_AUT"
TS_COL = "TS_TRAN"
SRC_IP_COL = "CD_END_LGC_OGM"

# Colunas de detalhe salvas no JSON para cada tentativa (inclui CD_IDFR_AUT).
DETAIL_COLUMNS = (
    "CD_IDFR_AUT",
    USER_COL,
    TS_COL,
    "CD_END_LGC_OGM",
    "CD_END_LGC_CPTV",
    "CD_END_FSCO",
    "CD_IDFC_DSVO",
    "CD_IDFC_ACSS",
    "CD_VRS_SO",
    "CD_TIP_CNXO",
    "NM_DSVO",
    "NM_MTD_AUT",
    "NM_SO",
    "NR_PTC",
)

_JDBC_RE = re.compile(r"^jdbc:db2://([^:/]+):(\d+)/(\S+)$")


@dataclass(frozen=True)
class Db2Config:
    hostname: str
    port: int
    database: str
    username: str
    password: str


def parse_jdbc_url(url: str) -> tuple[str, int, str]:
    m = _JDBC_RE.match(url.strip())
    if not m:
        raise ValueError("JDBC URL invalida: esperado jdbc:db2://host:port/db")
    return m.group(1), int(m.group(2)), m.group(3)


def load_credentials(path: Path) -> tuple[str, str]:
    if not path.is_file():
        raise FileNotFoundError(f"Credenciais nao encontradas em: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    user = data.get("username")
    pwd = data.get("password")
    if not user or not pwd:
        raise ValueError("JSON deve conter 'username' e 'password' nao vazios.")
    return str(user), str(pwd)


def connect(cfg: Db2Config):
    dsn = (
        f"DATABASE={cfg.database};"
        f"HOSTNAME={cfg.hostname};"
        f"PORT={cfg.port};"
        f"PROTOCOL=TCPIP;"
        f"UID={cfg.username};"
        f"PWD={cfg.password};"
    )
    return ibm_db.connect(dsn, "", "")


def _json_default(value):
    if isinstance(value, datetime):
        return value.isoformat(sep=" ")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, timedelta):
        return str(value)
    if isinstance(value, Decimal):
        if value == value.to_integral_value():
            return int(value)
        return float(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return value.hex()
    raise TypeError(f"Nao serializavel: {type(value).__name__}")


def fetch_all(conn, sql: str, params: tuple = ()) -> list[dict]:
    stmt = ibm_db.prepare(conn, sql)
    if stmt is False:
        raise RuntimeError(f"Falha ao preparar SQL: {sql}")
    ok = ibm_db.execute(stmt, params) if params else ibm_db.execute(stmt)
    if ok is False:
        raise RuntimeError(f"Falha ao executar SQL: {sql}")
    rows: list[dict] = []
    row = ibm_db.fetch_assoc(stmt)
    while row:
        rows.append({str(k).upper(): v for k, v in row.items()})
        row = ibm_db.fetch_assoc(stmt)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jdbc-url", default=os.environ.get("DB2_JDBC_URL", DEFAULT_JDBC_URL))
    ap.add_argument("--credentials", default=os.environ.get("DB2_CREDENTIALS_FILE",
                                                            str(DEFAULT_CREDENTIALS)))
    ap.add_argument("--data", help="Data alvo YYYY-MM-DD (default: hoje).", default=None)
    ap.add_argument("--min-tentativas", type=int, default=3,
                    help="Numero minimo de tentativas para considerar repetido (default: 3).")
    ap.add_argument("--limite", type=int, default=100,
                    help="Limite de linhas no ranking (default: 100).")
    ap.add_argument("--saida", default=None,
                    help="Arquivo JSON de saida (default: repeated_logins_<data>.json).")
    args = ap.parse_args()

    target_day = (datetime.strptime(args.data, "%Y-%m-%d").date()
                  if args.data else date.today())
    day_str = target_day.strftime("%Y-%m-%d")

    host, port, database = parse_jdbc_url(args.jdbc_url)
    username, password = load_credentials(Path(args.credentials).expanduser())
    cfg = Db2Config(host, port, database, username, password)

    print(f"[info] Conectando em {host}:{port}/{database} como {username}...")
    conn = None
    try:
        conn = connect(cfg)
        print(f"[info] Conectado. Buscando tentativas repetidas em {SCHEMA}.{TABLE} "
              f"no dia {day_str} (min_tentativas>={args.min_tentativas}).")

        # Ranking por usuario: numero total de tentativas e IPs distintos no dia.
        sql_por_usuario = f"""
            SELECT {USER_COL} AS USUARIO,
                   COUNT(*) AS TENTATIVAS,
                   COUNT(DISTINCT {SRC_IP_COL}) AS IPS_DISTINTOS,
                   MIN({TS_COL}) AS PRIMEIRA,
                   MAX({TS_COL}) AS ULTIMA
              FROM {SCHEMA}.{TABLE}
             WHERE DATE({TS_COL}) = ?
             GROUP BY {USER_COL}
            HAVING COUNT(*) >= ?
             ORDER BY TENTATIVAS DESC, USUARIO
             FETCH FIRST {int(args.limite)} ROWS ONLY
        """
        linhas = fetch_all(conn, sql_por_usuario, (day_str, args.min_tentativas))

        saida_path = Path(args.saida) if args.saida else (
            Path(__file__).resolve().parent
            / f"repeated_logins_{day_str}.json"
        )

        if not linhas:
            print(f"[ok] Nenhum usuario com >= {args.min_tentativas} tentativas em {day_str}.")
            payload = {
                "gerado_em": datetime.now().isoformat(timespec="seconds"),
                "data_alvo": day_str,
                "schema": SCHEMA,
                "tabela": TABLE,
                "min_tentativas": args.min_tentativas,
                "total_usuarios": 0,
                "usuarios": [],
            }
            saida_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, default=_json_default),
                encoding="utf-8",
            )
            print(f"[info] JSON salvo em: {saida_path}")
            return 0

        print()
        print(f"Usuarios com tentativas repetidas em {day_str} "
              f"(min {args.min_tentativas}):")
        print(f"{'USUARIO':<20} {'TENTATIVAS':>10} {'IPS':>6}  "
              f"{'PRIMEIRA':<20} {'ULTIMA':<20}")
        print("-" * 82)
        for r in linhas:
            usuario_txt = "(NULL)" if r["USUARIO"] is None else str(r["USUARIO"])
            print(f"{usuario_txt:<20} {r['TENTATIVAS']:>10} {r['IPS_DISTINTOS']:>6}  "
                  f"{str(r['PRIMEIRA']):<20} {str(r['ULTIMA']):<20}")

        # Detalhes: uma tentativa por linha, para cada usuario do ranking.
        # Importante: `CD_USU_AUT IN (...)` nao casa com NULL em SQL, entao
        # tratamos o grupo NULL separadamente com `IS NULL`.
        cols_sql = ", ".join(DETAIL_COLUMNS)
        usuarios_nao_nulos = [r["USUARIO"] for r in linhas if r["USUARIO"] is not None]
        tem_grupo_nulo = any(r["USUARIO"] is None for r in linhas)

        clausulas = []
        params_detalhe: list = [day_str]
        if usuarios_nao_nulos:
            placeholders = ", ".join(["?"] * len(usuarios_nao_nulos))
            clausulas.append(f"{USER_COL} IN ({placeholders})")
            params_detalhe.extend(usuarios_nao_nulos)
        if tem_grupo_nulo:
            clausulas.append(f"{USER_COL} IS NULL")

        sql_detalhes = f"""
            SELECT {cols_sql}
              FROM {SCHEMA}.{TABLE}
             WHERE DATE({TS_COL}) = ?
               AND ({' OR '.join(clausulas)})
             ORDER BY {USER_COL}, {TS_COL}
        """
        detalhes = fetch_all(conn, sql_detalhes, tuple(params_detalhe))

        # Chave "__NULL__" agrupa eventos sem usuario preenchido.
        NULL_KEY = "__NULL__"
        por_usuario: dict[str, list[dict]] = {}
        for row in detalhes:
            valor = row.get(USER_COL)
            chave = NULL_KEY if valor is None else str(valor).strip()
            por_usuario.setdefault(chave, []).append(row)

        usuarios_payload = []
        for r in linhas:
            valor = r["USUARIO"]
            if valor is None:
                chave = NULL_KEY
                usuario_repr = None
            else:
                chave = str(valor).strip()
                usuario_repr = chave
            usuarios_payload.append({
                "usuario": usuario_repr,
                "tentativas": int(r["TENTATIVAS"]),
                "ips_distintos": int(r["IPS_DISTINTOS"]),
                "primeira": r["PRIMEIRA"],
                "ultima": r["ULTIMA"],
                "eventos": por_usuario.get(chave, []),
            })

        total_tentativas = sum(r["TENTATIVAS"] for r in linhas)
        payload = {
            "gerado_em": datetime.now().isoformat(timespec="seconds"),
            "data_alvo": day_str,
            "schema": SCHEMA,
            "tabela": TABLE,
            "min_tentativas": args.min_tentativas,
            "total_usuarios": len(linhas),
            "total_tentativas": int(total_tentativas),
            "colunas_evento": list(DETAIL_COLUMNS),
            "usuarios": usuarios_payload,
        }
        saida_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, default=_json_default),
            encoding="utf-8",
        )

        print()
        print(f"[resumo] {len(linhas)} usuario(s) suspeito(s); "
              f"{total_tentativas} tentativa(s) somadas.")
        print(f"[info] JSON salvo em: {saida_path}")
        return 0

    except Exception as exc:
        print(f"[erro] {exc}", file=sys.stderr)
        return 1
    finally:
        if conn is not None:
            try:
                ibm_db.close(conn)
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
