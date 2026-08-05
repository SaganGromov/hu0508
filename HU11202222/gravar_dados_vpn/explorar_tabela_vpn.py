#!/usr/bin/env python3
"""
Explora metadados de uma tabela DB2 e compara com o arquivo tabela_vpn.md.

Objetivos:
- Confirmar existência da tabela
- Listar colunas reais com tipo, nulidade e posição
- Mostrar chave primária e índices
- Comparar as colunas físicas do banco com as colunas descritas no Markdown

Segurança:
- Não deixe usuário/senha hardcoded no script
- Use arquivo de credenciais local (JSON) com permissão 600
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Iterable

try:
    import ibm_db
except ImportError:
    print(
        "ERRO: pacote 'ibm_db' não encontrado. Instale com: pip install ibm_db",
        file=sys.stderr,
    )
    sys.exit(2)


@dataclass(frozen=True)
class Db2Config:
    hostname: str
    port: int
    database: str
    username: str
    password: str
    protocol: str = "TCPIP"


@dataclass(frozen=True)
class CatalogQuerySet:
    mode: str
    table_info_sql: str
    columns_sql: str
    pk_sql: str
    idx_sql: str


def parse_jdbc_url(jdbc_url: str) -> tuple[str, int, str]:
    """Converte jdbc:db2://host:port/database em (host, port, database)."""
    pattern = r"^jdbc:db2://([^:/]+):(\d+)/(\S+)$"
    match = re.match(pattern, jdbc_url.strip())
    if not match:
        raise ValueError(
            "JDBC URL inválida. Formato esperado: jdbc:db2://host:port/database"
        )
    host, port, database = match.group(1), int(match.group(2)), match.group(3)
    return host, port, database


def load_credentials(path: str) -> tuple[str, str]:
    """Lê credenciais de um arquivo JSON no formato {\"username\":...,\"password\":...}."""
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Arquivo de credenciais não encontrado: {path}. "
            "Crie um JSON com campos username e password."
        )

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        raise ValueError("Credenciais inválidas: informe username e password no JSON.")

    return str(username), str(password)


def connect_db2(cfg: Db2Config):
    conn_str = (
        f"DATABASE={cfg.database};"
        f"HOSTNAME={cfg.hostname};"
        f"PORT={cfg.port};"
        f"PROTOCOL={cfg.protocol};"
        f"UID={cfg.username};"
        f"PWD={cfg.password};"
    )
    conn = ibm_db.connect(conn_str, "", "")
    return conn


def fetch_all(conn, sql: str, params: Iterable[str] = ()) -> list[dict]:
    stmt = ibm_db.prepare(conn, sql)
    params_list = list(params)
    if params_list:
        ibm_db.execute(stmt, tuple(params_list))
    else:
        ibm_db.execute(stmt)

    rows: list[dict] = []
    row = ibm_db.fetch_assoc(stmt)
    while row:
        rows.append({k.upper(): v for k, v in row.items()})
        row = ibm_db.fetch_assoc(stmt)
    return rows


def detect_catalog_mode(conn) -> str:
    """Detecta se o catálogo disponível é SYSCAT (LUW) ou SYSIBM (z/OS)."""
    try:
        fetch_all(conn, "SELECT TABNAME FROM SYSCAT.TABLES FETCH FIRST 1 ROWS ONLY")
        return "SYSCAT"
    except Exception:
        pass

    try:
        fetch_all(conn, "SELECT NAME FROM SYSIBM.SYSTABLES FETCH FIRST 1 ROWS ONLY")
        return "SYSIBM"
    except Exception as exc:
        raise RuntimeError(
            "Nao foi possivel detectar catalogo do DB2 (SYSCAT/SYSIBM)."
        ) from exc


def build_catalog_queries(mode: str) -> CatalogQuerySet:
    if mode == "SYSCAT":
        return CatalogQuerySet(
            mode="SYSCAT",
            table_info_sql="""
                SELECT
                    TABSCHEMA,
                    TABNAME,
                    TYPE,
                    CARD,
                    NPAGES,
                    TBSPACE,
                    CREATE_TIME,
                    STATS_TIME
                FROM SYSCAT.TABLES
                WHERE TABSCHEMA = ?
                  AND TABNAME = ?
            """,
            columns_sql="""
                SELECT
                    COLNO,
                    COLNAME,
                    TYPENAME,
                    LENGTH,
                    SCALE,
                    NULLS,
                    DEFAULT,
                    IDENTITY,
                    GENERATED,
                    REMARKS
                FROM SYSCAT.COLUMNS
                WHERE TABSCHEMA = ?
                  AND TABNAME = ?
                ORDER BY COLNO
            """,
            pk_sql="""
                SELECT k.COLNAME, k.COLSEQ
                FROM SYSCAT.TABCONST tc
                JOIN SYSCAT.KEYCOLUSE k
                  ON tc.CONSTNAME = k.CONSTNAME
                 AND tc.TABSCHEMA = k.TABSCHEMA
                 AND tc.TABNAME = k.TABNAME
                WHERE tc.TABSCHEMA = ?
                  AND tc.TABNAME = ?
                  AND tc.TYPE = 'P'
                ORDER BY k.COLSEQ
            """,
            idx_sql="""
                SELECT
                    INDNAME,
                    UNIQUERULE,
                    COLNAMES,
                    NLEAF,
                    NLEVELS
                FROM SYSCAT.INDEXES
                WHERE TABSCHEMA = ?
                  AND TABNAME = ?
                ORDER BY INDNAME
            """,
        )

    return CatalogQuerySet(
        mode="SYSIBM",
        table_info_sql="""
            SELECT
                CREATOR AS TABSCHEMA,
                NAME AS TABNAME,
                TYPE,
                CARDF AS CARD,
                CAST(NULL AS INTEGER) AS NPAGES,
                DBNAME AS TBSPACE,
                CREATEDTS AS CREATE_TIME,
                STATSTIME AS STATS_TIME
            FROM SYSIBM.SYSTABLES
            WHERE CREATOR = ?
              AND NAME = ?
        """,
        columns_sql="""
            SELECT
                COLNO,
                NAME AS COLNAME,
                COLTYPE AS TYPENAME,
                LENGTH,
                SCALE,
                NULLS,
                DEFAULT,
                CAST(NULL AS CHAR(1)) AS IDENTITY,
                CAST(NULL AS CHAR(1)) AS GENERATED,
                CAST(NULL AS VARCHAR(254)) AS REMARKS
            FROM SYSIBM.SYSCOLUMNS
            WHERE TBCREATOR = ?
              AND TBNAME = ?
            ORDER BY COLNO
        """,
        pk_sql="""
            SELECT
                k.COLNAME,
                k.COLSEQ
            FROM SYSIBM.SYSINDEXES i
            JOIN SYSIBM.SYSKEYS k
              ON i.CREATOR = k.IXCREATOR
             AND i.NAME = k.IXNAME
            WHERE i.TBCREATOR = ?
              AND i.TBNAME = ?
              AND i.UNIQUERULE = 'P'
            ORDER BY k.COLSEQ
        """,
        idx_sql="""
            SELECT
                NAME AS INDNAME,
                UNIQUERULE,
                CAST(NULL AS VARCHAR(32000)) AS COLNAMES,
                NLEAF,
                NLEVELS
            FROM SYSIBM.SYSINDEXES
            WHERE TBCREATOR = ?
              AND TBNAME = ?
            ORDER BY NAME
        """,
    )


def parse_markdown_physical_columns(md_path: str) -> list[str]:
    """
    Extrai valores da coluna 'Coluna Física' da tabela em Markdown.

    Regra simples:
    - pega linhas que começam com '|'
    - ignora linha separadora
    - usa segunda coluna do pipe table
    """
    if not os.path.exists(md_path):
        raise FileNotFoundError(f"Arquivo Markdown não encontrado: {md_path}")

    physical_cols: list[str] = []
    in_columns_section = False

    with open(md_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")
            if line.strip().lower() == "## colunas":
                in_columns_section = True
                continue

            if in_columns_section and line.startswith("## "):
                break

            if not in_columns_section:
                continue

            if not line.strip().startswith("|"):
                continue

            cells = [c.strip() for c in line.split("|")[1:-1]]
            if len(cells) < 2:
                continue

            if cells[0].lower() == "coluna lógica" and cells[1].lower() == "coluna física":
                continue

            if set("".join(cells)) <= {"-", ":", " "}:
                continue

            col = cells[1].upper()
            if col and re.match(r"^[A-Z0-9_]+$", col):
                physical_cols.append(col)

    unique_ordered: list[str] = []
    seen = set()
    for col in physical_cols:
        if col not in seen:
            seen.add(col)
            unique_ordered.append(col)

    return unique_ordered


def print_section(title: str):
    print("\n" + "=" * 88)
    print(title)
    print("=" * 88)


def fmt(value, width: int | None = None) -> str:
    """Formata valores possivelmente nulos para impressão tabular."""
    text = "" if value is None else str(value)
    if width is None:
        return text
    return f"{text:<{width}}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspeciona tabela DB2 e compara com colunas do Markdown"
    )
    parser.add_argument(
        "--jdbc-url",
        default="jdbc:db2://brdb2p1.plexbsb.bb.com.br:446/BRDB2P1",
        help="JDBC URL no formato jdbc:db2://host:port/database",
    )
    parser.add_argument("--schema", required=True, help="Schema da tabela no DB2")
    parser.add_argument("--table", required=True, help="Nome físico da tabela no DB2")
    parser.add_argument(
        "--credentials-file",
        default="./db2_credentials.json",
        help="Arquivo JSON com username/password",
    )
    parser.add_argument(
        "--markdown",
        default="./tabela_vpn.md",
        help="Arquivo Markdown para comparação das colunas físicas",
    )
    args = parser.parse_args()

    schema = args.schema.upper().strip()
    table = args.table.upper().strip()

    try:
        username, password = load_credentials(args.credentials_file)
        host, port, database = parse_jdbc_url(args.jdbc_url)
        cfg = Db2Config(
            hostname=host,
            port=port,
            database=database,
            username=username,
            password=password,
        )

        conn = connect_db2(cfg)
        catalog_mode = detect_catalog_mode(conn)
        catalog_queries = build_catalog_queries(catalog_mode)
    except Exception as exc:
        print(f"Falha ao conectar no DB2: {exc}", file=sys.stderr)
        return 1

    try:
        table_info = fetch_all(conn, catalog_queries.table_info_sql, (schema, table))

        print_section("1) EXISTENCIA E METADADOS DA TABELA")
        print(f"Catalogo detectado: {catalog_queries.mode}")
        if not table_info:
            if catalog_queries.mode == "SYSCAT":
                print(f"Tabela {schema}.{table} nao encontrada em SYSCAT.TABLES")
            else:
                print(f"Tabela {schema}.{table} nao encontrada em SYSIBM.SYSTABLES")
            return 2

        info = table_info[0]
        print(f"Tabela encontrada: {info['TABSCHEMA']}.{info['TABNAME']}")
        print(f"Tipo            : {info.get('TYPE')}")
        print(f"Cardinalidade   : {info.get('CARD')}")
        print(f"Tablespace      : {info.get('TBSPACE')}")
        print(f"Criacao         : {info.get('CREATE_TIME')}")
        print(f"Ultimas stats   : {info.get('STATS_TIME')}")

        columns = fetch_all(conn, catalog_queries.columns_sql, (schema, table))

        print_section("2) COLUNAS REAIS NO DB2")
        print(
            "# | COLNAME | TYPE | LENGTH | SCALE | NULLS | DEFAULT | IDENTITY | GENERATED"
        )
        for c in columns:
            print(
                f"{fmt(c.get('COLNO')):>2} | {fmt(c.get('COLNAME'), 30)} | {fmt(c.get('TYPENAME'), 12)} | "
                f"{fmt(c.get('LENGTH'), 6)} | {fmt(c.get('SCALE'), 5)} | {fmt(c.get('NULLS'), 5)} | "
                f"{fmt(c.get('DEFAULT'), 12)} | {fmt(c.get('IDENTITY'), 8)} | {fmt(c.get('GENERATED'))}"
            )

        pk_cols = fetch_all(conn, catalog_queries.pk_sql, (schema, table))

        print_section("3) CHAVE PRIMARIA")
        if pk_cols:
            pk = ", ".join(p["COLNAME"] for p in pk_cols)
            print(f"PK: {pk}")
        else:
            print("Sem chave primaria cadastrada")

        indexes = fetch_all(conn, catalog_queries.idx_sql, (schema, table))

        print_section("4) INDICES")
        if indexes:
            for idx in indexes:
                print(
                    f"{fmt(idx.get('INDNAME'), 35)} | unique={fmt(idx.get('UNIQUERULE'))} | "
                    f"cols={fmt(idx.get('COLNAMES'))} | nleaf={fmt(idx.get('NLEAF'))} | levels={fmt(idx.get('NLEVELS'))}"
                )
        else:
            print("Sem indices cadastrados")

        md_cols = parse_markdown_physical_columns(args.markdown)
        db_cols = [c["COLNAME"].upper() for c in columns]

        only_in_md = [c for c in md_cols if c not in db_cols]
        only_in_db = [c for c in db_cols if c not in md_cols]

        print_section("5) COMPARACAO MARKDOWN x DB2 (COLUNA FISICA)")
        print(f"Colunas no Markdown: {len(md_cols)}")
        print(f"Colunas no DB2     : {len(db_cols)}")

        if not only_in_md and not only_in_db:
            print("OK: As colunas fisicas do Markdown batem com o DB2.")
        else:
            if only_in_md:
                print("Presentes no Markdown e ausentes no DB2:")
                for col in only_in_md:
                    print(f"  - {col}")
            if only_in_db:
                print("Presentes no DB2 e ausentes no Markdown:")
                for col in only_in_db:
                    print(f"  - {col}")

        print_section("6) AMOSTRA DE DADOS")
        print("Tabela reportada como vazia: executando contagem e top 5 linhas.")
        count_sql = f"SELECT COUNT(1) AS QTD FROM {schema}.{table}"
        sample_sql = f"SELECT * FROM {schema}.{table} FETCH FIRST 5 ROWS ONLY"

        count_rows = fetch_all(conn, count_sql)
        qtd = count_rows[0]["QTD"] if count_rows else None
        print(f"Quantidade de linhas: {qtd}")

        if qtd and int(qtd) > 0:
            sample_rows = fetch_all(conn, sample_sql)
            for i, row in enumerate(sample_rows, start=1):
                print(f"Linha {i}: {row}")
        else:
            print("Sem registros para amostrar.")

        print_section("FINAL")
        print("Inspecao concluida com sucesso.")
        return 0
    except Exception as exc:
        print(f"Erro durante a inspecao: {exc}", file=sys.stderr)
        return 3
    finally:
        try:
            ibm_db.close(conn)
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
