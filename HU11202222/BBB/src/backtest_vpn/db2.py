from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import ibm_db

from .config import Db2ConnectionConfig


def connect(config: Db2ConnectionConfig):
    conn_str = (
        f"DATABASE={config.database};"
        f"HOSTNAME={config.hostname};"
        f"PORT={config.port};"
        "PROTOCOL=TCPIP;"
        f"UID={config.username};"
        f"PWD={config.password};"
    )
    return ibm_db.connect(conn_str, "", "")


def fetch_all(conn, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
    stmt = ibm_db.prepare(conn, sql)
    params_tuple = tuple(params)
    if params_tuple:
        ibm_db.execute(stmt, params_tuple)
    else:
        ibm_db.execute(stmt)

    rows: list[dict[str, Any]] = []
    row = ibm_db.fetch_assoc(stmt)
    while row:
        rows.append({str(k).upper(): v for k, v in row.items()})
        row = ibm_db.fetch_assoc(stmt)
    return rows


def close(conn) -> None:
    ibm_db.close(conn)
