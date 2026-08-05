"""Acesso DB2 via ibm_db: conexao, consulta parametrizada e encerramento.

Nenhuma funcao deste modulo imprime nada nem registra credenciais.
"""

import ibm_db


def connect(db2_config):
    """Abre uma conexao ibm_db a partir de um Db2ConnectionConfig."""
    dsn = (
        "DATABASE={database};"
        "HOSTNAME={hostname};"
        "PORT={port};"
        "PROTOCOL=TCPIP;"
        "UID={username};"
        "PWD={password};"
    ).format(
        database=db2_config.database,
        hostname=db2_config.hostname,
        port=db2_config.port,
        username=db2_config.username,
        password=db2_config.password,
    )
    return ibm_db.connect(dsn, "", "")


def fetch_all(conn, sql, params=()):
    """Prepara e executa `sql` com binding `?`, retornando list[dict].

    As chaves de cada linha sao normalizadas para maiusculas.
    """
    stmt = ibm_db.prepare(conn, sql)
    if stmt is False:
        raise RuntimeError("Falha ao preparar SQL: {0}".format(sql))
    executed = ibm_db.execute(stmt, tuple(params))
    if executed is False:
        raise RuntimeError("Falha ao executar SQL: {0}".format(sql))
    rows = []
    row = ibm_db.fetch_assoc(stmt)
    while row:
        rows.append({str(key).upper(): value for key, value in row.items()})
        row = ibm_db.fetch_assoc(stmt)
    return rows


def close(conn):
    """Fecha a conexao ibm_db, ignorando conexoes nulas."""
    if conn is not None:
        ibm_db.close(conn)
