#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "ibm-db",
#     "redis",
#     "python-dotenv",
# ]
# ///
"""
VPN Data Writer - Lê sessões VPN do Redis e grava na tabela DB2PEP.AUT_CPTV.

Fluxo:
1. Conecta ao Redis via Sentinel (mesma configuração do login_handler.py)
2. Conecta ao DB2 via ibm_db
3. Monitora o ZSET PEP:syslog:sessions:bytime para novas sessões
4. Para cada sessão nova, lê o Hash e insere na tabela DB2
5. Marca sessões já gravadas para evitar duplicação

Segurança:
- Credenciais DB2 em arquivo JSON com permissão 600
- Credenciais Redis via variáveis de ambiente
"""

import sys
import time
import json
import logging
import os
import signal
from datetime import datetime
from typing import Optional, Tuple, List
from dataclasses import dataclass

import ibm_db
from redis.sentinel import Sentinel, MasterNotFoundError
from redis.exceptions import ConnectionError, TimeoutError, RedisError
from dotenv import load_dotenv

load_dotenv()

# ─── Configuração ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RedisConfig:
    """Configuração de conexão com Redis Sentinel."""
    sentinels: List[Tuple[str, int]]
    master_name: str
    sentinel_password: Optional[str]
    master_username: Optional[str]
    master_password: Optional[str]
    socket_timeout: int = 3


@dataclass(frozen=True)
class DB2Config:
    """Configuração de conexão com DB2."""
    hostname: str
    port: str
    database: str
    username: str
    password: str
    schema: str
    table: str


def parse_sentinels(raw: Optional[str]) -> List[Tuple[str, int]]:
    """Parseia string de sentinels no formato 'host:port,host:port'."""
    if not raw:
        return []
    sentinels = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" in item:
            host, port = item.split(":", 1)
            sentinels.append((host, int(port)))
        else:
            sentinels.append((item, 26379))
    return sentinels


def load_db2_credentials(path: str) -> dict:
    """Carrega credenciais DB2 de arquivo JSON."""
    with open(path, "r") as f:
        return json.load(f)


def load_config() -> Tuple[RedisConfig, DB2Config, str, int, str, int]:
    """Carrega configuração do ambiente e arquivo de credenciais."""
    sentinels = parse_sentinels(os.getenv("REDIS_SENTINELS"))

    redis_cfg = RedisConfig(
        sentinels=sentinels,
        master_name=os.getenv("REDIS_MASTER_NAME", "mymaster"),
        sentinel_password=os.getenv("REDIS_SENTINEL_PASSWORD") or None,
        master_username=os.getenv("REDIS_MASTER_USERNAME") or None,
        master_password=os.getenv("REDIS_PASSWORD") or None,
    )

    # Credenciais DB2
    creds_file = os.getenv("DB2_CREDENTIALS_FILE", "./db2_credentials.json")
    creds = load_db2_credentials(creds_file)

    db2_cfg = DB2Config(
        hostname=os.getenv("DB2_HOSTNAME", "brdb2p1.plexbsb.bb.com.br"),
        port=os.getenv("DB2_PORT", "446"),
        database=os.getenv("DB2_DATABASE", "BRDB2P1"),
        username=creds["username"],
        password=creds["password"],
        schema=os.getenv("DB2_SCHEMA", "DB2PEP"),
        table=os.getenv("DB2_TABLE", "AUT_CPTV"),
    )

    log_file = os.getenv("VPN_WRITER_LOG_FILE") or os.getenv("LOG_FILE", "/var/log/vpn_data_writer.log")
    poll_interval = int(os.getenv("POLL_INTERVAL_SECONDS", "5"))
    batch_size = int(os.getenv("BATCH_SIZE", "1000"))
    cursor_key = os.getenv("DB2_CURSOR_KEY", "PEP:db2writer:last_score")

    return redis_cfg, db2_cfg, log_file, poll_interval, cursor_key, batch_size


# ─── Constantes Redis ────────────────────────────────────────────────────────

SESSION_KEY_PREFIX = "PEP:syslog:session:"
SESSIONS_INDEX_ZSET = "PEP:syslog:sessions:bytime"
WRITTEN_SET_KEY = "PEP:db2writer:written"

# ─── Mapeamento Redis → DB2 ──────────────────────────────────────────────────
# Cada tupla: (campo_redis, coluna_db2, tipo_db2)
# Tipos: 'str', 'timestamp', 'int', 'decimal'

FIELD_MAP = [
    ("session_uid",             "CD_UNCO_AUT",      "str"),
    ("login_timestamp",         "TS_TRAN",          "timestamp"),
    ("src",                     "CD_END_LGC_OGM",   "str"),
    ("office_mode_ip",          "CD_END_LGC_CPTV",  "str"),
    ("login_option",            "NM_MTD_AUT",       "str"),
    ("hostname",                "NM_DSVO",          "str"),
    ("mac_address",             "CD_END_FSCO",      "str"),
    ("device_identification",   "CD_IDFC_DSVO",     "str"),
    ("fingerprint",             "CD_IDFC_ACSS",     "str"),
    ("os_name",                 "NM_SO",            "str"),
    ("os_version",              "CD_VRS_SO",        "str"),
    ("tunnel_protocol",         "CD_TIP_CNXO",      "str"),
    ("matricula_id",            "CD_USU_AUT",       "str"),
    ("user_group",              "TX_GR_ACSS",       "str"),
]

# ─── Globais ─────────────────────────────────────────────────────────────────

RUNNING = True


def signal_handler(signum, frame):
    """Encerra graciosamente ao receber SIGTERM/SIGINT."""
    global RUNNING
    logging.info("Sinal %s recebido, encerrando...", signum)
    RUNNING = False


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

# ─── Conexões ────────────────────────────────────────────────────────────────


def connect_redis(cfg: RedisConfig):
    """Conecta ao Redis Master via Sentinel."""
    if not cfg.sentinels:
        raise ValueError("REDIS_SENTINELS não configurado")

    kw = {"socket_timeout": cfg.socket_timeout}
    if cfg.sentinel_password:
        kw["sentinel_kwargs"] = {"password": cfg.sentinel_password}

    sentinel = Sentinel(cfg.sentinels, **kw)
    host, port = sentinel.discover_master(cfg.master_name)
    logging.info("Redis master descoberto: %s:%s (service=%s)", host, port, cfg.master_name)

    redis_client = sentinel.master_for(
        cfg.master_name,
        socket_timeout=cfg.socket_timeout,
        decode_responses=True,
        username=cfg.master_username,
        password=cfg.master_password,
    )
    redis_client.ping()
    return redis_client


def connect_db2(cfg: DB2Config):
    """Conecta ao DB2 via ibm_db."""
    conn_str = (
        f"DATABASE={cfg.database};"
        f"HOSTNAME={cfg.hostname};"
        f"PORT={cfg.port};"
        f"PROTOCOL=TCPIP;"
        f"UID={cfg.username};"
        f"PWD={cfg.password};"
    )
    conn = ibm_db.connect(conn_str, "", "")
    if not conn:
        raise RuntimeError(f"Falha ao conectar ao DB2: {ibm_db.conn_errormsg()}")
    logging.info("Conectado ao DB2 %s:%s/%s", cfg.hostname, cfg.port, cfg.database)
    return conn


# ─── Lógica de inserção ──────────────────────────────────────────────────────


def get_next_id(db2_conn, schema: str, table: str) -> int:
    """Obtém próximo CD_IDFR_AUT (MAX + 1)."""
    sql = f"SELECT COALESCE(MAX(CD_IDFR_AUT), 0) FROM {schema}.{table}"
    stmt = ibm_db.exec_immediate(db2_conn, sql)
    row = ibm_db.fetch_tuple(stmt)
    return int(row[0]) + 1 if row else 1


def parse_timestamp(value) -> Optional[str]:
    """Converte valor de timestamp para formato DB2."""
    if not value:
        return None
    try:
        ts = float(value)
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")
    except (ValueError, TypeError, OSError):
        pass
    # Tenta como string ISO
    if isinstance(value, str) and len(value) >= 19:
        return value[:26]
    return None


def build_insert_sql(schema: str, table: str) -> str:
    """Constrói o SQL de INSERT parametrizado."""
    columns = ["CD_IDFR_AUT", "TS_TRAN", "NR_PTC"]
    columns += [col for (_, col, _) in FIELD_MAP if col not in ("TS_TRAN",)]

    placeholders = ", ".join(["?"] * len(columns))
    col_list = ", ".join(columns)
    return f"INSERT INTO {schema}.{table} ({col_list}) VALUES ({placeholders})"


def prepare_row(session_data: dict, next_id: int) -> Optional[tuple]:
    """
    Prepara uma tupla de valores para INSERT a partir dos dados do Redis.

    Retorna None se dados obrigatórios estiverem faltando.
    """
    # TS_TRAN é obrigatório
    ts_raw = session_data.get("login_timestamp") or session_data.get("time") or session_data.get("updated_at")
    ts_value = parse_timestamp(ts_raw)
    if not ts_value:
        return None

    # NR_PTC = mês extraído do timestamp
    try:
        nr_ptc = int(ts_value[5:7])
    except (ValueError, IndexError):
        nr_ptc = 1

    values = [next_id, ts_value, nr_ptc]

    for redis_field, db2_col, dtype in FIELD_MAP:
        if db2_col == "TS_TRAN":
            continue  # já adicionado acima

        raw = session_data.get(redis_field)

        if raw is None or raw == "":
            values.append(None)
        elif dtype == "str":
            values.append(str(raw))
        elif dtype == "int":
            try:
                values.append(int(raw))
            except (ValueError, TypeError):
                values.append(None)
        elif dtype == "timestamp":
            values.append(parse_timestamp(raw))
        else:
            values.append(str(raw))

    return tuple(values)


def insert_session(db2_conn, schema: str, table: str, session_data: dict, next_id: int) -> bool:
    """Insere uma sessão no DB2. Retorna True em caso de sucesso."""
    row = prepare_row(session_data, next_id)
    if row is None:
        logging.warning("Sessão descartada (dados obrigatórios ausentes): uid=%s",
                        session_data.get("session_uid", "?"))
        return False

    sql = build_insert_sql(schema, table)
    try:
        stmt = ibm_db.prepare(db2_conn, sql)
        for i, val in enumerate(row, start=1):
            ibm_db.bind_param(stmt, i, val)
        ibm_db.execute(stmt)
        return True
    except Exception as e:
        logging.error("Erro ao inserir no DB2 (uid=%s): %s",
                      session_data.get("session_uid", "?"), e)
        return False


# ─── Loop principal ──────────────────────────────────────────────────────────


def process_batch(redis_client, db2_conn, db2_cfg: DB2Config,
                  cursor_key: str, batch_size: int = 1000) -> tuple[int, int, int, int]:
    """
    Processa um lote de sessões novas do Redis para o DB2.

    Retorna uma tupla com:
    (inseridos, lidos_no_zset, sem_hash_no_redis, ja_marcados_como_gravados)
    """
    # Obtém último score processado
    last_score = redis_client.get(cursor_key)
    if not last_score:
        # Sem cursor: pular direto para dados recentes (últimas 2h)
        # Hashes mais antigos que o TTL (25h) já expiraram no Redis.
        initial_score = str(time.time() - 7200)
        redis_client.set(cursor_key, initial_score)
        logging.info("Cursor inicial definido para %s (2h atrás)", initial_score)
        last_score = initial_score
    min_score = f"({last_score}"

    # Busca sessões ordenadas por timestamp (score)
    entries = redis_client.zrangebyscore(
        SESSIONS_INDEX_ZSET, min_score, "+inf",
        start=0, num=batch_size, withscores=True
    )

    if not entries:
        return 0, 0, 0, 0

    next_id = get_next_id(db2_conn, db2_cfg.schema, db2_cfg.table)
    inserted = 0
    missing_hash = 0
    already_written = 0
    max_score = last_score or "0"

    for session_uid, score in entries:
        # Verifica se já foi gravada
        if redis_client.sismember(WRITTEN_SET_KEY, session_uid):
            already_written += 1
            max_score = str(score)
            continue

        # Lê dados da sessão
        session_key = SESSION_KEY_PREFIX + session_uid
        session_data = redis_client.hgetall(session_key)

        if not session_data:
            logging.debug("Sessão %s sem dados no Redis, pulando", session_uid)
            missing_hash += 1
            max_score = str(score)
            continue

        if insert_session(db2_conn, db2_cfg.schema, db2_cfg.table, session_data, next_id):
            redis_client.sadd(WRITTEN_SET_KEY, session_uid)
            next_id += 1
            inserted += 1

        max_score = str(score)

    # Atualiza cursor
    redis_client.set(cursor_key, max_score)
    return inserted, len(entries), missing_hash, already_written


def main():
    """Loop principal: poll Redis → insert DB2."""
    redis_cfg, db2_cfg, log_file, poll_interval, cursor_key, batch_size = load_config()

    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    logging.info("Iniciando vpn_data_writer (poll=%ds, batch=%d, db2=%s:%s/%s/%s.%s)",
                 poll_interval, batch_size, db2_cfg.hostname, db2_cfg.port,
                 db2_cfg.database,
                 db2_cfg.schema, db2_cfg.table)

    redis_client = None
    db2_conn = None
    backoff = 1
    max_backoff = 60
    loops_without_inserts = 0
    skipped_total = 0
    total_inserted_since_start = 0
    start_time = time.time()

    while RUNNING:
        # Conexão Redis
        if redis_client is None:
            try:
                redis_client = connect_redis(redis_cfg)
                backoff = 1
            except Exception as e:
                logging.error("Falha ao conectar Redis: %s", e)
                time.sleep(min(backoff, max_backoff))
                backoff = min(backoff * 2, max_backoff)
                continue

        # Conexão DB2
        if db2_conn is None:
            try:
                db2_conn = connect_db2(db2_cfg)
                backoff = 1
            except Exception as e:
                logging.error("Falha ao conectar DB2: %s", e)
                time.sleep(min(backoff, max_backoff))
                backoff = min(backoff * 2, max_backoff)
                continue

        # Processa lote
        try:
            inserted, scanned, missing_hash, already_written = process_batch(
                redis_client, db2_conn, db2_cfg, cursor_key, batch_size
            )
            if inserted > 0:
                total_inserted_since_start += inserted
                elapsed = time.time() - start_time
                rate = total_inserted_since_start / elapsed if elapsed > 0 else 0
                logging.info(
                    "Lote gravado: inseridos=%d, lidos=%d, sem_hash=%d, ja_gravados=%d | total=%d, taxa=%.1f/s",
                    inserted, scanned, missing_hash, already_written,
                    total_inserted_since_start, rate,
                )
                ibm_db.commit(db2_conn)
                loops_without_inserts = 0
                skipped_total = 0
                if scanned >= batch_size:
                    continue  # batch cheio = backlog, processar sem pausa
            elif scanned > 0 and missing_hash + already_written == scanned:
                # Lote inteiro sem hash útil — fast-forward sem esperar
                skipped_total += scanned
                if skipped_total % 10000 < scanned:
                    logging.info(
                        "Fast-forward: %d entradas puladas no total (sem_hash=%d, ja_gravados=%d, cursor=%s)",
                        skipped_total, missing_hash, already_written,
                        redis_client.get(cursor_key),
                    )
                continue  # pula o sleep
            else:
                loops_without_inserts += 1
                skipped_total = 0
                # Heartbeat a cada ~1 minuto para facilitar troubleshooting.
                if loops_without_inserts * poll_interval >= 60:
                    logging.info(
                        "Sem insercoes no periodo: lidos=%d, sem_hash=%d, ja_gravados=%d, cursor=%s",
                        scanned,
                        missing_hash,
                        already_written,
                        redis_client.get(cursor_key),
                    )
                    loops_without_inserts = 0
            time.sleep(poll_interval)

        except (ConnectionError, TimeoutError, RedisError) as e:
            logging.error("Erro Redis: %s", e)
            redis_client = None
            time.sleep(min(backoff, max_backoff))
            backoff = min(backoff * 2, max_backoff)

        except Exception as e:
            error_msg = str(e)
            if "SQL" in error_msg or "IBM" in error_msg or "db2" in error_msg.lower():
                logging.error("Erro DB2, reconectando: %s", e)
                try:
                    ibm_db.close(db2_conn)
                except Exception:
                    pass
                db2_conn = None
            else:
                logging.exception("Erro inesperado: %s", e)
            time.sleep(min(backoff, max_backoff))
            backoff = min(backoff * 2, max_backoff)

    # Cleanup
    logging.info("Encerrando vpn_data_writer")
    if db2_conn:
        try:
            ibm_db.close(db2_conn)
        except Exception:
            pass


if __name__ == "__main__":
    main()
