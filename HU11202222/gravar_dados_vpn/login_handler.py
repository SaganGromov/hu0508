#!/usr/bin/env python3
"""
Login Handler - Processa eventos de login do syslog e armazena sessões no Redis e Kafka.

Estruturas de dados no Redis:
- PEP:syslog:session:<uid>        → Hash com dados da sessão
- PEP:syslog:sessions             → SET com todos os session_uid ativos
- PEP:syslog:sessions:bytime      → ZSET ordenado por timestamp
- PEP:syslog:matricula:<matricula> → Hash com última sessão do funcionário
- PEP:syslog:matricula:<matricula>:sessions → SET com session_uids do funcionário
- PEP:syslog:matricula:<matricula>:sessions:bytime → ZSET ordenado por timestamp
- PEP:syslog:user_ip:<ip>         → Hash com última sessão por IP
- PEP:syslog:unmatched            → Stream com eventos sem session_uid
"""
import sys
import time
import json
import logging
import re
from dataclasses import dataclass
from typing import Optional, Tuple, List
from redis.sentinel import Sentinel, MasterNotFoundError
from redis.exceptions import ConnectionError, TimeoutError, RedisError
from confluent_kafka import Producer as KafkaProducer
import os
from dotenv import load_dotenv

load_dotenv()


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
class KafkaConfig:
    """Configuração de conexão com Kafka."""
    bootstrap_servers: str
    security_protocol: str
    sasl_mechanism: str
    sasl_username: str
    sasl_password: str
    topic: str
    enabled: bool = True


@dataclass(frozen=True)
class SessionConfig:
    """Configuração de TTL das sessões."""
    ttl_seconds: int
    ttl_slack: int

    @property
    def effective_ttl(self) -> int:
        """TTL efetivo com margem de segurança."""
        return max(60, self.ttl_seconds + self.ttl_slack)


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


def load_config() -> Tuple[RedisConfig, SessionConfig, KafkaConfig, str]:
    """Carrega configuração do ambiente."""
    sentinels = parse_sentinels(os.getenv("REDIS_SENTINELS"))

    redis_cfg = RedisConfig(
        sentinels=sentinels,
        master_name=os.getenv("REDIS_MASTER_NAME", "mymaster"),
        sentinel_password=os.getenv("REDIS_SENTINEL_PASSWORD") or None,
        master_username=os.getenv("REDIS_MASTER_USERNAME") or None,
        master_password=os.getenv("REDIS_PASSWORD") or None,
    )

    try:
        ttl = int(os.getenv("SESSION_TTL_SECONDS", str(24 * 60 * 60)))
    except ValueError:
        ttl = 24 * 60 * 60

    try:
        slack = int(os.getenv("SESSION_TTL_SLACK", str(15 * 60)))
    except ValueError:
        slack = 15 * 60

    session_cfg = SessionConfig(ttl_seconds=ttl, ttl_slack=slack)
    log_file = os.getenv("LOG_FILE", "/var/log/redis_writer.log")

    kafka_enabled = os.getenv("KAFKA_ENABLED", "true").lower() in ("true", "1", "yes")
    kafka_cfg = KafkaConfig(
        bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "acr-kafka-seguranca.desenv.bb.com.br:443"),
        security_protocol=os.getenv("KAFKA_SECURITY_PROTOCOL", "SASL_SSL"),
        sasl_mechanism=os.getenv("KAFKA_SASL_MECHANISM", "SCRAM-SHA-512"),
        sasl_username=os.getenv("KAFKA_SASL_USERNAME", "kafka-user"),
        sasl_password=os.getenv("KAFKA_SASL_PASSWORD", "MTIzNDU2Nzg"),
        topic=os.getenv("KAFKA_TOPIC", "acr.vpn.redis.logs"),
        enabled=kafka_enabled,
    )

    return redis_cfg, session_cfg, kafka_cfg, log_file


# Carrega configuração global
REDIS_CONFIG, SESSION_CONFIG, KAFKA_CONFIG, LOG_FILE = load_config()

# Constantes de chaves Redis
STREAM_KEY = "PEP:syslog"
SESSION_KEY_PREFIX = "PEP:syslog:session:"
SESSIONS_INDEX_SET = "PEP:syslog:sessions"
SESSIONS_INDEX_ZSET = "PEP:syslog:sessions:bytime"
UNMATCHED_STREAM = "PEP:syslog:unmatched"
USER_DN_INDEX_PREFIX = "PEP:syslog:index:user_dn:"
USER_IP_CURRENT_PREFIX = "PEP:syslog:user_ip:"

# Novas constantes para índice por funcionário (matrícula)
MATRICULA_KEY_PREFIX = "PEP:syslog:matricula:"
MATRICULA_SESSIONS_SUFFIX = ":sessions"
MATRICULA_SESSIONS_BYTIME_SUFFIX = ":sessions:bytime"

# Regex para extrair matrícula (8 primeiros caracteres alfanuméricos)
MATRICULA_ID_PATTERN = re.compile(r"^([A-Za-z0-9]{8})")

# Kafka producer global
KAFKA_PRODUCER: Optional[KafkaProducer] = None

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def extract_matricula_id(user_dn: Optional[str]) -> Optional[str]:
    """
    Extrai a matrícula do funcionário (8 primeiros caracteres) do user_dn.
    
    Exemplo:
        "F9329989 THIAGO ZENI BAZOTTI" → "F9329989"
        "12345678 NOME SOBRENOME" → "12345678"
        None → None
        "ABC" → None (menos de 8 caracteres)
    """
    if not user_dn or not isinstance(user_dn, str):
        return None
    
    user_dn = user_dn.strip()
    match = MATRICULA_ID_PATTERN.match(user_dn)
    if match:
        return match.group(1).upper()
    return None


def _kafka_delivery_callback(err, msg):
    """Callback de confirmação de entrega ao Kafka."""
    if err is not None:
        logging.error("Falha ao entregar mensagem ao Kafka: %s", err)
    else:
        logging.debug(
            "Mensagem entregue em %s [%s] @ %s",
            msg.topic(), msg.partition(), msg.offset()
        )


def connect_kafka() -> Optional[KafkaProducer]:
    """Cria o producer Kafka. Retorna None se desabilitado ou em caso de erro."""
    cfg = KAFKA_CONFIG
    if not cfg.enabled:
        logging.info("Kafka desabilitado via KAFKA_ENABLED")
        return None

    try:
        conf = {
            'bootstrap.servers': cfg.bootstrap_servers,
            'security.protocol': cfg.security_protocol,
            'sasl.mechanism': cfg.sasl_mechanism,
            'sasl.username': cfg.sasl_username,
            'sasl.password': cfg.sasl_password,
        }
        producer = KafkaProducer(conf)
        logging.info("Kafka producer criado (bootstrap=%s, topic=%s)",
                     cfg.bootstrap_servers, cfg.topic)
        return producer
    except Exception as e:
        logging.error("Falha ao criar Kafka producer: %s", e)
        return None


def publish_to_kafka(producer: Optional[KafkaProducer], obj: dict):
    """Publica evento no Kafka de forma não-bloqueante. Falhas são apenas logadas."""
    if producer is None:
        return
    try:
        producer.produce(
            KAFKA_CONFIG.topic,
            value=json.dumps(obj, ensure_ascii=False).encode('utf-8'),
            callback=_kafka_delivery_callback,
        )
        producer.poll(0)
    except BufferError:
        logging.warning("Kafka producer buffer cheio, descartando evento")
    except Exception as e:
        logging.error("Erro ao publicar no Kafka: %s", e)


def connect_master():
    """Conecta ao Redis Master via Sentinel."""
    cfg = REDIS_CONFIG
    
    if not cfg.sentinels:
        raise ValueError("REDIS_SENTINELS não configurado")
    
    kw = {"socket_timeout": cfg.socket_timeout}
    if cfg.sentinel_password:
        kw["sentinel_kwargs"] = {"password": cfg.sentinel_password}
    
    sentinel = Sentinel(cfg.sentinels, **kw)

    try:
        host, port = sentinel.discover_master(cfg.master_name)
        logging.info(
            "Master descoberto via Sentinel %s:%s (service=%s, sentinel_auth=%s)",
            host, port, cfg.master_name, "on" if cfg.sentinel_password else "off"
        )
    except MasterNotFoundError:
        available_masters = _discover_available_masters(sentinel)
        raise MasterNotFoundError(
            f"Master '{cfg.master_name}' não encontrado. "
            f"Masters disponíveis: {', '.join(sorted(available_masters)) or 'nenhum'}"
        )

    redis_client = sentinel.master_for(
        cfg.master_name,
        socket_timeout=cfg.socket_timeout,
        decode_responses=True,
        username=cfg.master_username,
        password=cfg.master_password,
    )
    redis_client.ping()
    return redis_client


def _discover_available_masters(sentinel: Sentinel) -> set:
    """Lista masters disponíveis no Sentinel para diagnóstico."""
    names = set()
    for cli in sentinel.sentinels:
        try:
            masters = cli.sentinel_masters()
            if isinstance(masters, dict):
                for k in masters.keys():
                    name = k.decode() if isinstance(k, (bytes, bytearray)) else k
                    names.add(name)
        except Exception:
            pass
    return names

def parse_json_from_line(line: str) -> Optional[dict]:
    """
    Extrai o objeto JSON a partir do primeiro '{' encontrado na linha.
    
    Retorna None se não houver JSON válido.
    """
    idx = line.find("{")
    if idx < 0:
        return None
    try:
        return json.loads(line[idx:])
    except json.JSONDecodeError:
        return None


def to_str_mapping(obj: dict) -> dict:
    """
    Converte valores para string (Redis Hash espera strings).
    
    Dicionários e listas são serializados como JSON.
    Valores None são ignorados.
    """
    mapping = {}
    for key, value in obj.items():
        if value is None:
            continue
        if isinstance(value, (dict, list)):
            mapping[key] = json.dumps(value, ensure_ascii=False)
        else:
            mapping[key] = str(value)
    return mapping


def _update_matricula_index(pipeline, matricula_id: str, session_uid: str, 
                           mapping: dict, started_at: str, first_fields: dict,
                           ttl: int, now_ts: int):
    """
    Atualiza o índice de sessões por funcionário (matrícula).
    
    Estruturas criadas/atualizadas:
    - PEP:syslog:matricula:<matricula> → Hash com dados da última sessão
    - PEP:syslog:matricula:<matricula>:sessions → SET de session_uids
    - PEP:syslog:matricula:<matricula>:sessions:bytime → ZSET ordenado
    """
    matricula_key = MATRICULA_KEY_PREFIX + matricula_id
    sessions_set_key = matricula_key + MATRICULA_SESSIONS_SUFFIX
    sessions_zset_key = matricula_key + MATRICULA_SESSIONS_BYTIME_SUFFIX
    
    # Adiciona sessão aos índices do funcionário
    pipeline.sadd(sessions_set_key, session_uid)
    pipeline.zadd(sessions_zset_key, {session_uid: now_ts})
    
    # Atualiza hash do funcionário com dados de referência
    pipeline.hincrby(matricula_key, "__events", 1)
    pipeline.hincrby(matricula_key, "__sessions", 0)  # Inicializa se não existir
    
    # Apenas atualiza referências, não grava a sessão inteira aqui
    pipeline.hset(matricula_key, "last_session_uid", session_uid)
    pipeline.hset(matricula_key, "matricula_id", matricula_id)
    pipeline.hset(matricula_key, "updated_at", str(now_ts))
    
    # Campos imutáveis (primeira ocorrência)
    pipeline.hsetnx(matricula_key, "started_at", started_at)
    pipeline.hsetnx(matricula_key, "first_session_uid", session_uid)
    for field, value in first_fields.items():
        if value:
            pipeline.hsetnx(matricula_key, field, str(value))
    
    # TTL nas chaves do funcionário
    pipeline.expire(matricula_key, ttl)
    pipeline.expire(sessions_set_key, ttl)
    pipeline.expire(sessions_zset_key, ttl)


def _update_user_ip_index(pipeline, user_ip: str, session_uid: str,
                          mapping: dict, started_at: str, first_fields: dict,
                          ttl: int, prev_user_dn_norm: Optional[str]):
    """Atualiza índice por IP do usuário."""
    # Remove do índice antigo se mudou
    if prev_user_dn_norm and prev_user_dn_norm != user_ip:
        pipeline.srem(USER_DN_INDEX_PREFIX + prev_user_dn_norm, session_uid)
        pipeline.zrem(USER_DN_INDEX_PREFIX + prev_user_dn_norm + ":bytime", session_uid)
    
    # Adiciona/atualiza no índice atual
    now_ts = int(time.time())
    pipeline.sadd(USER_DN_INDEX_PREFIX + user_ip, session_uid)
    pipeline.zadd(USER_DN_INDEX_PREFIX + user_ip + ":bytime", {session_uid: now_ts})
    
    # Hash de último estado por IP
    user_ip_key = USER_IP_CURRENT_PREFIX + user_ip
    pipeline.hincrby(user_ip_key, "__events", 1)
    pipeline.hset(user_ip_key, mapping=mapping)
    pipeline.hsetnx(user_ip_key, "started_at", started_at)
    
    for field, value in first_fields.items():
        if value:
            pipeline.hsetnx(user_ip_key, field, str(value))
    
    pipeline.expire(user_ip_key, ttl)

def upsert_session(redis_client, obj: dict):
    """
    Enriquece um único Hash por session_uid e atualiza índices.
    
    Índices atualizados:
    - Por session_uid (principal)
    - Por matricula_id (matrícula do funcionário - 8 primeiros dígitos do user_dn)
    - Por user_ip (IP do office mode)
    """
    session_uid = obj.get("session_uid")
    now_ts = int(time.time())

    if not session_uid:
        try:
            redis_client.xadd(UNMATCHED_STREAM, {"raw": json.dumps(obj, ensure_ascii=False)})
        except Exception as e:
            logging.error("Falha ao xadd UNMATCHED: %s", e)
        return

    session_uid_str = str(session_uid)
    session_key = SESSION_KEY_PREFIX + session_uid_str
    mapping = to_str_mapping(obj)

    # Timestamps
    started_at = str(obj.get("login_timestamp") or obj.get("time") or now_ts)
    mapping["updated_at"] = str(now_ts)
    mapping["session_uid"] = session_uid_str

    # Extrai dados importantes
    user_ip = obj.get("office_mode_ip")
    user_dn = obj.get("user_dn")
    matricula_id = extract_matricula_id(user_dn)
    
    if user_ip:
        mapping["user_ip"] = user_ip
    if matricula_id:
        mapping["matricula_id"] = matricula_id

    ttl = SESSION_CONFIG.effective_ttl

    # Campos que devem ser definidos apenas na primeira vez
    first_fields = {
        "first_src": obj.get("src"),
        "first_origin": obj.get("origin"),
        "first_host_ip": obj.get("host_ip"),
    }

    # Busca valor anterior para comparação
    prev_user_dn_norm = redis_client.hget(session_key, "user_norm")

    # Executa atualizações em pipeline para atomicidade
    pipeline = redis_client.pipeline()
    
    # === Atualiza sessão principal ===
    pipeline.hincrby(session_key, "__events", 1)
    pipeline.hset(session_key, mapping=mapping)
    pipeline.hsetnx(session_key, "started_at", started_at)
    
    for field, value in first_fields.items():
        if value:
            pipeline.hsetnx(session_key, field, str(value))
    
    # Índices globais de sessões
    pipeline.sadd(SESSIONS_INDEX_SET, session_uid_str)
    pipeline.zadd(SESSIONS_INDEX_ZSET, {session_uid_str: now_ts})
    
    # === Índice por funcionário (matrícula) ===
    if matricula_id:
        _update_matricula_index(
            pipeline, matricula_id, session_uid_str,
            mapping, started_at, first_fields, ttl, now_ts
        )

    # === Índice por IP ===
    if user_ip:
        _update_user_ip_index(
            pipeline, user_ip, session_uid_str,
            mapping, started_at, first_fields, ttl, prev_user_dn_norm
        )

    # Renova TTL da sessão
    pipeline.expire(session_key, ttl)
    pipeline.execute()

    # === Publica no Kafka (isolado do Redis) ===
    publish_to_kafka(KAFKA_PRODUCER, obj)

def main():
    """Loop principal: lê stdin, parseia JSON e atualiza Redis e Kafka."""
    global KAFKA_PRODUCER
    redis_client = None
    backoff = 1
    max_backoff = 30
    
    logging.info("Iniciando login_handler (TTL=%ds, slack=%ds, kafka=%s)",
                 SESSION_CONFIG.ttl_seconds, SESSION_CONFIG.ttl_slack,
                 "on" if KAFKA_CONFIG.enabled else "off")
    
    # Inicializa Kafka producer (falha não impede inicialização)
    KAFKA_PRODUCER = connect_kafka()
    
    while True:
        # Conexão com Redis
        if redis_client is None:
            try:
                redis_client = connect_master()
                backoff = 1
                logging.info("Conectado ao master Redis via Sentinel (service=%s)",
                             REDIS_CONFIG.master_name)
            except Exception as e:
                logging.error("Falha ao conectar via Sentinel: %s", e)
                time.sleep(min(backoff, max_backoff))
                backoff = min(backoff * 2, max_backoff)
                continue

        # Lê linha do stdin
        line = sys.stdin.readline()
        if not line:
            time.sleep(0.05)
            continue
        
        line = line.rstrip("\r\n")
        if not line:
            continue

        try:
            obj = parse_json_from_line(line)
            if not obj:
                redis_client.xadd(UNMATCHED_STREAM, {"raw": line})
                continue
            upsert_session(redis_client, obj)
            
        except (ConnectionError, TimeoutError, RedisError) as e:
            logging.error("Erro Redis, reconectando: %s", e)
            redis_client = None
            time.sleep(min(backoff, max_backoff))
            backoff = min(backoff * 2, max_backoff)
            
        except Exception as e:
            logging.exception("Erro processando linha: %r (%s)", line, e)


if __name__ == "__main__":
    main()
