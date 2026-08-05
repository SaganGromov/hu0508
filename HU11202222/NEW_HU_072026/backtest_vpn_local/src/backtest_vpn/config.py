"""Configuracao do backtest local de VPN: constantes, dataclasses e helpers."""

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

DEFAULT_JDBC_URL = "jdbc:db2://b2db2g5.plexbs2.bb.com.br:61250/B2DB2G5"
DEFAULT_CREDENTIALS_FILE = "../gravar_dados_vpn/db2_credentials.json"

# Identificadores SQL (schema, tabela, coluna) precisam passar por esta regex
# ANTES de qualquer interpolacao em SQL. Valores literais usam binding `?`.
_IDENTIFIER_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_JDBC_URL_RE = re.compile(r"^jdbc:db2://([^:/]+):(\d+)/([^:;]+).*$")

_DATETIME_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d")


@dataclass(frozen=True)
class Db2ConnectionConfig:
    hostname: str
    port: int
    database: str
    username: str
    password: str


@dataclass(frozen=True)
class VpnTableConfig:
    schema: str
    table: str
    user_column: str
    timestamp_column: str
    source_ip_column: str
    corporate_ip_column: str
    hostname_column: str
    device_column: str


@dataclass(frozen=True)
class PhysicalLoginTableConfig:
    schema: str
    table: str
    user_column: str
    timestamp_column: str
    network_column: Optional[str]
    network_value: Optional[str]


@dataclass(frozen=True)
class BacktestConfig:
    db2: Db2ConnectionConfig
    vpn_table: VpnTableConfig
    physical_table: Optional[PhysicalLoginTableConfig]
    start: datetime
    end: datetime
    active_window_hours: int
    distinct_limit: int
    daily_login_limit: int
    sample_limit: int
    output_dir: Path
    sweep_distinct_limits: List[int]
    sweep_daily_limits: List[int]
    sweep_window_hours: List[int]
    stability_granularity: str
    velocity_minutes: int
    dormancy_days: int
    seed: int
    clean_cohort_min_events: int
    mta_table: Optional[object] = None


def load_dotenv_file(path):
    """Carrega um arquivo .env simples (KEY=VALUE) sem sobrescrever o ambiente.

    Linhas em branco e comentarios (#) sao ignorados. Usa
    os.environ.setdefault para que flags de CLI e variaveis ja exportadas
    tenham precedencia. Nunca escreve no arquivo.
    """
    path = Path(path)
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if key:
            os.environ.setdefault(key, value)


def parse_jdbc_url(url):
    """Extrai (host, porta, banco) de uma URL JDBC DB2."""
    match = _JDBC_URL_RE.match(str(url).strip())
    if not match:
        raise ValueError(
            "JDBC URL invalida (esperado jdbc:db2://host:porta/banco): {0}".format(url)
        )
    return match.group(1), int(match.group(2)), match.group(3)


def load_credentials(path):
    """Le o JSON de credenciais {"username": ..., "password": ...}.

    Nunca inclui a senha em mensagens de erro.
    """
    path = Path(path)
    if not path.is_file():
        raise ValueError("Arquivo de credenciais nao encontrado: {0}".format(path))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Arquivo de credenciais nao contem JSON valido: {0} (linha {1})".format(
                path, exc.lineno
            )
        )
    if not isinstance(data, dict):
        raise ValueError(
            "Arquivo de credenciais deve ser um objeto JSON: {0}".format(path)
        )
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        raise ValueError(
            'Arquivo de credenciais deve conter as chaves "username" e "password"'
            " nao vazias: {0}".format(path)
        )
    return str(username), str(password)


def parse_datetime(value):
    """Aceita 'YYYY-MM-DD' ou 'YYYY-MM-DD HH:MM:SS'."""
    text = str(value).strip()
    for fmt in _DATETIME_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    raise ValueError(
        "Data/hora invalida: {0!r} (use YYYY-MM-DD ou 'YYYY-MM-DD HH:MM:SS')".format(value)
    )


def normalize_identifier(value, label):
    """Uppercase e valida um identificador SQL; levanta ValueError com o flag."""
    if value is None or str(value).strip() == "":
        raise ValueError("{0}: identificador nao informado.".format(label))
    normalized = str(value).strip().upper()
    if not _IDENTIFIER_RE.match(normalized):
        raise ValueError(
            "{0}: identificador invalido {1!r}"
            " (esperado ^[A-Z][A-Z0-9_]*$ apos uppercase).".format(label, value)
        )
    return normalized


def resolve_path(path, base_dir):
    """Resolve `path` como absoluto, relativo a `base_dir` quando necessario."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = Path(base_dir) / candidate
    return candidate.resolve()
