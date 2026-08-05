from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


DEFAULT_JDBC_URL = "jdbc:db2://b2db2g5.plexbs2.bb.com.br:61250/B2DB2G5"
DEFAULT_CREDENTIALS_FILE = "../gravar_dados_vpn/db2_credentials.json"


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
    network_column: str | None
    network_value: str | None


@dataclass(frozen=True)
class BacktestConfig:
    db2: Db2ConnectionConfig
    vpn_table: VpnTableConfig
    physical_table: PhysicalLoginTableConfig | None
    start: datetime
    end: datetime
    active_window_hours: int
    distinct_limit: int
    daily_login_limit: int
    sample_limit: int
    output_dir: Path


def load_dotenv_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def parse_jdbc_url(jdbc_url: str) -> tuple[str, int, str]:
    match = re.match(r"^jdbc:db2://([^:/]+):(\d+)/([^:;]+).*$", jdbc_url.strip())
    if not match:
        raise ValueError("JDBC URL invalida. Use o formato jdbc:db2://host:port/database")
    return match.group(1), int(match.group(2)), match.group(3)


def load_credentials(path: Path) -> tuple[str, str]:
    if not path.exists():
        raise FileNotFoundError(f"Arquivo de credenciais DB2 nao encontrado: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("Credenciais invalidas: o JSON deve conter username e password.")
    return username, password


def parse_datetime(value: str) -> datetime:
    normalized = value.strip()
    if len(normalized) == 10:
        normalized = f"{normalized} 00:00:00"
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(normalized, fmt)
        except ValueError:
            pass
    raise ValueError("Data invalida. Use YYYY-MM-DD ou YYYY-MM-DD HH:MM:SS.")


def normalize_identifier(value: str, label: str) -> str:
    normalized = value.strip().upper()
    if not re.match(r"^[A-Z][A-Z0-9_]*$", normalized):
        raise ValueError(f"Identificador invalido para {label}: {value!r}")
    return normalized


def resolve_path(path: str, base_dir: Path) -> Path:
    resolved = Path(path).expanduser()
    if not resolved.is_absolute():
        resolved = base_dir / resolved
    return resolved.resolve()
