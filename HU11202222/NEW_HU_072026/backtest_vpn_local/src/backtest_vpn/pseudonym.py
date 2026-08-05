"""Pseudonimizacao HMAC-SHA256 de chaves de usuario."""

import hashlib
import hmac
import os
from pathlib import Path


DEFAULT_KEY_FILENAME = ".pseudonym_key"


def ensure_gitignored(repo_dir, entry=DEFAULT_KEY_FILENAME):
    """Garante que a chave local e mapas reversos nao sejam versionados."""
    path = Path(repo_dir) / ".gitignore"
    existing = []
    if path.exists():
        existing = path.read_text(encoding="utf-8").splitlines()
    needed = [entry, "reverse_map_*.json", "extracts/", "adjudication/", "reports/"]
    additions = [item for item in needed if item not in existing]
    if additions:
        with open(path, "a", encoding="utf-8") as handle:
            if existing and existing[-1] != "":
                handle.write("\n")
            for item in additions:
                handle.write(item + "\n")


def load_or_create_key(path, repo_dir=None):
    """Carrega a chave hex local ou cria uma nova com chmod 600."""
    key_path = Path(path)
    if not key_path.exists():
        key_path.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")
        try:
            os.chmod(str(key_path), 0o600)
        except OSError:
            pass
    raw = key_path.read_text(encoding="utf-8").strip()
    if len(raw) < 32:
        raise ValueError("Chave de pseudonimizacao invalida")
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        key = raw.encode("utf-8")
    if repo_dir is not None:
        ensure_gitignored(repo_dir)
    return key


def key_id(key):
    """Identificador nao secreto da chave."""
    return hashlib.sha256(key).hexdigest()[:8]


class Pseudonymizer:
    """Pseudonimizador deterministico para uma chave local."""

    def __init__(self, key):
        self.key = key
        self.key_id = key_id(key)

    def pseudonymize(self, user_key):
        text = "" if user_key is None else str(user_key).strip().upper()
        digest = hmac.new(self.key, text.encode("utf-8"), hashlib.sha256).hexdigest()
        return "U-" + digest[:12]


class IdentityPseudonymizer:
    """Pseudonimizador nulo: devolve o proprio user_key sem transformacao.

    Usado quando o operador passa ``--no-pseudonymize`` para que matriculas e
    demais chaves apareçam explicitamente no bundle. Mantém a mesma interface
    (``pseudonymize`` + ``key_id``) para permanecer intercambiavel com o
    :class:`Pseudonymizer` real.
    """

    key_id = "none"

    def pseudonymize(self, user_key):
        return "" if user_key is None else str(user_key).strip().upper()


def pseudonymize(user_key, key):
    return Pseudonymizer(key).pseudonymize(user_key)
