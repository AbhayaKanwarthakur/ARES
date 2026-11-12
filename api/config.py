"""Environment-backed configuration for the passive scoring API."""
import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.engine import URL


@dataclass(frozen=True)
class ApiSettings:
    database_url: str
    api_keys_file: str
    docs_enabled: bool = False

    @staticmethod
    def database_url_from_env():
        database_url = os.environ.get("DATABASE_URL", "").strip()
        if not database_url:
            password_file = os.environ.get("DATABASE_PASSWORD_FILE", "").strip()
            if not password_file:
                raise ValueError("Set DATABASE_URL or DATABASE_PASSWORD_FILE.")
            try:
                password = Path(password_file).read_text(encoding="utf-8").strip()
            except OSError as error:
                raise ValueError("Unable to read the PostgreSQL password secret.") from error
            if not password:
                raise ValueError("The PostgreSQL password secret is empty.")
            database_url = URL.create(
                "postgresql+psycopg",
                username=os.environ.get("DATABASE_USER", "ares"),
                password=password,
                host=os.environ.get("DATABASE_HOST", "postgres"),
                port=int(os.environ.get("DATABASE_PORT", "5432")),
                database=os.environ.get("DATABASE_NAME", "ares"),
            ).render_as_string(hide_password=False)
        if not database_url.startswith("postgresql+psycopg://"):
            raise ValueError("DATABASE_URL must use the postgresql+psycopg:// driver.")
        return database_url

    @classmethod
    def from_env(cls):
        database_url = cls.database_url_from_env()
        api_keys_file = os.environ.get("ARES_API_KEYS_FILE", "").strip()
        if not api_keys_file:
            raise ValueError("ARES_API_KEYS_FILE must point to a provisioned API-key file.")
        docs_enabled = os.environ.get("ARES_ENABLE_API_DOCS", "false").lower()
        if docs_enabled not in {"true", "false"}:
            raise ValueError("ARES_ENABLE_API_DOCS must be 'true' or 'false'.")
        return cls(database_url, api_keys_file, docs_enabled=docs_enabled == "true")
