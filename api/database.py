"""PostgreSQL engine and request-scoped sessions."""
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import ApiSettings


@lru_cache(maxsize=1)
def get_engine():
    settings = ApiSettings.from_env()
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        pool_timeout=5,
        pool_recycle=1800,
    )


def get_session_factory():
    return sessionmaker(bind=get_engine(), expire_on_commit=False, class_=Session)


def get_session():
    with get_session_factory()() as session:
        yield session
