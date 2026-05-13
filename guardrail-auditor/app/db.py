"""SQLAlchemy engine and session factory."""

import os
from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Default SQLite for local dev; override with DATABASE_URL (e.g. Postgres free tier)
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./guardrail.db")

_sqlite_common = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
if DATABASE_URL.startswith("sqlite") and ":memory:" in DATABASE_URL:
    engine = create_engine(
        DATABASE_URL,
        connect_args=_sqlite_common,
        poolclass=StaticPool,
    )
else:
    engine = create_engine(
        DATABASE_URL,
        connect_args=_sqlite_common,
    )
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
