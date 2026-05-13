"""Pytest configuration: set env before `app.db` is imported by test modules."""

import os

# Isolate DB during automated tests (full suite imports `app` in arbitrary order).
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
