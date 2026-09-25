"""Pytest configuration: backend on sys.path, temp DB."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

_tmpdir = tempfile.mkdtemp(prefix="rlab-test-")
os.environ["RLAB_DATA"] = _tmpdir
os.environ["DATABASE_URL"] = f"sqlite:///{Path(_tmpdir) / 'test.db'}"
# tests drive the clock and activation/expiry ticks explicitly
os.environ.setdefault("RLAB_DISABLE_SCHEDULER", "1")
# env must be set before any app.* import reads config.py


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    from app import db as dbmod
    dbmod.init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def db():
    from app import db as dbmod
    dbmod.init_db()
    s = dbmod.SessionLocal()
    # clean slate for ordering-sensitive tests
    for tbl in (dbmod.ExceptionEvent, dbmod.PolicyException, dbmod.Run,
                dbmod.Scenario, dbmod.Snapshot, dbmod.Rule, dbmod.Policy,
                dbmod.Neighbor):
        s.query(tbl).delete()
    s.commit()
    # reset ROWID sequences so policy ids are stable per test
    import sqlalchemy as _sa
    if s.bind.dialect.name == "sqlite":
        has_seq = s.execute(_sa.text(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='sqlite_sequence'")).first()
        if has_seq:
            for t in ("exception_events", "policy_exceptions", "runs",
                      "scenarios", "snapshots", "rules", "policies",
                      "neighbors"):
                s.execute(_sa.text(
                    "DELETE FROM sqlite_sequence WHERE name=:n"), {"n": t})
            s.commit()
    yield s
    s.close()
