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
# env must be set before any app.* import reads config.py
# tests drive boundaries deterministically via POST /api/exceptions/sweep/run
os.environ.setdefault("RLAB_SWEEP_DISABLED", "1")


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
    from app.clock import clock
    dbmod.init_db()
    s = dbmod.SessionLocal()
    # clean slate for ordering-sensitive tests (children first)
    for tbl in (dbmod.ExceptionEvent, dbmod.PolicyException,
                dbmod.Run, dbmod.Scenario, dbmod.Snapshot,
                dbmod.Rule, dbmod.Policy, dbmod.Neighbor):
        s.query(tbl).delete()
    s.commit()
    clock.reset()
    yield s
    s.close()
    clock.reset()
