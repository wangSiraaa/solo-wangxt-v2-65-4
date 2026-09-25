"""
Live FRR cross-validation for the SYNTHESIZED config (immutable baseline +
active time-bounded exceptions), installed under a throwaway prefix-list name
into the isolated local lab container and removed afterwards.

Auto-skips when neither docker nor the rpolicy-router-a container is present
— same guard as test_frr_consistency.py. Nothing here ever touches production:
transport is docker-exec to the internal labnet bridge only.
"""
from __future__ import annotations

import datetime as dt

import pytest

from app import clock, db as dbmod
from app import exceptions_service as xs
from app.frr_bridge import FRRBridge, FRRUnavailable
from app.validate import cross_validate
from tests.test_frr_consistency import _docker_available  # noqa: F401


T0 = dt.datetime(2026, 6, 1, 12, 0, tzinfo=dt.timezone.utc)


@pytest.fixture
def fx(db):
    clock.freeze(T0)
    pol = dbmod.Policy(name="xc-live", family=4, default_action="deny")
    db.add(pol)
    db.commit()
    db.refresh(pol)
    from app import service
    service.replace_rules(db, pol, [
        {"seq": 10, "prefix": "192.168.0.0/16", "action": "deny", "le": 32},
        {"seq": 20, "prefix": "10.0.0.0/8", "action": "permit", "le": 24},
    ])
    xs.publish_baseline(db, pol.id, label="base")
    # active emergency permit exception
    ex = xs.create_exception(
        db, pol.id, name="emergency", action="permit",
        start_at=T0 - dt.timedelta(minutes=5),
        end_at=T0 + dt.timedelta(hours=1),
        matches=[{"prefix": "192.168.100.0/24"},
                 {"prefix": "192.168.200.0/23", "le": 24}],
        reason="live lab check", priority=100)
    xs.submit(db, ex.id)
    xs.approve(db, ex.id, approver="lab", at=T0 - dt.timedelta(minutes=10))
    yield db, pol, ex
    clock.reset_clock()


PROBES = [
    "192.168.100.0/24",   # exception permit (baseline would deny)
    "192.168.100.128/25", # outside exact exception scope -> baseline deny
    "192.168.200.0/24",   # exception ge/le scope permit
    "192.168.200.0/23",   # /23 not covered (le 24) -> baseline deny
    "192.168.50.0/24",    # baseline deny
    "10.0.1.0/24",        # baseline permit
    "8.8.8.8/32",         # default deny
]


def _live_bridge(node="a"):
    br = FRRBridge(node=node, timeout=15)
    try:
        return br.connect()
    except FRRUnavailable:
        pytest.skip("local FRR lab container not running")


@pytest.mark.skipif(not _docker_available(),
                    reason="docker CLI unavailable; isolated FRR lab not up")
def test_live_composed_config_matches_frr(fx):
    db, pol, ex = fx
    composed, seq_map, excs, snap = xs.composed_policy_at(
        db, pol.id, at=T0, name="xc-live-check")
    assert [e.id for e in excs] == [ex.id]
    br = _live_bridge()
    try:
        out = cross_validate(composed, PROBES, node="a", bridge=br,
                             install=True, remove_after=True)
    finally:
        br.close()
    assert out["status"] == "match", out["mismatches"]

    # cleanup verification: the throwaway list is gone from FRR
    br2 = _live_bridge()
    try:
        shown = br2.show_prefix_list(composed.name, 4)
    except FRRUnavailable:
        shown = ""
    finally:
        br2.close()
    assert "xc-live-check" not in shown or "entries: 0" in shown \
        or "can't find" in shown.lower()
