"""
Additional boundary tests for time-bounded exceptions (acceptance detail):
* effective view / cross-validate entry points behave on no-baseline policy;
* ge/le match scope windows behave exactly like baseline rules;
* exception only overrides INSIDE its scope: prefixes in scope flip, prefixes
  outside the scope are untouched even if inside the exception base prefix.
"""
from __future__ import annotations

import datetime as dt

import pytest

from app import clock, db as dbmod
from app import exceptions_service as xs

T0 = dt.datetime(2026, 6, 1, 12, 0, tzinfo=dt.timezone.utc)


@pytest.fixture
def fx(db):
    clock.freeze(T0)
    pol = dbmod.Policy(name="bounds", family=4, default_action="deny")
    db.add(pol)
    db.commit()
    db.refresh(pol)
    from app import service
    service.replace_rules(db, pol, [
        {"seq": 10, "prefix": "192.168.0.0/16", "action": "deny", "le": 32},
        {"seq": 20, "prefix": "10.0.0.0/8", "action": "permit", "le": 24},
    ])
    snap = xs.publish_baseline(db, pol.id, label="b")
    yield db, pol, snap
    clock.reset_clock()


def _approve(db, ex, at=None):
    xs.submit(db, ex.id)
    return xs.approve(db, ex.id, approver="a",
                      at=at if at is not None else T0)


def test_effective_view_no_baseline_is_4xx(db):
    p = dbmod.Policy(name="nobase", family=4, default_action="deny")
    db.add(p)
    db.commit()
    with pytest.raises(xs.ExceptionError):
        xs.effective_view(db, p.id)


def test_ge_le_scope_and_out_of_scope_prefixes_untouched(fx):
    db, pol, _ = fx
    ex = xs.create_exception(
        db, pol.id, name="lenwin", action="permit", priority=100,
        start_at=T0 - dt.timedelta(minutes=1),
        end_at=T0 + dt.timedelta(hours=1),
        matches=[{"prefix": "192.168.0.0/16", "ge": 24, "le": 26}])
    _approve(db, ex)

    def act(pfx):
        return xs.enriched_classify(db, pol.id, pfx, at=T0)["final_action"]

    assert act("192.168.100.0/24") == "permit"     # in length window
    assert act("192.168.100.0/26") == "permit"     # in window
    assert act("192.168.100.0/27") == "deny"       # longer than le: baseline
    assert act("192.168.0.0/16") == "deny"         # shorter than ge: baseline
    assert act("10.0.1.0/24") == "permit"          # unrelated baseline rule
    assert act("8.8.8.8/32") == "deny"             # default


def test_exception_scope_exact_prefix_does_not_leak(fx):
    db, pol, _ = fx
    ex = xs.create_exception(
        db, pol.id, name="exact", action="permit", priority=100,
        start_at=T0 - dt.timedelta(minutes=1),
        end_at=T0 + dt.timedelta(hours=1),
        matches=[{"prefix": "192.168.100.0/24"}])  # exact /24 only
    _approve(db, ex)
    assert xs.enriched_classify(db, pol.id, "192.168.100.0/24",
                                at=T0)["final_action"] == "permit"
    assert xs.enriched_classify(db, pol.id, "192.168.100.128/25",
                                at=T0)["final_action"] == "deny"
    assert xs.enriched_classify(db, pol.id, "192.168.100.0/25",
                                at=T0)["final_action"] == "deny"


def test_deny_exception_can_strip_a_baseline_permit(fx):
    db, pol, _ = fx
    ex = xs.create_exception(
        db, pol.id, name="harddeny", action="deny", priority=100,
        start_at=T0 - dt.timedelta(minutes=1),
        end_at=T0 + dt.timedelta(hours=1),
        matches=[{"prefix": "10.0.9.0/24"}])
    _approve(db, ex)
    hit = xs.enriched_classify(db, pol.id, "10.0.9.0/24", at=T0)
    assert hit["final_action"] == "deny"
    assert hit["matched_owner"]["exception_id"] == ex.id
    # neighboring baseline permits survive
    assert xs.enriched_classify(db, pol.id, "10.0.8.0/24",
                                at=T0)["final_action"] == "permit"
    # semantic impact: exactly a permit->deny witness for the stripped prefix
    view = xs.effective_view(db, pol.id, at=T0)
    hit_w = [w for w in view["witnesses"]
             if w["prefix"] == "10.0.9.0/24" and w["change"] == "permit->deny"]
    assert len(hit_w) == 1


def test_timeline_active_set_tracks_three_windows(fx):
    db, pol, _ = fx
    a = xs.create_exception(db, pol.id, name="a", action="permit", priority=100,
        start_at=T0, end_at=T0 + dt.timedelta(hours=2),
        matches=[{"prefix": "192.168.1.0/24"}])
    b = xs.create_exception(db, pol.id, name="b", action="permit", priority=50,
        start_at=T0 + dt.timedelta(hours=1),
        end_at=T0 + dt.timedelta(hours=3),
        matches=[{"prefix": "192.168.2.0/24"}])
    for e in (a, b):
        _approve(db, e)
    tl = xs.timeline(db, pol.id, at=T0 + dt.timedelta(hours=4))
    sets = {bnd["at"]: bnd["active_exception_ids"] for bnd in tl["boundaries"]}
    at0 = _iso(T0)
    at1 = _iso(T0 + dt.timedelta(hours=1))
    at2 = _iso(T0 + dt.timedelta(hours=2))
    at3 = _iso(T0 + dt.timedelta(hours=3))
    assert sets.get(at0) == [a.id]
    assert sets.get(at1) == [a.id, b.id]       # priority order: b(p50) first
    assert sets.get(at2) == [b.id]
    assert sets.get(at3) == []


def _iso(t):
    return t.isoformat()


def test_active_exception_chain_labels_owner(fx):
    db, pol, _ = fx
    ex = xs.create_exception(db, pol.id, name="lab", action="permit", priority=10,
        start_at=T0 - dt.timedelta(minutes=1),
        end_at=T0 + dt.timedelta(hours=1),
        matches=[{"prefix": "192.168.100.0/24"}])
    _approve(db, ex)
    hit = xs.enriched_classify(db, pol.id, "192.168.100.0/24", at=T0)
    layers = [(c["seq"], c["layer"], c["matched"]) for c in hit["chain"]]
    matched = [c for c in hit["chain"] if c["matched"]]
    assert len(matched) == 1
    assert matched[0]["layer"] == "exception"
    assert matched[0]["owner"]["exception_id"] == ex.id
    # first match terminates here: only the winning exception entry plus the
    # implicit default are walked; chain rows are labeled by owner
    assert any(layer == "exception" for _, layer, _ in layers)
    assert all(layer in ("exception", "default") for _, layer, _ in layers)

    # a prefix the overlay does not cover walks the baseline and labels it
    hit2 = xs.enriched_classify(db, pol.id, "192.168.50.0/24", at=T0)
    assert hit2["matched_layer"] == "baseline"
    assert any(c["layer"] == "baseline" for c in hit2["chain"])
