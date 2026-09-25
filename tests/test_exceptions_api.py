"""
End-to-end HTTP acceptance tests for time-bounded exceptions.

Drives the full REST surface with the injectable lab clock:
publish baseline -> draft -> submit -> approve(scheduled) -> frozen-clock
advance across start/end -> effective chain flips and restores -> restart
catch-up emits one history row -> baseline supersede forces re-review ->
synthesized config cross-validates (fake FRR; live container auto-skip).
"""
from __future__ import annotations

import datetime as dt

import pytest

from app import clock, db as dbmod
from app import exceptions_service as xs

T0 = dt.datetime(2026, 9, 1, 0, 0, tzinfo=dt.timezone.utc)


@pytest.fixture(autouse=True)
def _freeze():
    fixed = clock.freeze(T0)
    yield fixed
    clock.reset_clock()


def _iso(t):
    return t.isoformat()


def _policy(client, name="e2e", family=4, default="deny"):
    r = client.post("/api/policies",
                    json={"name": name, "family": family,
                          "default_action": default})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _rules(client, pid, rules, default=None):
    r = client.put(f"/api/policies/{pid}/rules",
                   json={"rules": rules, "default_action": default})
    assert r.status_code == 200, r.text
    return r.json()


def _baseline(client, pid, label="v1"):
    r = client.post(f"/api/policies/{pid}/baseline/publish",
                    json={"label": label})
    assert r.status_code == 201, r.text
    return r.json()


def _exc(client, pid, **over):
    body = {
        "name": "window-A", "action": "permit",
        "start_at": _iso(T0 + dt.timedelta(hours=2)),
        "end_at": _iso(T0 + dt.timedelta(hours=4)),
        "matches": [{"prefix": "192.168.100.0/24"}],
        "reason": "maintenance", "priority": 100, "requested_by": "ops",
    }
    body.update(over)
    r = client.post(f"/api/policies/{pid}/exceptions", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_boundary_effect_and_auto_restore_via_clock(client):
    pid = _policy(client)
    _rules(client, pid, [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "permit", "le": 24},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "deny", "le": 32},
    ])
    _baseline(client, pid)
    e = _exc(client, pid)

    assert client.post(f"/api/exceptions/{e['id']}/submit",
                       json={"actor": "ops"}).json()["status"] == "pending"
    r = client.post(f"/api/exceptions/{e['id']}/approve",
                    json={"approver": "lead"})
    assert r.json()["status"] == "scheduled"

    probe = "192.168.100.0/24"

    def classify(at):
        return client.post(f"/api/policies/{pid}/effective/classify",
                           json={"prefix": probe, "at": _iso(at)}).json()

    assert classify(T0 + dt.timedelta(hours=1))["final_action"] == "deny"

    # advance the frozen clock across the start boundary: tick activates
    r = client.post("/api/clock/advance",
                    json={"seconds": 2 * 3600}).json()
    assert e["id"] in r["tick"]["activated"]
    hit = classify(T0 + dt.timedelta(hours=2))
    assert hit["final_action"] == "permit"
    assert hit["matched_layer"] == "exception"
    assert hit["active_exception_ids"] == [e["id"]]

    # advance across end: auto-expire, baseline restored
    r = client.post("/api/clock/advance",
                    json={"seconds": 2 * 3600}).json()
    assert e["id"] in r["tick"]["expired"]
    hit = classify(T0 + dt.timedelta(hours=4))
    assert hit["final_action"] == "deny" and hit["matched_layer"] == "baseline"

    hist = client.get(f"/api/exceptions/{e['id']}/history").json()
    assert [h["event_type"] for h in hist].count("ACTIVATED") == 1
    assert [h["event_type"] for h in hist].count("EXPIRED") == 1


def test_overlapping_exceptions_http_and_preview_witness(client):
    pid = _policy(client, name="overlap")
    _rules(client, pid, [
        {"seq": 10, "prefix": "192.168.0.0/16", "action": "deny", "le": 32}])
    _baseline(client, pid)
    broad = _exc(client, pid, name="broad", priority=200, action="permit",
                 start_at=_iso(T0), end_at=_iso(T0 + dt.timedelta(hours=2)),
                 matches=[{"prefix": "192.168.0.0/16", "le": 32}])
    narrow = _exc(client, pid, name="narrow", priority=100, action="deny",
                  start_at=_iso(T0), end_at=_iso(T0 + dt.timedelta(hours=2)),
                  matches=[{"prefix": "192.168.100.0/24"}])
    for e in (broad, narrow):
        client.post(f"/api/exceptions/{e['id']}/submit", json={"actor": "x"})
        client.post(f"/api/exceptions/{e['id']}/approve",
                    json={"approver": "lead"})

    eff = client.get(f"/api/policies/{pid}/effective",
                     params={"at": _iso(T0 + dt.timedelta(minutes=10))}).json()
    # deterministic priority order in the synthesis
    assert [x["id"] for x in eff["active_exceptions"]] == [narrow["id"],
                                                           broad["id"]]
    assert eff["witnesses"][0]["prefix"] == "192.168.0.0/16"

    chain = client.post(f"/api/policies/{pid}/effective/classify",
                        json={"prefix": "192.168.100.0/24",
                              "at": _iso(T0 + dt.timedelta(minutes=10))}).json()
    assert chain["final_action"] == "deny"
    assert chain["matched_owner"]["exception_id"] == narrow["id"]

    # preview before approval shows semantic impact, not a text diff
    pv = client.get(f"/api/exceptions/{narrow['id']}/preview").json()
    assert pv["witness_count"] == 0     # narrow deny == baseline deny there


def test_restart_catchup_single_history_record(client):
    pid = _policy(client, name="restart")
    _rules(client, pid, [
        {"seq": 10, "prefix": "192.168.0.0/16", "action": "deny", "le": 32}])
    _baseline(client, pid)
    e = _exc(client, pid,
             start_at=_iso(T0 + dt.timedelta(hours=1)),
             end_at=_iso(T0 + dt.timedelta(hours=2)))
    client.post(f"/api/exceptions/{e['id']}/submit", json={"actor": "x"})
    client.post(f"/api/exceptions/{e['id']}/approve", json={"approver": "l"})

    # jump past the window; the advance itself performs the catch-up, just
    # like the startup tick after a restart
    adv = client.post("/api/clock/advance",
                      json={"at": _iso(T0 + dt.timedelta(hours=3))}).json()
    assert e["id"] in adv["tick"]["expired"]
    out2 = client.post("/api/exceptions/tick",
                       json={"at": _iso(T0 + dt.timedelta(hours=4))}).json()
    assert out2["expired"] == [] and out2["activated"] == []

    # fresh sessions (as after a process restart) still see exactly one row
    s = dbmod.SessionLocal()
    n = s.query(dbmod.ExceptionEvent).filter_by(
        exception_id=e["id"], event_type=xs.E_EXPIRED).count()
    s.close()
    assert n == 1


def test_baseline_supersede_forces_review_flow(client):
    pid = _policy(client, name="reviewflow")
    _rules(client, pid, [
        {"seq": 10, "prefix": "192.168.0.0/16", "action": "deny", "le": 32}])
    v1 = _baseline(client, pid, "v1")
    e = _exc(client, pid,
             start_at=_iso(T0 + dt.timedelta(hours=10)),
             end_at=_iso(T0 + dt.timedelta(hours=12)))
    client.post(f"/api/exceptions/{e['id']}/submit", json={"actor": "x"})
    client.post(f"/api/exceptions/{e['id']}/approve", json={"approver": "l"})

    # baseline replaced: future exception becomes needs_review
    _rules(client, pid, [
        {"seq": 5, "prefix": "192.168.0.0/16", "action": "permit", "le": 32},
        {"seq": 90, "prefix": "0.0.0.0/0", "action": "deny"}])
    v2 = _baseline(client, pid, "v2")
    got = client.get(f"/api/exceptions/{e['id']}").json()
    assert got["needs_review"] is True
    assert got["snapshot_id"] == v1["id"]
    assert got["baseline_is_current"] is False

    # even with the window open, a blocked exception must not synthesize in
    client.post("/api/clock/advance",
                json={"at": _iso(T0 + dt.timedelta(hours=10, minutes=30))})
    eff = client.get(f"/api/policies/{pid}/effective").json()
    assert [x["id"] for x in eff["active_exceptions"]] == []

    # re-preview against new baseline, then confirm -> activates
    pv = client.get(f"/api/exceptions/{e['id']}/preview",
                    params={"baseline_snapshot_id": v2["id"]}).json()
    assert pv["baseline_is_current"] is True
    r = client.post(f"/api/exceptions/{e['id']}/review",
                    json={"reviewer": "sre"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["needs_review"] is False
    assert body["reviewed_snapshot_id"] == v2["id"]
    assert body["status"] == "active"

    # old snapshot payload untouched: probe replay on v1 still denies
    rep = client.post(f"/api/snapshots/{v1['id']}/replay",
                      json={"probes": ["192.168.100.0/24"]}).json()
    assert rep["results"][0]["final_action"] == "deny"


def test_revoke_and_validation_http(client):
    pid = _policy(client, name="rev")
    _rules(client, pid, [
        {"seq": 1, "prefix": "10.0.0.0/8", "action": "deny"}])
    _baseline(client, pid)

    # bad windows / family mix rejected
    r = client.post(f"/api/policies/{pid}/exceptions", json={
        "name": "bad", "action": "permit",
        "start_at": _iso(T0 + dt.timedelta(hours=2)),
        "end_at": _iso(T0 + dt.timedelta(hours=1)),
        "matches": [{"prefix": "10.1.0.0/16"}]})
    assert r.status_code == 422
    r = client.post(f"/api/policies/{pid}/exceptions", json={
        "name": "badfam", "action": "permit",
        "start_at": _iso(T0), "end_at": _iso(T0 + dt.timedelta(hours=1)),
        "matches": [{"prefix": "2001:db8::/32"}]})
    assert r.status_code == 422

    e = _exc(client, pid)
    r = client.post(f"/api/exceptions/{e['id']}/revoke",
                    json={"actor": "sec", "reason": "nope"})
    assert r.json()["status"] == "revoked"
    # repeat revoke is idempotent
    assert client.post(f"/api/exceptions/{e['id']}/revoke",
                       json={}).json()["status"] == "revoked"
    hist = client.get(f"/api/exceptions/{e['id']}/history").json()
    assert [h["event_type"] for h in hist].count("REVOKED") == 1


def test_timeline_endpoint_shape(client):
    pid = _policy(client, name="tl")
    _rules(client, pid, [
        {"seq": 1, "prefix": "192.168.0.0/16", "action": "deny", "le": 32}])
    _baseline(client, pid)
    e = _exc(client, pid)
    tl = client.get(f"/api/policies/{pid}/timeline").json()
    assert tl["current_baseline_snapshot_id"]
    assert len(tl["exceptions"]) == 1
    boundary_ats = {b["at"] for b in tl["boundaries"]}
    assert _iso(T0 + dt.timedelta(hours=2)) in boundary_ats
    assert {"CREATED"} <= {ev["event_type"] for ev in tl["events"]}


def test_effective_cross_validate_with_fake_bridge(client, monkeypatch):
    """The synthesized config must validate through validate.cross_validate."""
    from app.routers import exceptions_api as xa
    from tests.test_frr_consistency import FakeFRRBridge
    from app import validate

    pid = _policy(client, name="xv")
    _rules(client, pid, [
        {"seq": 10, "prefix": "192.168.0.0/16", "action": "deny", "le": 32},
        {"seq": 20, "prefix": "10.0.0.0/8", "action": "permit", "le": 24}])
    _baseline(client, pid)
    e = _exc(client, pid, start_at=_iso(T0 - dt.timedelta(minutes=1)),
             end_at=_iso(T0 + dt.timedelta(hours=2)))
    client.post(f"/api/exceptions/{e['id']}/submit", json={"actor": "x"})
    client.post(f"/api/exceptions/{e['id']}/approve", json={"approver": "l"})

    # intercept bridge construction used by validate.cross_validate
    composed_holder = {}
    real_cv = validate.cross_validate

    def fake_cv(policy, probes, node="a", **kw):
        composed_holder["p"] = policy
        return real_cv(policy, probes, node=node,
                       bridge=FakeFRRBridge(policy), install=True)
    monkeypatch.setattr(xa, "cross_validate", fake_cv)

    r = client.post(f"/api/policies/{pid}/effective/cross-validate",
                    json={"probes": ["192.168.100.0/24", "10.0.1.0/24",
                                     "8.8.8.8/32"], "node": "a"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "match"
    assert body["active_exception_ids"] == [e["id"]]
    # overlay entry carries an FRR-safe dense seq
    seqs = [r0.seq for r0 in composed_holder["p"].rules]
    assert seqs == list(range(1, len(seqs) + 1))
