"""
Acceptance tests for time-bounded policy exceptions.

Covers:
1. approved exception effective at exact boundary instants + auto-restore;
2. two overlapping exceptions -> deterministic result + minimal witness;
3. repeated / out-of-order activate/expire leave the terminal state untouched;
4. baseline supersede -> pending exceptions need re-review, old snapshot kept;
5. process-restart catch-up of expiry records history exactly once;
   pre-existing snapshot diffs / ordered probe replays keep working;
plus revoke idempotency, preview+reconfirm, and FRR(Fake)-consistency of the
composed config.
"""
import datetime as dt

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app import db as dbmod, exception_service as es, service
from app.clock import clock
from app.engine import Action, policy_from_dicts
from app.exceptions import (
    ExceptionSpec, compose_policy, effective_classify, overlap_witnesses,
)
from app.validate import cross_validate

from test_frr_consistency import FakeFRRBridge

T = lambda h, m=0: dt.datetime(2026, 9, 25, h, m, 0, tzinfo=dt.timezone.utc)
ISO = lambda d: d.isoformat()


# ------------------------------------------------------------------ helpers
def _policy_with_baseline(client, name=None, rules=None, default="deny",
                          family=4, label="baseline"):
    import uuid
    name = name or f"maint-{uuid.uuid4().hex[:8]}"
    r = client.post("/api/policies", json={
        "name": name, "family": family, "default_action": default})
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    rules = rules if rules is not None else [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 24},
    ]
    rr = client.put(f"/api/policies/{pid}/rules", json={"rules": rules})
    assert rr.status_code == 200, rr.text
    s = client.post(f"/api/policies/{pid}/snapshots", json={"label": label})
    assert s.status_code == 201, s.text
    return pid, s.json()["id"]


def _approved_exception(client, pid, snap_id, *, name="win", prefix, action,
                        start=T(12), end=T(14), priority=100, ge=None, le=None,
                        reason="maintenance window"):
    r = client.post(f"/api/policies/{pid}/exceptions", json={
        "name": name, "prefix": prefix, "action": action, "ge": ge, "le": le,
        "priority": priority, "starts_at": ISO(start), "ends_at": ISO(end),
        "reason": reason, "baseline_snapshot_id": snap_id})
    assert r.status_code == 201, r.text
    eid = r.json()["id"]
    assert r.json()["status"] == "draft"
    assert client.post(f"/api/exceptions/{eid}/submit").status_code == 200
    ar = client.post(f"/api/exceptions/{eid}/approve",
                     json={"approver": "ops-lead"})
    assert ar.status_code == 200, ar.text
    assert ar.json()["status"] == "planned"
    return eid


def _sweep(client, at):
    r = client.post("/api/exceptions/sweep/run", json={"at": ISO(at)})
    assert r.status_code == 200, r.text
    return r.json()


def _classify(client, pid, prefix, at):
    r = client.post(f"/api/policies/{pid}/effective/classify", json={
        "prefix": prefix, "at": ISO(at)})
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------- 1. boundary + auto restore
def test_exception_effective_at_boundaries_and_restores(client):
    pid, sid = _policy_with_baseline(client)
    # 192.168.100.0/24 is permitted by baseline seq20; exception DENIES it
    eid = _approved_exception(
        client, pid, sid, prefix="192.168.100.0/24", action="deny")

    # one second before the window: unchanged baseline
    assert _sweep(client, T(11, 59) .replace(second=59))["activated"] == []
    d = _classify(client, pid, "192.168.100.0/24", T(11, 59).replace(second=59))
    assert d["final_action"] == "permit" and d["terminal"] == "rule"
    assert d["winning_exception"] is None

    # exact start boundary (half-open): active
    r = _sweep(client, T(12))
    assert r["activated"] == [eid] and r["expired"] == []
    d = _classify(client, pid, "192.168.100.0/24", T(12))
    assert d["final_action"] == "deny" and d["terminal"] == "exception"
    assert d["winning_exception"]["id"] == eid
    assert d["overridden"] is True and d["baseline_action"] == "permit"
    # unrelated prefix still decided by baseline (no /32 rule -> default deny)
    d2 = _classify(client, pid, "10.1.2.3/32", T(12))
    assert d2["final_action"] == "deny" and d2["terminal"] == "default"

    # exact end boundary: restored to baseline automatically
    r = _sweep(client, T(14))
    assert r["expired"] == [eid]
    d = _classify(client, pid, "192.168.100.0/24", T(14))
    assert d["final_action"] == "permit" and d["terminal"] == "rule"

    status = client.get(f"/api/exceptions/{eid}").json()
    assert status["status"] == "expired"
    types = [e["event_type"] for e in status["events"]]
    assert types == ["created", "submit", "approve", "activate", "expire"]
    # activation/expiry recorded exactly at their boundary instants
    by_type = {e["event_type"]: e["at_time"] for e in status["events"]}
    assert by_type["activate"] == ISO(T(12))
    assert by_type["expire"] == ISO(T(14))


def test_status_history_is_db_persisted(client, db):
    pid, sid = _policy_with_baseline(client)
    eid = _approved_exception(
        client, pid, sid, prefix="192.168.100.0/24", action="deny")
    _sweep(client, T(12))
    rows = list(db.scalars(
        select(dbmod.ExceptionEvent).where(
            dbmod.ExceptionEvent.exception_id == eid)))
    assert [r.event_type for r in rows] == \
        ["created", "submit", "approve", "activate"]
    # append-only: from/to status recorded
    act = [r for r in rows if r.event_type == "activate"][0]
    assert act.from_status == "planned" and act.to_status == "active"


# ------------------------------------------- 2. overlapping exceptions winner
def test_overlapping_exceptions_deterministic_with_witness(client):
    pid, sid = _policy_with_baseline(client)
    # narrow deny (lower priority) vs broad permit over all /24s (higher)
    e_narrow = _approved_exception(
        client, pid, sid, name="narrow-deny",
        prefix="192.168.100.0/24", action="deny", priority=100)
    e_broad = _approved_exception(
        client, pid, sid, name="broad-permit",
        prefix="192.168.0.0/16", action="permit", ge=24, le=24, priority=200)

    pv = client.get(f"/api/exceptions/{e_narrow}/preview").json()
    overlaps = [o for o in pv["overlaps"]
                if {o["winner_id"], o["loser_id"]} == {e_broad, e_narrow}]
    assert len(overlaps) == 1
    o = overlaps[0]
    # minimal witness prefix sits inside BOTH scopes
    assert o["prefix"] == "192.168.100.0/24"
    assert o["conflicting"] is True
    assert o["winner_id"] == e_broad and o["winner_action"] == "permit"

    _sweep(client, T(12))
    d = _classify(client, pid, o["prefix"], T(12))
    assert d["final_action"] == "permit"
    assert d["winning_exception"]["id"] == e_broad
    # the losing exception still shows in the chain with its decision
    chain = {c["exception_id"]: c for c in d["exception_chain"]}
    assert chain[e_narrow]["matched"] is True and chain[e_narrow]["rank"] == 1
    assert chain[e_broad]["rank"] == 0


def test_overlap_resolution_flips_with_priority(client):
    pid, sid = _policy_with_baseline(client)
    a = _approved_exception(client, pid, sid, name="a-deny",
                            prefix="192.168.0.0/16", action="deny",
                            ge=24, le=24, priority=100)
    b = _approved_exception(client, pid, sid, name="b-permit",
                            prefix="192.168.100.0/24", action="permit",
                            priority=200)
    _sweep(client, T(12))
    d = _classify(client, pid, "192.168.100.0/24", T(12))
    assert d["winning_exception"]["id"] == b      # higher priority wins
    assert d["final_action"] == "permit"


def test_same_priority_resolved_by_more_specific_scope():
    # deterministic total ordering even with equal explicit priority
    broad = ExceptionSpec(id=1, name="b", prefix="192.168.0.0/16",
                          action=Action.PERMIT, ge=24, le=24, priority=100)
    narrow = ExceptionSpec(id=2, name="n", prefix="192.168.100.0/24",
                           action=Action.DENY, priority=100)
    base = policy_from_dicts("p", [
        {"seq": 10, "prefix": "0.0.0.0/0", "action": "permit"}],
        default_action="deny")
    c = compose_policy(base, [broad, narrow])
    h = effective_classify(c, "192.168.100.0/24")
    assert h.winning_exception.id == 2 and h.final_action == Action.DENY
    # witness exists and both scopes match it
    ow = overlap_witnesses([broad, narrow])
    assert ow[0].winner_id == 2 and ow[0].prefix == "192.168.100.0/24"


# ----------------------------------------- 3. idempotent / out-of-order events
def test_repeated_and_out_of_order_events_keep_terminal_state(client):
    pid, sid = _policy_with_baseline(client)
    eid = _approved_exception(
        client, pid, sid, prefix="192.168.100.0/24", action="deny")

    # activate before start -> 409
    r = client.post(f"/api/exceptions/{eid}/activate", json={"at": ISO(T(11))})
    assert r.status_code == 409
    # planned -> expire (not active, window unmet) -> 409
    r = client.post(f"/api/exceptions/{eid}/expire", json={"at": ISO(T(11, 30))})
    assert r.status_code == 409

    _sweep(client, T(12))
    # duplicate activations: no state change, no extra history
    for _ in range(3):
        r = client.post(f"/api/exceptions/{eid}/activate", json={"at": ISO(T(12))})
        assert r.status_code == 200 and r.json() == {"changed": False,
                                                      "status": "active"}
    # out-of-order late activation AFTER expiry must not resurrect
    _sweep(client, T(14))
    late = client.post(f"/api/exceptions/{eid}/activate", json={"at": ISO(T(15))})
    assert late.status_code == 200
    assert late.json()["changed"] is False and late.json().get("stale") is True
    # repeated expiry is a no-op
    for _ in range(2):
        r = client.post(f"/api/exceptions/{eid}/expire", json={"at": ISO(T(14))})
        assert r.json() == {"changed": False, "status": "expired"}

    status = client.get(f"/api/exceptions/{eid}").json()
    assert status["status"] == "expired"
    types = [e["event_type"] for e in status["events"]]
    assert types.count("activate") == 1 and types.count("expire") == 1


def test_clock_jump_past_window_never_activates(client):
    pid, sid = _policy_with_baseline(client)
    eid = _approved_exception(
        client, pid, sid, prefix="192.168.100.0/24", action="deny")
    # jump straight past the whole window
    r = _sweep(client, T(16))
    assert r["activated"] == [] and r["skipped"] == [eid]
    d = _classify(client, pid, "192.168.100.0/24", T(16))
    assert d["terminal"] == "rule"          # never transiently active
    status = client.get(f"/api/exceptions/{eid}").json()
    assert status["status"] == "expired"
    types = [e["event_type"] for e in status["events"]]
    assert "activate" not in types


def test_revoke_is_idempotent_and_restores_baseline(client):
    pid, sid = _policy_with_baseline(client)
    eid = _approved_exception(
        client, pid, sid, prefix="192.168.100.0/24", action="deny")
    _sweep(client, T(12))
    assert _classify(client, pid, "192.168.100.0/24", T(12))["final_action"] == "deny"
    r1 = client.post(f"/api/exceptions/{eid}/revoke",
                     json={"note": "rollback", "at": ISO(T(12, 30))})
    assert r1.status_code == 200 and r1.json()["changed"] is True
    r2 = client.post(f"/api/exceptions/{eid}/revoke", json={"note": "again"})
    assert r2.json()["changed"] is False and r2.json()["status"] == "revoked"
    # revoked exception is gone from the effective policy; expiry can't revive
    assert _classify(client, pid, "192.168.100.0/24", T(13))["terminal"] == "rule"
    client.post(f"/api/exceptions/{eid}/expire", json={"at": ISO(T(14))})
    assert client.get(f"/api/exceptions/{eid}").json()["status"] == "revoked"


# ------------------------------------ 4. baseline supersede + re-review flow
def test_baseline_supersede_requires_reconfirm_and_keeps_old(client):
    pid, v1 = _policy_with_baseline(
        client, rules=[
            {"seq": 10, "prefix": "192.168.0.0/16", "action": "permit", "le": 32},
        ], label="v1")
    eid = _approved_exception(
        client, pid, v1, prefix="192.168.100.0/24", action="deny")

    # operator replaces the baseline -> new immutable snapshot v2
    r = client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "192.168.0.0/16", "action": "deny", "le": 32},
    ]})
    assert r.status_code == 200
    v2 = client.post(f"/api/policies/{pid}/snapshots",
                     json={"label": "v2-tightened"}).json()["id"]

    exc = client.get(f"/api/exceptions/{eid}").json()
    assert exc["needs_review"] is True
    assert "superseded" in exc["review_reason"]
    assert exc["baseline_snapshot_id"] == v1           # binding unchanged
    types = [e["event_type"] for e in exc["events"]]
    assert "review_required" in types

    # it must NOT activate at its window while unreviewed
    assert _sweep(client, T(12))["activated"] == []
    assert client.get(f"/api/exceptions/{eid}").json()["status"] == "planned"

    # the OLD snapshot is immutable: its rules still permit
    old = client.get(f"/api/snapshots/{v1}").json()
    assert old["payload"]["rules"][0]["action"] == "permit"

    # re-preview against v2: in v2 the prefix is already denied, so the
    # exception changes nothing there (witness set reflects the new baseline)
    pv = client.get(f"/api/exceptions/{eid}/preview",
                    params={"snapshot_id": v2}).json()
    assert pv["baseline_snapshot_id"] == v2 and pv["needs_review"] is True
    sig, n = pv["signature"], len(pv["witnesses"])

    # a stale/wrong signature is rejected
    bad = client.post(f"/api/exceptions/{eid}/reconfirm", json={
        "snapshot_id": v2, "signature": "deadbeefdeadbeef", "witness_count": n})
    assert bad.status_code == 409
    ok = client.post(f"/api/exceptions/{eid}/reconfirm", json={
        "snapshot_id": v2, "signature": sig, "witness_count": n})
    assert ok.status_code == 200, ok.text
    assert ok.json()["needs_review"] is False
    assert ok.json()["baseline_snapshot_id"] == v2

    # now it follows the normal lifecycle on the NEW baseline
    assert _sweep(client, T(12))["activated"] == [eid]
    assert client.get(f"/api/exceptions/{eid}").json()["status"] == "active"

    # old snapshot diff & replay remain correct (immutable history). The
    # minimal witness is the SHALLOWEST representative of the changed region
    # (the whole 192.168.0.0/16 le32 band flips permit->deny).
    d = client.post("/api/snapshots/diff", json={
        "old_snapshot_id": v1, "new_snapshot_id": v2}).json()
    assert d["witness_count"] >= 1
    changed = {w["prefix"]: w["change"] for w in d["witnesses"]}
    assert changed == {"192.168.0.0/16": "permit->deny"}
    # explicit probe replay still answers at the /24 granularity
    rep1 = client.post(f"/api/snapshots/{v1}/replay", json={
        "probes": ["192.168.100.0/24"]}).json()
    assert rep1["results"][0]["final_action"] == "permit"
    rep2 = client.post(f"/api/snapshots/{v2}/replay", json={
        "probes": ["192.168.100.0/24"]}).json()
    assert rep2["results"][0]["final_action"] == "deny"


def test_active_exception_keeps_running_when_baseline_superseded(client):
    pid, v1 = _policy_with_baseline(client)
    eid = _approved_exception(
        client, pid, v1, prefix="192.168.100.0/24", action="deny")
    _sweep(client, T(12))
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "permit"}]})
    client.post(f"/api/policies/{pid}/snapshots", json={"label": "v2"})
    # active exception is NOT forced into review; it stays effective until its
    # own end boundary against the snapshot it was approved with
    exc = client.get(f"/api/exceptions/{eid}").json()
    assert exc["needs_review"] is False and exc["status"] == "active"


# --------------------------------------- 5. restart catch-up records once
def test_restart_catchup_expiry_single_history_row(client, db):
    from app.config import DATABASE_URL
    pid, sid = _policy_with_baseline(client)
    eid = _approved_exception(
        client, pid, sid, prefix="192.168.100.0/24", action="deny")
    _sweep(client, T(12))

    # simulate a PROCESS RESTART: brand new engine/sessionmaker on the same DB
    fresh_engine = create_engine(DATABASE_URL, future=True)
    FreshSession = sessionmaker(bind=fresh_engine, future=True)

    def expired_event_count():
        fs = FreshSession()
        try:
            return len(list(fs.scalars(select(dbmod.ExceptionEvent).where(
                dbmod.ExceptionEvent.exception_id == eid,
                dbmod.ExceptionEvent.event_type == "expire"))))
        finally:
            fs.close()

    # clock is now past end (as after downtime spanning the boundary)
    fs = FreshSession()
    try:
        out1 = es.sweep(fs, now=T(15))
    finally:
        fs.close()
    assert out1["expired"] == [eid]
    assert expired_event_count() == 1

    # second restart / repeated catch-up changes nothing
    fs = FreshSession()
    try:
        out2 = es.sweep(fs, now=T(16))
    finally:
        fs.close()
    assert out2["expired"] == [] and expired_event_count() == 1

    status = client.get(f"/api/exceptions/{eid}").json()
    assert status["status"] == "expired"
    assert [e["event_type"] for e in status["events"]].count("expire") == 1
    fresh_engine.dispose()


# ------------------------------------------------------- FRR composed config
def test_composed_policy_matches_frr_model():
    baseline = policy_from_dicts("maint", [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 24},
    ])
    specs = [
        ExceptionSpec(id=1, name="guard", prefix="192.168.100.0/24",
                      action=Action.DENY, priority=100),
        ExceptionSpec(id=2, name="temp-open", prefix="10.0.0.0/9",
                      action=Action.PERMIT, ge=10, le=32, priority=200),
    ]
    composed = compose_policy(baseline, specs)
    probes = [
        "192.168.100.0/24",   # exception deny overrides baseline permit
        "192.168.200.0/24",   # baseline permit
        "10.128.0.0/10",      # exception permit overrides baseline deny
        "10.64.0.0/10",       # outside /9 -> baseline deny
        "8.8.8.8/32",         # default deny
    ]
    br = FakeFRRBridge(None, node="a")
    out = cross_validate(composed.policy, probes, bridge=br)
    assert out["status"] == "match", out["mismatches"]
    assert br.installed == {}                 # throwaway list removed
    # baseline rules are untouched (composed uses virtual seqs)
    assert [r.seq for r in baseline.rules] == [10, 20]
    rendered = composed.policy.to_frr_prefix_list().splitlines()
    assert rendered[0].startswith("ip prefix-list maint-effective seq 10 permit 10.0.0.0/9")
    assert any("seq 1000020 permit 192.168.0.0/16 le 24" in l for l in rendered)


def test_effective_cross_validate_endpoint(client):
    pid, sid = _policy_with_baseline(client)
    eid = _approved_exception(
        client, pid, sid, prefix="192.168.100.0/24", action="deny")
    _sweep(client, T(12))
    # exercise the API path with an injectable bridge (no live container
    # needed): FRRUnavailable is 503 when docker absent; assert the composed
    # config endpoint renders exceptions and runs recorded against sim bridge
    # indirectly via validate.cross_validate on the service-level composed.
    s = dbmod.SessionLocal()
    try:
        composed = es.effective_at(s, pid, at=T(12))
        assert [x.id for x in composed.exceptions] == [eid]
        br = FakeFRRBridge(None, node="a")
        out = cross_validate(composed.policy,
                             ["192.168.100.0/24", "192.168.200.0/24"],
                             bridge=br)
        assert out["status"] == "match"
    finally:
        s.close()


# -------------------------------------------------------------- misc semantics
def test_exception_family_must_match_baseline(client):
    pid, sid = _policy_with_baseline(client, name="v4", family=4)
    r = client.post(f"/api/policies/{pid}/exceptions", json={
        "name": "bad", "prefix": "2001:db8::/40", "action": "permit",
        "starts_at": ISO(T(12)), "ends_at": ISO(T(14)),
        "baseline_snapshot_id": sid})
    assert r.status_code == 422 and "famil" in r.json()["detail"]


def test_window_validation(client):
    pid, sid = _policy_with_baseline(client)
    r = client.post(f"/api/policies/{pid}/exceptions", json={
        "name": "bad-window", "prefix": "10.0.0.0/8", "action": "permit",
        "starts_at": ISO(T(14)), "ends_at": ISO(T(12)),
        "baseline_snapshot_id": sid})
    assert r.status_code == 422


def test_preview_reports_minimal_witnesses_without_persisting(client):
    pid, sid = _policy_with_baseline(client)
    r = client.post(f"/api/policies/{pid}/exceptions/preview", json={
        "candidate": {
            "name": "preview-only", "prefix": "192.168.100.0/24",
            "action": "deny", "starts_at": ISO(T(12)), "ends_at": ISO(T(14))},
        "snapshot_id": sid})
    assert r.status_code == 200, r.text
    pv = r.json()
    assert pv["target_exception_id"] is None
    prefixes = {w["prefix"]: w["change"] for w in pv["witnesses"]}
    # baseline permitted /24s in 192.168.0.0/16 le24; denying exactly
    # 192.168.100.0/24 flips that single cell
    assert prefixes.get("192.168.100.0/24") == "permit->deny"
    assert client.get(f"/api/policies/{pid}/exceptions").json() == []


def test_clock_override_api(client):
    r = client.post("/api/clock", json={"at": ISO(T(9))})
    assert r.json()["now"] == ISO(T(9))
    assert client.get("/api/clock").json()["real"] is False
    client.post("/api/clock", json={"reset": True})
    assert client.get("/api/clock").json()["real"] is True


def test_active_exception_cannot_be_edited_but_draft_can(client):
    pid, sid = _policy_with_baseline(client)
    eid = _approved_exception(
        client, pid, sid, prefix="192.168.100.0/24", action="deny")
    _sweep(client, T(12))
    r = client.patch(f"/api/exceptions/{eid}", json={"reason": "nope"})
    assert r.status_code == 409

    # draft on a fresh exception is editable
    r = client.post(f"/api/policies/{pid}/exceptions", json={
        "name": "drafty", "prefix": "10.0.0.0/8", "action": "permit",
        "starts_at": ISO(T(12)), "ends_at": ISO(T(14)),
        "baseline_snapshot_id": sid})
    did = r.json()["id"]
    r = client.patch(f"/api/exceptions/{did}", json={"reason": "edited"})
    assert r.status_code == 200 and r.json()["reason"] == "edited"


# ----------------------------------- live FRR (only when container present)
def _docker_available():
    import shutil, subprocess
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "exec", "rpolicy-router-a", "true"],
                              capture_output=True, timeout=5).returncode == 0
    except OSError:
        return False


@pytest.mark.skipif(not _docker_available(),
                    reason="FRR container rpolicy-router-a not running")
def test_live_frr_composed_effective_config(client):
    from app.frr_bridge import FRRBridge
    pid, sid = _policy_with_baseline(client)
    eid = _approved_exception(
        client, pid, sid, prefix="192.168.100.0/24", action="deny")
    _sweep(client, T(12))
    s = dbmod.SessionLocal()
    try:
        composed = es.effective_at(s, pid, at=T(12))
        out = cross_validate(
            composed.policy,
            ["192.168.100.0/24", "192.168.200.0/24", "8.8.8.8/32"],
            node="a", bridge=FRRBridge(node="a"))
        assert out["status"] == "match", out
    finally:
        s.close()
