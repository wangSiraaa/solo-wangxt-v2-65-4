"""
Acceptance tests for time-bounded policy exceptions.

Coverage (mapped to the requirements):
* approved exception takes effect at the boundary instant and the baseline is
  restored automatically after end;
* two overlapping exceptions produce ONE deterministic winner and a minimal
  witness prefix set;
* duplicated / out-of-order activate/expire leave the terminal state and the
  history untouched;
* a baseline update sends not-yet-effective exceptions into needs_review and
  never overwrites the old baseline; review + confirm is required;
* after a "process restart" the catch-up expiry runs but writes its history
  row exactly once;
* existing snapshot diff and ordered probe replay keep working with active
  exceptions layered on top;
* boundary semantics: active on [start, end) — permit AT start, baseline
  restored AT end.
"""
from __future__ import annotations

import datetime as dt

import pytest

from app import clock, db as dbmod
from app import exceptions_service as xs
from app.engine import Action


T0 = dt.datetime(2026, 6, 1, 12, 0, tzinfo=dt.timezone.utc)


@pytest.fixture
def fx(db):
    """policy + baseline + frozen clock."""
    fixed = clock.freeze(T0)
    pol = dbmod.Policy(name="maint", family=4, default_action="deny")
    db.add(pol)
    db.commit()
    db.refresh(pol)
    # baseline live rules
    from app import service
    service.replace_rules(db, pol, [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "permit", "le": 24},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "deny", "le": 32},
    ])
    snap = xs.publish_baseline(db, pol.id, label="base-v1")
    yield {"db": db, "pol": pol, "snap": snap, "clock": fixed}
    clock.reset_clock()


def _iso(t):
    return t.isoformat()


def _make(db, pol, **kw):
    params = dict(
        name="maint-1", action="permit", priority=100,
        start_at=T0 + dt.timedelta(hours=1),
        end_at=T0 + dt.timedelta(hours=2),
        matches=[{"prefix": "192.168.100.0/24"}],
        reason="emergency maintenance window", requested_by="ops",
    )
    params.update(kw)
    return xs.create_exception(db, pol.id, **params)


def _approve(db, ex, approver="netops-lead", at=None):
    xs.submit(db, ex.id, actor=approver)
    return xs.approve(db, ex.id, approver=approver,
                      at=at if at is not None else T0)


# ------------------------------------------------------------------ lifecycle
def test_full_lifecycle_steps(fx):
    db, pol = fx["db"], fx["pol"]
    ex = _make(db, pol)
    assert ex.status == xs.DRAFT
    xs.submit(db, ex.id, actor="netops-lead")
    assert ex.status == xs.PENDING
    ex = xs.approve(db, ex.id, approver="netops-lead", at=T0)
    assert ex.status == xs.SCHEDULED
    assert ex.approved_by == "netops-lead"

    # before the window: baseline still denies the witness
    before = xs.enriched_classify(db, pol.id, "192.168.100.0/24", at=T0)
    assert before["final_action"] == "deny"
    assert before["matched_layer"] == "baseline"
    assert before["active_exception_ids"] == []

    # AT start boundary: exception active (window is [start, end))
    at_start = xs.activate(db, ex.id, at=T0 + dt.timedelta(hours=1))
    assert at_start.status == xs.ACTIVE
    hit_start = xs.enriched_classify(
        db, pol.id, "192.168.100.0/24", at=T0 + dt.timedelta(hours=1))
    assert hit_start["final_action"] == "permit"
    assert hit_start["matched_layer"] == "exception"
    assert hit_start["matched_owner"]["exception_id"] == ex.id

    # AT end boundary: expired, baseline restored automatically
    at_end = xs.expire(db, ex.id, at=T0 + dt.timedelta(hours=2))
    assert at_end.status == xs.EXPIRED
    hit_end = xs.enriched_classify(
        db, pol.id, "192.168.100.0/24", at=T0 + dt.timedelta(hours=2))
    assert hit_end["final_action"] == "deny"
    assert hit_end["matched_layer"] == "baseline"

    types = [e["event_type"] for e in xs.event_history(db, ex.id)]
    assert types == ["CREATED", "SUBMITTED", "APPROVED", "SCHEDULED",
                     "ACTIVATED", "EXPIRED"]


def test_approve_within_open_window_activates_immediately(fx):
    db, pol = fx["db"], fx["pol"]
    ex = _make(db, pol, start_at=T0 - dt.timedelta(minutes=1),
               end_at=T0 + dt.timedelta(hours=1))
    xs.submit(db, ex.id, actor="netops-lead")
    ex = xs.approve(db, ex.id, approver="netops-lead", at=T0)
    assert ex.status == xs.ACTIVE
    assert ex.activated_at == T0


def test_approve_after_window_refused(fx):
    db, pol = fx["db"], fx["pol"]
    ex = _make(db, pol, start_at=T0 - dt.timedelta(hours=3),
               end_at=T0 - dt.timedelta(hours=2))
    xs.submit(db, ex.id)
    with pytest.raises(xs.ExceptionConflict):
        xs.approve(db, ex.id, at=T0)


def test_illegal_transitions_rejected(fx):
    db, pol = fx["db"], fx["pol"]
    ex = _make(db, pol)
    with pytest.raises(xs.ExceptionConflict):
        xs.approve(db, ex.id)            # draft cannot approve
    xs.submit(db, ex.id)
    xs.approve(db, ex.id, at=T0)
    with pytest.raises(xs.ExceptionConflict):
        xs.submit(db, ex.id)            # cannot resubmit scheduled


# ------------------------------------------------------------------ idempotency
def test_duplicate_and_out_of_order_activation_expiry(fx):
    db, pol = fx["db"], fx["pol"]
    ex = _approve(db, _make(db, pol))

    # late activate while still scheduled-before-start -> stays scheduled
    assert xs.activate(db, ex.id, at=T0).status == xs.SCHEDULED

    xs.activate(db, ex.id, at=T0 + dt.timedelta(hours=1, seconds=30))
    # duplicate activate at a later, still-open time: no change / no event
    again = xs.activate(db, ex.id, at=T0 + dt.timedelta(hours=1, minutes=10))
    assert again.status == xs.ACTIVE

    # an out-of-order ACTIVATE delivered after expiry must NOT resurrect
    xs.expire(db, ex.id, at=T0 + dt.timedelta(hours=2))
    late = xs.activate(db, ex.id, at=T0 + dt.timedelta(hours=3))
    assert late.status == xs.EXPIRED

    # duplicate expiry: terminal state stays expired, one EXPIRED row only
    assert xs.expire(db, ex.id, at=T0 + dt.timedelta(hours=4)).status == xs.EXPIRED
    assert xs.expire(db, ex.id, at=T0 + dt.timedelta(hours=5)).status == xs.EXPIRED

    hist = xs.event_history(db, ex.id)
    assert [e["event_type"] for e in hist].count("ACTIVATED") == 1
    assert [e["event_type"] for e in hist].count("EXPIRED") == 1

    # revoke cannot reopen a terminal exception either
    assert xs.revoke(db, ex.id).status == xs.EXPIRED


def test_restart_catchup_expires_once(fx):
    """Simulate restart: dispose sessions/engines, rerun catch-up twice."""
    db, pol = fx["db"], fx["pol"]
    ex = _approve(db, _make(db, pol))
    fx["clock"].set(T0 + dt.timedelta(hours=3))      # window long past

    # process-restart catch-up (fresh session, same durable DB)
    s1 = dbmod.SessionLocal()
    out1 = xs.run_due_ticks(s1, at=clock.now())
    s1.close()
    assert ex.id in out1["expired"]

    s2 = dbmod.SessionLocal()
    out2 = xs.run_due_ticks(s2, at=clock.now())
    s2.close()
    assert out2["expired"] == []                      # nothing left to do

    s3 = dbmod.SessionLocal()
    rows = s3.query(dbmod.ExceptionEvent).filter_by(
        exception_id=ex.id, event_type=xs.E_EXPIRED).all()
    assert len(rows) == 1                            # exactly one history row
    s3.close()

    db.expire_all()
    reloaded = db.get(dbmod.PolicyException, ex.id)
    assert reloaded.status == xs.EXPIRED


def test_revoke_is_idempotent_and_blocks_activation(fx):
    db, pol = fx["db"], fx["pol"]
    ex = _approve(db, _make(db, pol))
    xs.revoke(db, ex.id, actor="sec", reason="change rejected")
    assert xs.revoke(db, ex.id).status == xs.REVOKED
    assert xs.activate(db, ex.id,
                       at=T0 + dt.timedelta(hours=1, minutes=1)).status == xs.REVOKED
    assert xs.expire(db, ex.id,
                     at=T0 + dt.timedelta(hours=2)).status == xs.REVOKED
    assert len([e for e in xs.event_history(db, ex.id)
                if e["event_type"] == "REVOKED"]) == 1


# ------------------------------------------------------------- overlapping
def test_two_overlapping_exceptions_deterministic_winner_and_witness(fx):
    db, pol = fx["db"], fx["pol"]
    # broad permit at lower priority...
    broad = _make(db, pol, name="broad", action="permit", priority=200,
                  start_at=T0, end_at=T0 + dt.timedelta(hours=2),
                  matches=[{"prefix": "192.168.0.0/16", "le": 32}])
    # ...narrow deny at HIGHER priority (smaller number wins)
    narrow = _make(db, pol, name="narrow", action="deny", priority=100,
                   start_at=T0, end_at=T0 + dt.timedelta(hours=2),
                   matches=[{"prefix": "192.168.100.0/24"}])
    _approve(db, broad, at=T0 - dt.timedelta(minutes=1))
    _approve(db, narrow, at=T0 - dt.timedelta(minutes=1))

    view = xs.effective_view(db, pol.id, at=T0 + dt.timedelta(minutes=30))
    ids = [e["id"] for e in view["active_exceptions"]]
    assert ids == [narrow.id, broad.id]     # priority order, id tie-break

    # narrow region: higher-priority deny overrides broad permit
    hit_narrow = xs.enriched_classify(db, pol.id, "192.168.100.0/24",
                                      at=T0 + dt.timedelta(minutes=30))
    assert hit_narrow["final_action"] == "deny"
    assert hit_narrow["matched_owner"]["exception_id"] == narrow.id

    # broad-only region: permit from the lower-priority exception
    hit_broad = xs.enriched_classify(db, pol.id, "192.168.50.0/24",
                                     at=T0 + dt.timedelta(minutes=30))
    assert hit_broad["final_action"] == "permit"
    assert hit_broad["matched_owner"]["exception_id"] == broad.id

    # minimal witness set: one shallowest representative for the whole
    # broad-permit region, never a prefix inside the narrow deny hole (where
    # the action does not change)
    permit_w = [w for w in view["witnesses"] if w["change"] == "deny->permit"]
    assert permit_w and permit_w[0]["prefix"] == "192.168.0.0/16"
    import ipaddress as _ip
    hole = _ip.ip_network("192.168.100.0/24")
    for w in view["witnesses"]:
        assert not _ip.ip_network(w["prefix"]).subnet_of(hole)
    assert not [w for w in view["witnesses"]
                if w["prefix"].startswith("192.168.100.")]

    # swap priorities: outcome flips deterministically
    xs.update_draft  # drafts only; use new pair instead
    broad2 = _make(db, pol, name="broad2", action="permit", priority=50,
                   start_at=T0 + dt.timedelta(hours=3),
                   end_at=T0 + dt.timedelta(hours=5),
                   matches=[{"prefix": "192.168.0.0/16", "le": 32}])
    narrow2 = _make(db, pol, name="narrow2", action="deny", priority=300,
                    start_at=T0 + dt.timedelta(hours=3),
                    end_at=T0 + dt.timedelta(hours=5),
                    matches=[{"prefix": "192.168.100.0/24"}])
    _approve(db, broad2, at=T0 + dt.timedelta(hours=2, minutes=59))
    _approve(db, narrow2, at=T0 + dt.timedelta(hours=2, minutes=59))
    hit_flip = xs.enriched_classify(db, pol.id, "192.168.100.0/24",
                                    at=T0 + dt.timedelta(hours=4))
    assert hit_flip["final_action"] == "permit"
    assert hit_flip["matched_owner"]["exception_id"] == broad2.id


def test_priority_tie_breaks_on_exception_id(fx):
    db, pol = fx["db"], fx["pol"]
    a = _make(db, pol, name="a", action="permit", priority=100,
              start_at=T0, end_at=T0 + dt.timedelta(hours=1),
              matches=[{"prefix": "192.168.100.0/24"}])
    b = _make(db, pol, name="b", action="deny", priority=100,
              start_at=T0, end_at=T0 + dt.timedelta(hours=1),
              matches=[{"prefix": "192.168.100.0/24"}])
    _approve(db, a, at=T0 - dt.timedelta(minutes=1))
    _approve(db, b, at=T0 - dt.timedelta(minutes=1))
    hit = xs.enriched_classify(db, pol.id, "192.168.100.0/24", at=T0)
    # same priority -> lower id wins deterministically
    assert hit["matched_owner"]["exception_id"] == a.id
    assert hit["final_action"] == "permit"


# ------------------------------------------------------------- baseline supersede
def test_baseline_supersede_marks_pending_for_review(fx):
    db, pol, snap_v1 = fx["db"], fx["pol"], fx["snap"]
    # not-yet-effective exception bound to v1
    ex = _approve(db, _make(db, pol,
                            start_at=T0 + dt.timedelta(hours=5),
                            end_at=T0 + dt.timedelta(hours=6)))
    assert ex.status == xs.SCHEDULED

    from app import service
    service.replace_rules(db, pol, [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 30, "prefix": "192.168.0.0/16", "action": "permit", "le": 32},
    ])
    snap_v2 = xs.publish_baseline(db, pol.id, label="base-v2")

    ex = db.get(dbmod.PolicyException, ex.id)
    assert ex.needs_review is True
    assert ex.status == xs.SCHEDULED              # not auto-cancelled
    # bound snapshot remains immutable v1
    assert ex.snapshot_id == snap_v1.id
    assert pol.baseline_snapshot_id == snap_v2.id

    # due tick while window opens must NOT activate a review-blocked exception
    out = xs.run_due_ticks(db, at=T0 + dt.timedelta(hours=5, minutes=1))
    assert ex.id in out["review_blocked"]
    ex = db.get(dbmod.PolicyException, ex.id)
    assert ex.status == xs.SCHEDULED and ex.needs_review is True
    # and it is not present in the synthesized effective policy
    view = xs.effective_view(db, pol.id, at=T0 + dt.timedelta(hours=5, minutes=1))
    assert ex.id not in [e["id"] for e in view["active_exceptions"]]

    # a direct activate / catch-up tick cannot bypass the pending review,
    # and neither does a duplicate idempotent approval resurrect it.
    blocked = xs.activate(db, ex.id,
                          at=T0 + dt.timedelta(hours=5, minutes=1))
    assert blocked.status == xs.SCHEDULED and blocked.needs_review is True
    again = xs.approve(db, ex.id, approver="someone-else",
                       at=T0 + dt.timedelta(hours=5, minutes=1))
    assert again.approved_by == "netops-lead"   # original approval untouched
    # preview against the NEW baseline is possible without mutation
    prev = xs.preview_exception(db, ex, baseline_snapshot_id=snap_v2.id)
    assert prev["baseline_is_current"] is True
    # confirm review -> still scheduled (window open now -> activate applied)
    reviewed = xs.confirm_review(db, ex.id,
                                 at=T0 + dt.timedelta(hours=5, minutes=1))
    assert reviewed.needs_review is False
    assert reviewed.reviewed_snapshot_id == snap_v2.id
    assert reviewed.status == xs.ACTIVE

    hit = xs.enriched_classify(db, pol.id, "192.168.100.0/24",
                               at=T0 + dt.timedelta(hours=5, minutes=1))
    assert hit["final_action"] == "permit"
    assert hit["baseline_snapshot_id"] == snap_v2.id

    types = [e["event_type"] for e in xs.event_history(db, ex.id)]
    assert types.count("BASELINE_STALED") == 1
    assert types.count("REVIEWED") == 1


def test_active_exception_not_disturbed_by_baseline_change(fx):
    db, pol = fx["db"], fx["pol"]
    ex = _make(db, pol, start_at=T0 - dt.timedelta(hours=1),
               end_at=T0 + dt.timedelta(hours=1))
    _approve(db, ex, at=T0 - dt.timedelta(hours=2))
    xs.run_due_ticks(db, at=T0)
    assert db.get(dbmod.PolicyException, ex.id).status == xs.ACTIVE

    from app import service
    service.replace_rules(db, pol, [
        {"seq": 99, "prefix": "0.0.0.0/0", "action": "deny"}])
    xs.publish_baseline(db, pol.id, label="base-v2")
    ex = db.get(dbmod.PolicyException, ex.id)
    assert ex.needs_review is False and ex.status == xs.ACTIVE
    # remains effective; window end still expires it
    xs.run_due_ticks(db, at=T0 + dt.timedelta(hours=1, minutes=1))
    assert db.get(dbmod.PolicyException, ex.id).status == xs.EXPIRED


def test_draft_unaffected_by_baseline_change(fx):
    db, pol = fx["db"], fx["pol"]
    ex = _make(db, pol)
    from app import service
    service.replace_rules(db, pol, [
        {"seq": 1, "prefix": "10.0.0.0/8", "action": "deny"}])
    xs.publish_baseline(db, pol.id, label="base-v2")
    assert db.get(dbmod.PolicyException, ex.id).needs_review is False


def test_old_baseline_snapshot_not_overwritten(fx):
    db, pol, snap_v1 = fx["db"], fx["pol"], fx["snap"]
    v1_rules = list(snap_v1.payload["rules"])
    from app import service
    service.replace_rules(db, pol, [
        {"seq": 1, "prefix": "8.8.8.0/24", "action": "permit"}])
    xs.publish_baseline(db, pol.id, label="base-v2")
    again = db.get(dbmod.Snapshot, snap_v1.id)
    assert again.payload["rules"] == v1_rules
    # and snapshot diff / replay over the old snapshot still behave
    s2_id = pol.baseline_snapshot_id
    d = service.snapshot_diff(db, snap_v1.id, s2_id)
    assert d["witness_count"] >= 1


# ------------------------------------------------------------------ validation
def test_exception_validation(fx):
    db, pol = fx["db"], fx["pol"]
    with pytest.raises(xs.ExceptionError):
        _make(db, pol, start_at=T0 + dt.timedelta(hours=2),
              end_at=T0 + dt.timedelta(hours=1))       # end <= start
    with pytest.raises(xs.ExceptionError):
        _make(db, pol, matches=[])                      # empty scope
    with pytest.raises(xs.ExceptionError):
        _make(db, pol, matches=[{"prefix": "2001:db8::/32"}])  # family mix
    with pytest.raises(xs.ExceptionError):
        _make(db, pol, matches=[{"prefix": "10.0.0.0/8",
                                 "ge": 24, "le": 20}])  # ge>le
    with pytest.raises(xs.ExceptionError):
        _make(db, pol, action="drop")                   # bad action


def test_no_baseline_snapshot_requires_publish(db):
    pol = dbmod.Policy(name="lonely", family=4, default_action="deny")
    db.add(pol)
    db.commit()
    with pytest.raises(xs.ExceptionError):
        xs.create_exception(
            db, pol.id, name="x", action="permit",
            start_at=T0, end_at=T0 + dt.timedelta(hours=1),
            matches=[{"prefix": "10.0.0.0/8"}])


def test_timeline_has_boundaries_and_events(fx):
    db, pol = fx["db"], fx["pol"]
    ex = _approve(db, _make(db, pol))
    tl = xs.timeline(db, pol.id, at=T0 + dt.timedelta(minutes=90))
    assert {b["at"] for b in tl["boundaries"]} >= {
        _iso(T0 + dt.timedelta(hours=1)),
        _iso(T0 + dt.timedelta(hours=2))}
    active_sets = {b["at"]: b["active_exception_ids"]
                   for b in tl["boundaries"]}
    assert active_sets[_iso(T0 + dt.timedelta(hours=1))] == [ex.id]
    assert active_sets[_iso(T0 + dt.timedelta(hours=2))] == []
    # projected status at a future instant without mutating
    assert xs.projected_status(ex, now=T0 + dt.timedelta(hours=3)) == "expired"
    assert db.get(dbmod.PolicyException, ex.id).status == xs.SCHEDULED


# ------------------------------------------------------------------ FRR render
def test_composed_render_is_frr_safe_and_removable(fx):
    """
    The synthesized config is a plain prefix list over dense seqs; verify it
    renders and evaluates identically through the plist.c-ported semantics via
    validate.cross_validate with a fake bridge (live FRR tested separately in
    test_frr_exceptions when a container is present).
    """
    from tests.test_frr_consistency import FakeFRRBridge  # type: ignore
    db, pol = fx["db"], fx["pol"]
    ex = _make(db, pol, action="permit",
               start_at=T0 - dt.timedelta(minutes=5),
               end_at=T0 + dt.timedelta(hours=1),
               matches=[{"prefix": "192.168.100.0/24"}])
    _approve(db, ex, at=T0 - dt.timedelta(hours=1))
    composed, seq_map, excs, snap = xs.composed_policy_at(db, pol.id, at=T0)
    seqs = [r.seq for r in composed.rules]
    assert seqs == list(range(1, len(seqs) + 1))     # dense, FRR-safe

    probes = ["192.168.100.0/24", "192.168.50.0/24",
              "10.0.1.0/24", "8.8.8.8/32"]
    from app.validate import cross_validate
    fake = FakeFRRBridge(composed)
    result = cross_validate(composed, probes, bridge=fake, install=True)
    assert result["status"] == "match", result["mismatches"]
    # the list was removed after validation
    assert fake.installed == {}
