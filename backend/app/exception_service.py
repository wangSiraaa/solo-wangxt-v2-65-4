"""
Service layer for time-bounded policy exceptions.

Key guarantees:

* Lifecycle state machine:
      draft -> pending -> planned -> active -> expired
                          └───────────> revoked
      draft -> rejected -> draft (edit + resubmit)
  Every transition appends an ExceptionEvent row keyed by
  (exception_id, event_type, at_time); history is append-only.

* activate / expire / revoke are IDEMPOTENT. Repeated or out-of-order
  delivery of timer events never changes a settled state and never inserts a
  second history row. A late "activate" cannot resurrect an expired/revoked
  exception.

* The catch-up sweep is driven by the injectable clock. On process restart it
  simply replays overdue boundaries against stored state; because state moves
  monotonically and history rows are de-duplicated, each boundary is recorded
  exactly once.

* An exception binds an IMMUTABLE snapshot. When a newer snapshot is taken
  (baseline superseded), not-yet-active exceptions are flagged needs_review:
  they will not activate until re-previewed and explicitly reconfirmed. The
  old snapshot (and thus the old policy) is never overwritten.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db as dbmod
from .clock import as_utc, clock
from .engine import Action, PolicyError
from .exceptions import (
    ComposedPolicy, ExceptionSpec,
    compose_policy, effective_classify, overlap_witnesses, order_exceptions,
    priority_key,
)
from .service import ValidationError, engine_policy_from_snapshot


# States ---------------------------------------------------------------------
DRAFT, PENDING, PLANNED, ACTIVE, EXPIRED, REVOKED, REJECTED = (
    "draft", "pending", "planned", "active", "expired", "revoked", "rejected")

# terminal / not-yet-active classification
TERMINAL = {EXPIRED, REVOKED}
NOT_YET_ACTIVE = {DRAFT, PENDING, PLANNED, REJECTED}

# allowed submit-time status transitions
TRANSITIONS = {
    "submit":   (DRAFT, PENDING),
    "approve":  (PENDING, PLANNED),
    "reject":   (PENDING, REJECTED),
    "revise":   (REJECTED, DRAFT),
    "activate": (PLANNED, ACTIVE),
    "expire":   (ACTIVE, EXPIRED),
    "revoke":   (PLANNED, REVOKED),
    "revoke_active": (ACTIVE, REVOKED),
    "reconfirm": (PLANNED, PLANNED),
}


class Conflict(Exception):
    """Illegal state transition (HTTP 409)."""


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _now() -> dt.datetime:
    return clock.now()


def _parse_dt(value) -> dt.datetime:
    if isinstance(value, dt.datetime):
        return as_utc(value)
    if isinstance(value, str):
        s = value.strip().replace("Z", "+00:00")
        return as_utc(dt.datetime.fromisoformat(s))
    raise ValidationError(f"bad datetime: {value!r}")


def _record_event(session: Session, exc: dbmod.PolicyException,
                  event_type: str, at_time: dt.datetime,
                  from_status: Optional[str], to_status: Optional[str],
                  detail: Optional[dict] = None) -> Optional[dbmod.ExceptionEvent]:
    """Append a history row unless an identical (type, at_time) row exists."""
    at_time = as_utc(at_time)
    existing = session.scalar(
        select(dbmod.ExceptionEvent).where(
            dbmod.ExceptionEvent.exception_id == exc.id,
            dbmod.ExceptionEvent.event_type == event_type,
            dbmod.ExceptionEvent.at_time == at_time,
        ))
    if existing is not None:
        return None
    ev = dbmod.ExceptionEvent(
        exception_id=exc.id, event_type=event_type,
        from_status=from_status, to_status=to_status,
        at_time=at_time, detail=detail or {},
    )
    session.add(ev)
    return ev


def _transition(session: Session, exc: dbmod.PolicyException, event: str,
                at_time: Optional[dt.datetime] = None,
                detail: Optional[dict] = None,
                record: bool = True) -> dbmod.ExceptionEvent | None:
    if event not in TRANSITIONS:
        raise Conflict(f"unknown event {event!r}")
    src, dst = TRANSITIONS[event]
    if exc.status != src:
        raise Conflict(
            f"exception {exc.id}: cannot {event} from status {exc.status!r} "
            f"(required {src!r})")
    at_time = as_utc(at_time or _now())
    ev = None
    if record:
        ev = _record_event(session, exc, event, at_time, src, dst, detail)
    exc.status = dst
    return ev


def _validate_scope(family: int, prefix: str, ge, le,
                    action: str, start: dt.datetime, end: dt.datetime) -> None:
    # parse scope through the engine rule (strict, family + ge/le validation)
    from .engine import Rule
    try:
        r = Rule(seq=1, prefix=prefix, action=Action(action), ge=ge, le=le)
    except PolicyError as e:
        raise ValidationError(str(e))
    except ValueError as e:
        raise ValidationError(f"bad prefix: {e}")
    if r.family != family:
        raise ValidationError(
            f"{r.prefix} is IPv{r.family} but policy is IPv{family}; "
            "families must not be mixed")
    if not (start < end):
        raise ValidationError("ends_at must be strictly after starts_at")


def _latest_snapshot(session: Session, policy_id: int) -> Optional[dbmod.Snapshot]:
    return session.scalar(
        select(dbmod.Snapshot).where(dbmod.Snapshot.policy_id == policy_id)
        .order_by(dbmod.Snapshot.version.desc()))


# --------------------------------------------------------------------------
# CRUD / lifecycle
# --------------------------------------------------------------------------

def create_exception(session: Session, policy_id: int, body: dict,
                     baseline_snapshot_id: Optional[int] = None,
                     ) -> dbmod.PolicyException:
    pol = session.get(dbmod.Policy, policy_id)
    if pol is None:
        raise ValidationError(f"policy {policy_id} not found")
    snap = (session.get(dbmod.Snapshot, baseline_snapshot_id)
            if baseline_snapshot_id else _latest_snapshot(session, policy_id))
    if snap is None:
        raise ValidationError(
            "policy has no immutable baseline snapshot; take a snapshot first")
    if snap.policy_id != policy_id:
        raise ValidationError("baseline snapshot belongs to another policy")
    if snap.payload.get("family") != pol.family:
        raise ValidationError("baseline family mismatch")

    start = _parse_dt(body["starts_at"])
    end = _parse_dt(body["ends_at"])
    _validate_scope(pol.family, body["prefix"].strip(), body.get("ge"),
                    body.get("le"), body["action"], start, end)

    exc = dbmod.PolicyException(
        policy_id=policy_id, name=body["name"],
        baseline_snapshot_id=snap.id, family=pol.family,
        prefix=body["prefix"].strip(), ge=body.get("ge"), le=body.get("le"),
        action=body["action"], priority=int(body.get("priority", 100)),
        starts_at=start, ends_at=end,
        reason=body.get("reason", ""),
        requested_by=body.get("requested_by", "lab"),
        status=DRAFT,
    )
    session.add(exc)
    session.flush()
    _record_event(session, exc, "created", _now(), None, DRAFT,
                  {"baseline_snapshot_id": snap.id})
    session.commit()
    session.refresh(exc)
    return exc


def update_draft(session: Session, exc_id: int, body: dict) -> dbmod.PolicyException:
    exc = session.get(dbmod.PolicyException, exc_id)
    if exc is None:
        raise ValidationError("exception not found")
    if exc.status not in (DRAFT, REJECTED):
        raise Conflict("only draft / rejected exceptions can be edited")
    pol = session.get(dbmod.Policy, exc.policy_id)
    start = _parse_dt(body.get("starts_at", exc.starts_at))
    end = _parse_dt(body.get("ends_at", exc.ends_at))
    _validate_scope(exc.family,
                    body.get("prefix", exc.prefix).strip(),
                    body.get("ge", exc.ge), body.get("le", exc.le),
                    body.get("action", exc.action), start, end)
    for field in ("name", "reason", "requested_by"):
        if body.get(field) is not None:
            setattr(exc, field, body[field])
    exc.prefix = body.get("prefix", exc.prefix).strip()
    exc.ge = body.get("ge", exc.ge)
    exc.le = body.get("le", exc.le)
    exc.action = body.get("action", exc.action)
    exc.priority = int(body.get("priority", exc.priority))
    exc.starts_at, exc.ends_at = start, end
    _record_event(session, exc, "edited", _now(), exc.status, exc.status, body)
    session.commit()
    session.refresh(exc)
    return exc


def submit(session: Session, exc_id: int) -> dbmod.PolicyException:
    exc = session.get(dbmod.PolicyException, exc_id)
    if exc is None:
        raise ValidationError("exception not found")
    if exc.needs_review:
        raise Conflict("baseline superseded: reconfirm against the new "
                       "baseline before submission")
    _transition(session, exc, "submit")
    session.commit()
    session.refresh(exc)
    return exc


def approve(session: Session, exc_id: int, approver: str = "approver",
            now: Optional[dt.datetime] = None) -> dbmod.PolicyException:
    exc = session.get(dbmod.PolicyException, exc_id)
    if exc is None:
        raise ValidationError("exception not found")
    if exc.needs_review:
        raise Conflict("baseline superseded after submission: reconfirm first")
    ev = _transition(session, exc, "approve", at_time=now)
    exc.approved_by = approver
    exc.approved_at = as_utc(now or _now())
    if ev:
        ev.detail = {"approved_by": approver}
    session.commit()
    session.refresh(exc)
    return exc


def reject(session: Session, exc_id: int, note: str = "") -> dbmod.PolicyException:
    exc = session.get(dbmod.PolicyException, exc_id)
    if exc is None:
        raise ValidationError("exception not found")
    _transition(session, exc, "reject", detail={"note": note})
    session.commit()
    session.refresh(exc)
    return exc


def activate(session: Session, exc_id: int, at: Optional[dt.datetime] = None,
             late_ok: bool = False) -> dict:
    """
    Idempotent activation.

    * planned -> active only when at >= starts_at (timer delivery);
    * already active/expired/revoked -> no-op (``changed: False``), no history;
    * a LATE explicit activate for an exception whose window already ended is
      rejected: late timer events must never resurrect a settled exception.
    """
    exc = session.get(dbmod.PolicyException, exc_id)
    if exc is None:
        raise ValidationError("exception not found")
    at = as_utc(at or _now())
    if exc.status == ACTIVE:
        return {"changed": False, "status": exc.status}
    if exc.status in TERMINAL:
        return {"changed": False, "status": exc.status, "stale": True}
    if exc.status != PLANNED:
        raise Conflict(f"cannot activate exception in status {exc.status!r}")
    if at < as_utc(exc.starts_at):
        raise Conflict("activation before starts_at; window has not begun")
    if at >= as_utc(exc.ends_at):
        # late event: do NOT resurrect — leave it for expiry sweep / error out
        raise Conflict("activation arrives after ends_at; window already "
                       "passed (late events cannot activate)")
    if exc.needs_review:
        raise Conflict("baseline superseded: reconfirm before activation")
    ev = _transition(session, exc, "activate", at_time=at)
    session.commit()
    session.refresh(exc)
    return {"changed": ev is not None, "status": exc.status}


def expire(session: Session, exc_id: int, at: Optional[dt.datetime] = None) -> dict:
    """Idempotent expiry at the half-open end boundary; restores baseline."""
    exc = session.get(dbmod.PolicyException, exc_id)
    if exc is None:
        raise ValidationError("exception not found")
    at = as_utc(at or _now())
    if exc.status == EXPIRED:
        return {"changed": False, "status": EXPIRED}
    if exc.status == REVOKED:
        return {"changed": False, "status": REVOKED, "stale": True}
    if exc.status != ACTIVE:
        # never active (e.g. planned window fully missed) is also settled as
        # expired — but only once.
        if exc.status == PLANNED and at >= as_utc(exc.ends_at):
            # planned but never activated (clock jumped past window): record a
            # direct expire without an activate row.
            _record_event(session, exc, "skipped", at, PLANNED, EXPIRED,
                          {"reason": "window elapsed before activation"})
            exc.status = EXPIRED
            ev = _record_event(session, exc, "expire", at, PLANNED, EXPIRED)
            session.commit()
            session.refresh(exc)
            return {"changed": ev is not None, "status": EXPIRED, "skipped": True}
        raise Conflict(f"cannot expire exception in status {exc.status!r}")
    if at < as_utc(exc.ends_at):
        raise Conflict("expiry before ends_at; use revoke for early removal")
    ev = _transition(session, exc, "expire", at_time=at)
    session.commit()
    session.refresh(exc)
    return {"changed": ev is not None, "status": EXPIRED}


def revoke(session: Session, exc_id: int, at: Optional[dt.datetime] = None,
           note: str = "") -> dict:
    """Idempotent early removal (planned or active)."""
    exc = session.get(dbmod.PolicyException, exc_id)
    if exc is None:
        raise ValidationError("exception not found")
    at = as_utc(at or _now())
    if exc.status == REVOKED:
        return {"changed": False, "status": REVOKED}
    if exc.status in (EXPIRED,):
        return {"changed": False, "status": EXPIRED, "stale": True}
    if exc.status == PLANNED:
        ev = _transition(session, exc, "revoke", at_time=at,
                         detail={"note": note})
    elif exc.status == ACTIVE:
        ev = _transition(session, exc, "revoke_active", at_time=at,
                         detail={"note": note})
    else:
        raise Conflict(f"cannot revoke exception in status {exc.status!r}")
    session.commit()
    session.refresh(exc)
    return {"changed": ev is not None, "status": REVOKED}


# --------------------------------------------------------------------------
# Clock-driven sweep (runs on startup, periodically, and on demand)
# --------------------------------------------------------------------------

def _due_activations(session: Session, now: dt.datetime) -> List[dbmod.PolicyException]:
    return list(session.scalars(
        select(dbmod.PolicyException).where(
            dbmod.PolicyException.status == PLANNED,
            dbmod.PolicyException.needs_review.is_(False),
            dbmod.PolicyException.starts_at <= now,
            dbmod.PolicyException.ends_at > now,
        ).order_by(dbmod.PolicyException.starts_at, dbmod.PolicyException.id)))


def _due_expiries(session: Session, now: dt.datetime) -> List[dbmod.PolicyException]:
    return list(session.scalars(
        select(dbmod.PolicyException).where(
            dbmod.PolicyException.status == ACTIVE,
            dbmod.PolicyException.ends_at <= now,
        ).order_by(dbmod.PolicyException.ends_at, dbmod.PolicyException.id)))


def _skipped_windows(session: Session, now: dt.datetime) -> List[dbmod.PolicyException]:
    """planned & never activated but window already fully in the past."""
    return list(session.scalars(
        select(dbmod.PolicyException).where(
            dbmod.PolicyException.status == PLANNED,
            dbmod.PolicyException.ends_at <= now,
        )))


def sweep(session: Session, now: Optional[dt.datetime] = None) -> dict:
    """
    Apply all boundaries due at/ before ``now`` in ONE transaction.

    Safe to run repeatedly and after restart: every transition is guarded by
    stored status and history rows are de-duplicated, so a boundary is
    recorded exactly once even if its timer event is delivered many times.
    """
    now = as_utc(now or _now())
    activated, expired, skipped = [], [], []

    # expiries first makes an over-window jump idempotent: an exception whose
    # whole window is in the past never transiently activates.
    for exc in _skipped_windows(session, now):
        _record_event(session, exc, "skipped", as_utc(exc.ends_at),
                      PLANNED, EXPIRED,
                      {"reason": "window elapsed before activation"})
        exc.status = EXPIRED
        _record_event(session, exc, "expire", as_utc(exc.ends_at),
                      PLANNED, EXPIRED)
        skipped.append(exc.id)

    for exc in _due_expiries(session, now):
        if _transition(session, exc, "expire", at_time=exc.ends_at):
            expired.append(exc.id)

    for exc in _due_activations(session, now):
        if _transition(session, exc, "activate", at_time=exc.starts_at):
            activated.append(exc.id)

    session.commit()
    return {"at": now.isoformat(), "activated": activated,
            "expired": expired, "skipped": skipped}


# --------------------------------------------------------------------------
# Baseline supersedence & reconfirmation
# --------------------------------------------------------------------------

def mark_superseded_exceptions(session: Session, policy_id: int,
                               new_snapshot: dbmod.Snapshot) -> int:
    """
    Called inside snapshot creation. Not-yet-active exceptions bound to an
    older baseline are flagged for re-review; active exceptions keep running
    against the snapshot they were approved with (the old snapshot is
    immutable and never overwritten).
    """
    rows = list(session.scalars(
        select(dbmod.PolicyException).where(
            dbmod.PolicyException.policy_id == policy_id,
            dbmod.PolicyException.baseline_snapshot_id != new_snapshot.id,
            dbmod.PolicyException.status.in_(sorted(NOT_YET_ACTIVE)),
            dbmod.PolicyException.needs_review.is_(False),
        )))
    for exc in rows:
        exc.needs_review = True
        exc.review_reason = (
            f"baseline superseded by snapshot v{new_snapshot.version}; "
            "re-preview and reconfirm before it can take effect")
        _record_event(session, exc, "review_required", _now(),
                      exc.status, exc.status,
                      {"new_snapshot_id": new_snapshot.id,
                       "new_version": new_snapshot.version})
    if rows:
        session.flush()
    return len(rows)


def _spec_from_row(exc: dbmod.PolicyException) -> ExceptionSpec:
    return ExceptionSpec(
        id=exc.id, name=exc.name, prefix=exc.prefix,
        action=Action(exc.action), ge=exc.ge, le=exc.le,
        priority=exc.priority,
    )


def active_exception_rows(session: Session, policy_id: int,
                          at: dt.datetime) -> List[dbmod.PolicyException]:
    rows = list(session.scalars(
        select(dbmod.PolicyException).where(
            dbmod.PolicyException.policy_id == policy_id,
            dbmod.PolicyException.status == ACTIVE,
            dbmod.PolicyException.starts_at <= at,
            dbmod.PolicyException.ends_at > at,
        )))
    return sorted(rows, key=lambda r: priority_key(_spec_from_row(r)))


def baseline_policy_for(session: Session, policy_id: int,
                        snapshot_id: Optional[int]) -> tuple:
    pol = session.get(dbmod.Policy, policy_id)
    if pol is None:
        raise ValidationError(f"policy {policy_id} not found")
    snap = (session.get(dbmod.Snapshot, snapshot_id)
            if snapshot_id else _latest_snapshot(session, policy_id))
    if snap is None:
        raise ValidationError("no baseline snapshot for policy")
    if snap.policy_id != policy_id:
        raise ValidationError("snapshot belongs to another policy")
    return pol, snap, engine_policy_from_snapshot(snap)


def composed_for_rows(baseline: Policy,
                      rows: List[dbmod.PolicyException],
                      name: Optional[str] = None) -> ComposedPolicy:
    specs = [_spec_from_row(r) for r in rows]
    return compose_policy(baseline, specs, name=name)


def effective_at(session: Session, policy_id: int,
                 at: Optional[dt.datetime] = None,
                 snapshot_id: Optional[int] = None,
                 include_planned_preview: bool = False) -> ComposedPolicy:
    """
    Composed policy for a moment in time. By default uses the current
    baseline (latest snapshot) + exceptions that are ACTIVE in [start,end).
    ``include_planned_preview`` also folds in approved planned exceptions whose
    window covers ``at`` (for what-if preview).
    """
    at = as_utc(at or _now())
    _pol, _snap, baseline = baseline_policy_for(session, policy_id, snapshot_id)
    rows = active_exception_rows(session, policy_id, at)
    if include_planned_preview:
        planned = list(session.scalars(
            select(dbmod.PolicyException).where(
                dbmod.PolicyException.policy_id == policy_id,
                dbmod.PolicyException.status == PLANNED,
                dbmod.PolicyException.starts_at <= at,
                dbmod.PolicyException.ends_at > at,
            )))
        rows = sorted(set(rows) | set(planned),
                      key=lambda r: priority_key(_spec_from_row(r)))
    return composed_for_rows(baseline, rows)


# --------------------------------------------------------------------------
# Preview + reconfirm
# --------------------------------------------------------------------------

def preview_signature(payload: dict) -> str:
    """Stable hash of what the operator saw; confirm must echo it."""
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def preview_exception(session: Session, exc_id: Optional[int] = None,
                      policy_id: Optional[int] = None,
                      candidate: Optional[dict] = None,
                      at: Optional[dt.datetime] = None,
                      snapshot_id: Optional[int] = None,
                      other_active_ids: Optional[List[int]] = None) -> dict:
    """
    Semantic impact preview. Two modes:

    * existing exception (``exc_id``): preview against its bound snapshot or a
      supplied ``snapshot_id`` (used during re-review);
    * candidate draft body: validate + preview without persisting.
    """
    specs: List[ExceptionSpec] = []
    target: Optional[dbmod.PolicyException] = None
    target_spec: Optional[ExceptionSpec] = None
    bound_snap_id = snapshot_id

    if exc_id is not None:
        target = session.get(dbmod.PolicyException, exc_id)
        if target is None:
            raise ValidationError("exception not found")
        pid = target.policy_id
        if bound_snap_id is None:
            bound_snap_id = target.baseline_snapshot_id
        target_spec = _spec_from_row(target)
        window_start, window_end = as_utc(target.starts_at), as_utc(target.ends_at)
        at = at or window_start
    elif candidate is not None:
        if policy_id is None:
            raise ValidationError("policy_id required for candidate preview")
        pid = policy_id
        if bound_snap_id is None:
            snap = _latest_snapshot(session, pid)
            bound_snap_id = snap.id if snap else None
        start = _parse_dt(candidate["starts_at"])
        end = _parse_dt(candidate["ends_at"])
        _validate_scope((session.get(dbmod.Policy, pid)).family,
                        candidate["prefix"].strip(), candidate.get("ge"),
                        candidate.get("le"), candidate["action"], start, end)
        target_spec = ExceptionSpec(
            id=None, name=candidate.get("name", "candidate"),
            prefix=candidate["prefix"].strip(), action=Action(candidate["action"]),
            ge=candidate.get("ge"), le=candidate.get("le"),
            priority=int(candidate.get("priority", 100)))
        window_start, window_end = start, end
        at = at or start
    else:
        raise ValidationError("exc_id or candidate required")

    _pol, snap, baseline = baseline_policy_for(session, pid, bound_snap_id)

    # sibling exceptions that overlap the same time window (other committed
    # active/planned rows), so overlap composition is previewed faithfully.
    at = as_utc(at)
    q = select(dbmod.PolicyException).where(
        dbmod.PolicyException.policy_id == pid,
        dbmod.PolicyException.status.in_([ACTIVE, PLANNED]),
        dbmod.PolicyException.starts_at < window_end,
        dbmod.PolicyException.ends_at > window_start,
    )
    siblings = [r for r in session.scalars(q)
                if r.id != (target.id if target else None)]
    if other_active_ids:
        for rid in other_active_ids:
            row = session.get(dbmod.PolicyException, rid)
            if row is not None and row not in siblings:
                siblings.append(row)
    specs = order_exceptions([_spec_from_row(r) for r in siblings] + [target_spec])

    only_baseline = compose_policy(baseline, [])
    with_exc = compose_policy(baseline, specs)

    # witnesses: behavior change of baseline -> composed (minimal set)
    from .trie import minimal_witness_set
    witnesses = [w.to_dict() for w in minimal_witness_set(
        only_baseline.policy, with_exc.policy)]
    # translate virtual seqs back to layer sources (both sides share the same
    # baseline virtual-seq band)
    for w in witnesses:
        for key in ("old_seq", "new_seq"):
            v = w.get(key)
            if v is None:
                w[key.replace("seq", "source")] = None
                continue
            src = with_exc.source_of(v)
            w[key.replace("seq", "source")] = src
            if src and src["layer"] == "baseline":
                w[key] = src["seq"]            # show the original baseline seq
    overlaps = [o.to_dict() for o in overlap_witnesses(specs)]

    payload = {
        "policy_id": pid,
        "baseline_snapshot_id": snap.id,
        "baseline_version": snap.version,
        "target_exception_id": target.id if target else None,
        "target_name": target_spec.name,
        "at": at.isoformat(),
        "window": [window_start.isoformat(), window_end.isoformat()],
        "scope": {"family": target_spec.family, "prefix": target_spec.prefix,
                  "ge": target_spec.ge, "le": target_spec.le},
        "action": target_spec.action.value,
        "witnesses": witnesses,
        "overlaps": overlaps,
        "exception_count": len(specs),
    }
    payload["signature"] = preview_signature(payload)
    payload["needs_review"] = bool(target and target.needs_review
                                   and target.baseline_snapshot_id != snap.id)
    return payload


def reconfirm(session: Session, exc_id: int, new_snapshot_id: int,
              signature: str, seen_witness_count: int) -> dbmod.PolicyException:
    """
    Rebind a needs_review exception to the current baseline after the operator
    has seen (and echoed) the fresh preview. Throws if the preview changed
    since the signature was produced or the target snapshot is not the latest.
    """
    exc = session.get(dbmod.PolicyException, exc_id)
    if exc is None:
        raise ValidationError("exception not found")
    if exc.status not in (PLANNED, DRAFT, PENDING, REJECTED):
        raise Conflict(f"cannot reconfirm exception in status {exc.status!r}")
    latest = _latest_snapshot(session, exc.policy_id)
    if latest is None or latest.id != new_snapshot_id:
        raise Conflict("reconfirmation must target the current latest snapshot")
    preview = preview_exception(
        session, exc_id=exc_id, snapshot_id=new_snapshot_id,
        at=as_utc(exc.starts_at))
    if preview["signature"] != signature:
        raise Conflict("stale preview: semantic impact changed; fetch a new "
                       "preview and confirm that one")
    if seen_witness_count != len(preview["witnesses"]):
        raise Conflict("witness set changed since preview; re-review required")

    old = exc.baseline_snapshot_id
    exc.baseline_snapshot_id = new_snapshot_id
    exc.needs_review = False
    exc.review_reason = ""
    _record_event(session, exc, "reconfirmed", _now(), exc.status, exc.status,
                  {"old_snapshot_id": old, "new_snapshot_id": new_snapshot_id})
    session.commit()
    session.refresh(exc)
    return exc


# --------------------------------------------------------------------------
# Effective classification
# --------------------------------------------------------------------------

def classify_effective(session: Session, policy_id: int, prefix: str,
                       at: Optional[dt.datetime] = None,
                       snapshot_id: Optional[int] = None) -> dict:
    at = as_utc(at or _now())
    composed = effective_at(session, policy_id, at=at, snapshot_id=snapshot_id)
    hit = effective_classify(composed, prefix)
    d = hit.to_dict()
    d["at"] = at.isoformat()
    d["baseline_snapshot_id"] = (
        snapshot_id or _latest_snapshot(session, policy_id).id)
    return d


# --------------------------------------------------------------------------
# Serialization
# --------------------------------------------------------------------------

def exception_dict(exc: dbmod.PolicyException,
                   events: Optional[List[dbmod.ExceptionEvent]] = None) -> dict:
    return {
        "id": exc.id, "policy_id": exc.policy_id, "name": exc.name,
        "baseline_snapshot_id": exc.baseline_snapshot_id,
        "family": exc.family, "prefix": exc.prefix,
        "ge": exc.ge, "le": exc.le, "action": exc.action,
        "priority": exc.priority,
        "starts_at": as_utc(exc.starts_at).isoformat(),
        "ends_at": as_utc(exc.ends_at).isoformat(),
        "reason": exc.reason, "requested_by": exc.requested_by,
        "approved_by": exc.approved_by,
        "approved_at": as_utc(exc.approved_at).isoformat() if exc.approved_at else None,
        "status": exc.status,
        "needs_review": exc.needs_review, "review_reason": exc.review_reason,
        "created_at": as_utc(exc.created_at).isoformat() if exc.created_at else None,
        "events": ([event_dict(e) for e in events] if events is not None else []),
    }


def event_dict(ev: dbmod.ExceptionEvent) -> dict:
    return {
        "id": ev.id, "exception_id": ev.exception_id,
        "event_type": ev.event_type,
        "from_status": ev.from_status, "to_status": ev.to_status,
        "at_time": as_utc(ev.at_time).isoformat(),
        "detail": ev.detail,
        "created_at": as_utc(ev.created_at).isoformat(),
    }


def list_events(session: Session, exc_id: Optional[int] = None) -> List[dict]:
    q = select(dbmod.ExceptionEvent)
    if exc_id is not None:
        q = q.where(dbmod.ExceptionEvent.exception_id == exc_id)
    q = q.order_by(dbmod.ExceptionEvent.at_time, dbmod.ExceptionEvent.id)
    return [event_dict(e) for e in session.scalars(q)]
