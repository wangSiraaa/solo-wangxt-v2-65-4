"""
Time-bounded policy exceptions: lifecycle, idempotent transitions, baseline
binding, priority-based composition and semantic preview.

Design summary
--------------
* An exception NEVER modifies baseline rules. It binds to an immutable
  Snapshot (id + family + match scope + window + priority + action).
* Synthesis evaluates the BASELINE policy first and layers active exception
  entries on top; the first match in order
      baseline seqs asc, then exception (priority asc, exception id asc)
  wins. Overlapping exceptions therefore have one total, deterministic order.
* Lifecycle:  draft -> pending -> scheduled -> active -> expired
                   ^            ^ any pre-terminal -> revoked
  When the policy's baseline pointer moves, pending/scheduled exceptions are
  flagged needs_review and must be re-previewed + confirmed against the new
  baseline before they may activate ("旧策略不被覆盖").
* Transitions ACTIVATED / EXPIRED / REVOKED are idempotent (conditional
  single-row state gate + fixed idempotency key). A late ACTIVATE after
  expiry, a repeated EXPIRE after a restart catch-up, a duplicate REVOKE —
  none changes the terminal state and none inserts a second history row.
"""
from __future__ import annotations

import datetime as dt
from typing import Iterable, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import clock, db as dbmod
from .engine import (
    Action, Policy as EnginePolicy, Rule as EngineRule, PolicyError,
    policy_from_dicts,
)

DRAFT = "draft"
PENDING = "pending"
SCHEDULED = "scheduled"
ACTIVE = "active"
EXPIRED = "expired"
REVOKED = "revoked"
PRE_EFFECTIVE = (PENDING, SCHEDULED)
TERMINAL = (EXPIRED, REVOKED)

# event types
E_CREATED = "CREATED"
E_SUBMITTED = "SUBMITTED"
E_APPROVED = "APPROVED"
E_SCHEDULED = "SCHEDULED"
E_ACTIVATED = "ACTIVATED"
E_EXPIRED = "EXPIRED"
E_REVOKED = "REVOKED"
E_STALED = "BASELINE_STALED"
E_REVIEWED = "REVIEWED"


class ExceptionError(ValueError):
    """Bad input (4xx validation)."""


class ExceptionConflict(RuntimeError):
    """Illegal lifecycle transition (HTTP 409)."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def aware(t: dt.datetime) -> dt.datetime:
    if t.tzinfo is None:
        return t.replace(tzinfo=dt.timezone.utc)
    return t.astimezone(dt.timezone.utc)


def parse_dt(v: str | dt.datetime) -> dt.datetime:
    if isinstance(v, dt.datetime):
        return aware(v)
    try:
        s = str(v).strip().replace("Z", "+00:00")
        return aware(dt.datetime.fromisoformat(s))
    except ValueError as e:
        raise ExceptionError(f"bad timestamp {v!r}: {e}")


def _iso(t: Optional[dt.datetime]) -> Optional[str]:
    return aware(t).isoformat() if t is not None else None


def validate_matches(family: int, matches: List[dict]) -> List[dict]:
    """Parse every match scope entry through ipaddress/engine geometry."""
    if not matches:
        raise ExceptionError("exception needs at least one match scope")
    out = []
    for i, m in enumerate(matches):
        try:
            r = EngineRule(
                seq=i + 1, prefix=str(m["prefix"]).strip(),
                action=Action(m.get("action", "permit")),
                ge=m.get("ge"), le=m.get("le"),
            )
        except (PolicyError, ValueError, KeyError) as e:
            raise ExceptionError(f"match #{i + 1}: {e}")
        if r.family != family:
            raise ExceptionError(
                f"match #{i + 1} {r.prefix} is IPv{r.family} but exception is "
                f"IPv{family}; families must not be mixed")
        out.append({"prefix": r.prefix, "ge": r.ge, "le": r.le})
    return out


def _get_policy(session: Session, policy_id: int) -> dbmod.Policy:
    p = session.get(dbmod.Policy, policy_id)
    if p is None:
        raise ExceptionError(f"policy {policy_id} not found")
    return p


def _get_exc(session: Session, exc_id: int) -> dbmod.PolicyException:
    ex = session.get(dbmod.PolicyException, exc_id)
    if ex is None:
        raise ExceptionError(f"exception {exc_id} not found")
    return ex


def _record_event(session: Session, ex: dbmod.PolicyException,
                  event_type: str, idem_key: str, detail: dict | None = None,
                  actor: str = "lab", at: Optional[dt.datetime] = None
                  ) -> Optional[dbmod.ExceptionEvent]:
    """
    Insert a history row iff its idempotency key is unused. Returns the row
    (new or pre-existing) so callers can tell a genuine transition from a
    repeated delivery.
    """
    key = idem_key
    existing = session.scalar(
        select(dbmod.ExceptionEvent).where(
            dbmod.ExceptionEvent.idem_key == key))
    if existing is not None:
        return existing
    ev = dbmod.ExceptionEvent(
        exception_id=ex.id, event_type=event_type, idem_key=key,
        detail=detail or {}, actor=actor,
        occurred_at=at if at is not None else clock.now(),
    )
    session.add(ev)
    session.flush()
    return ev


def _guard(ex: dbmod.PolicyException, allowed: Iterable[str], what: str):
    if ex.status not in allowed:
        raise ExceptionConflict(
            f"{what}: exception {ex.id} is {ex.status}; allowed from "
            f"{sorted(allowed)}")


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def create_exception(session: Session, policy_id: int, *, name: str,
                     action: str, start_at, end_at, matches: List[dict],
                     reason: str = "", requested_by: str = "lab",
                     priority: int = 100,
                     snapshot_id: Optional[int] = None
                     ) -> dbmod.PolicyException:
    pol = _get_policy(session, policy_id)
    if action not in ("permit", "deny"):
        raise ExceptionError("action must be permit/deny")
    start = parse_dt(start_at)
    end = parse_dt(end_at)
    if not start < end:
        raise ExceptionError("start_at must be strictly before end_at")

    snap_id = snapshot_id or pol.baseline_snapshot_id
    if snap_id is None:
        raise ExceptionError(
            "policy has no immutable baseline snapshot; publish a baseline first")
    snap = session.get(dbmod.Snapshot, snap_id)
    if snap is None or snap.policy_id != pol.id:
        raise ExceptionError(
            f"snapshot {snap_id} does not belong to policy {pol.id}")
    if snap.payload.get("family") != pol.family:
        raise ExceptionError("baseline snapshot family mismatch")

    norm_matches = validate_matches(pol.family, matches)

    ex = dbmod.PolicyException(
        policy_id=pol.id, name=name[:128], family=pol.family,
        snapshot_id=snap.id, matches=norm_matches, action=action,
        priority=int(priority), start_at=start, end_at=end,
        reason=reason[:512], requested_by=requested_by[:64],
        status=DRAFT,
    )
    session.add(ex)
    session.flush()
    _record_event(session, ex, E_CREATED, f"{ex.id}:CREATED",
                  actor=requested_by, at=clock.now())
    session.commit()
    session.refresh(ex)
    return ex


def update_draft(session: Session, exc_id: int, changes: dict,
                 actor: str = "lab") -> dbmod.PolicyException:
    ex = _get_exc(session, exc_id)
    _guard(ex, (DRAFT,), "edit")
    if "name" in changes:
        ex.name = str(changes["name"])[:128]
    if "reason" in changes:
        ex.reason = str(changes["reason"])[:512]
    if "priority" in changes:
        ex.priority = int(changes["priority"])
    if "action" in changes and changes["action"] in ("permit", "deny"):
        ex.action = changes["action"]
    times = {}
    if "start_at" in changes:
        times["start"] = parse_dt(changes["start_at"])
    if "end_at" in changes:
        times["end"] = parse_dt(changes["end_at"])
    new_start = times.get("start", aware(ex.start_at))
    new_end = times.get("end", aware(ex.end_at))
    if not new_start < new_end:
        raise ExceptionError("start_at must be strictly before end_at")
    ex.start_at, ex.end_at = new_start, new_end
    if changes.get("matches"):
        ex.matches = validate_matches(ex.family, changes["matches"])
    session.commit()
    session.refresh(ex)
    return ex


def delete_exception(session: Session, exc_id: int) -> None:
    ex = _get_exc(session, exc_id)
    _guard(ex, (DRAFT,), "delete")
    session.delete(ex)
    session.commit()


# ---------------------------------------------------------------------------
# lifecycle transitions (manual)
# ---------------------------------------------------------------------------

def submit(session: Session, exc_id: int, actor: str = "lab"
           ) -> dbmod.PolicyException:
    ex = _get_exc(session, exc_id)
    _guard(ex, (DRAFT,), "submit")
    pol = session.get(dbmod.Policy, ex.policy_id)
    ex.status = PENDING
    # submitted against a baseline that is already superseded -> review now
    if pol.baseline_snapshot_id != ex.snapshot_id:
        ex.needs_review = True
        _record_event(
            session, ex, E_STALED,
            f"{ex.id}:{E_STALED}:{pol.baseline_snapshot_id}",
            {"bound_snapshot_id": ex.snapshot_id,
             "current_snapshot_id": pol.baseline_snapshot_id}, actor=actor)
    _record_event(session, ex, E_SUBMITTED, f"{ex.id}:SUBMITTED", actor=actor)
    session.commit()
    session.refresh(ex)
    return ex


def approve(session: Session, exc_id: int, approver: str = "approver",
            at: Optional[dt.datetime] = None) -> dbmod.PolicyException:
    """
    pending -> scheduled (future window) | active (window already open).

    Idempotent: if an APPROVED event already exists the call is a no-op and
    never emits a duplicate. Approval is refused while needs_review is set.
    """
    at = at or clock.now()
    ex = _get_exc(session, exc_id)
    # Idempotent: a prior approval makes the call a no-op and never emits a
    # duplicate event or flips an already-approved exception.
    already = session.scalar(
        select(dbmod.ExceptionEvent).where(
            dbmod.ExceptionEvent.idem_key == f"{ex.id}:APPROVED"))
    if already is not None:
        session.rollback()
        return session.get(dbmod.PolicyException, exc_id)
    _guard(ex, (PENDING,), "approve")
    if ex.needs_review:
        raise ExceptionConflict(
            f"approve: exception {ex.id} must be re-reviewed against the "
            "current baseline snapshot first")
    if aware(ex.end_at) <= at:
        raise ExceptionConflict(
            f"approve: exception {ex.id} window already ended at "
            f"{aware(ex.end_at).isoformat()}")
    ex.approved_by, ex.approved_at = approver[:64], at
    _record_event(session, ex, E_APPROVED, f"{ex.id}:APPROVED",
                  actor=approver, at=at)
    if aware(ex.start_at) <= at:
        ex.status = ACTIVE
        ex.activated_at = at
        _record_event(session, ex, E_ACTIVATED, f"{ex.id}:ACTIVATED",
                      actor=approver, at=at)
    else:
        ex.status = SCHEDULED
        _record_event(session, ex, E_SCHEDULED, f"{ex.id}:SCHEDULED",
                      actor=approver, at=at)
    session.commit()
    session.refresh(ex)
    return ex


def confirm_review(session: Session, exc_id: int, reviewer: str = "reviewer",
                   at: Optional[dt.datetime] = None) -> dbmod.PolicyException:
    """
    Re-preview against the CURRENT baseline and confirm the old exception may
    still take effect. The bound snapshot is never mutated; reviewed_snapshot
    records which baseline the human re-checked.
    """
    at = at or clock.now()
    ex = _get_exc(session, exc_id)
    _guard(ex, (PENDING, SCHEDULED), "review confirmation")
    pol = session.get(dbmod.Policy, ex.policy_id)
    cur_base = pol.baseline_snapshot_id
    if cur_base is None:
        raise ExceptionConflict("policy has no current baseline snapshot")
    if cur_base == ex.snapshot_id and not ex.needs_review:
        raise ExceptionConflict("exception is bound to the current baseline; "
                                "no review required")
    preview = preview_exception(session, ex, baseline_snapshot_id=cur_base)
    ex.needs_review = False
    ex.reviewed_snapshot_id = cur_base
    ex.reviewed_at, ex.reviewed_by = at, reviewer[:64]
    ex.review_preview = {
        "baseline_snapshot_id": cur_base,
        "witness_count": preview["witness_count"],
        "witnesses": preview["witnesses"],
    }
    _record_event(
        session, ex, E_REVIEWED, f"{ex.id}:REVIEWED:{cur_base}",
        {"baseline_snapshot_id": cur_base,
         "witness_count": preview["witness_count"]}, actor=reviewer, at=at)
    session.commit()
    session.refresh(ex)
    # the window may have opened (or passed) while the exception waited:
    # apply due transitions immediately, idempotently.
    activate(session, ex.id, at=at)
    session.refresh(ex)
    expire(session, ex.id, at=at)
    session.refresh(ex)
    return ex


def revoke(session: Session, exc_id: int, actor: str = "operator",
           reason: str = "") -> dbmod.PolicyException:
    """
    Revoke from any pre-terminal state. Idempotent: revoking an already
    revoked exception changes nothing and emits no second history row.
    Revoking an expired exception is also a no-op (never reopens it).
    """
    at = clock.now()
    ex = _get_exc(session, exc_id)
    if ex.status in TERMINAL:
        return ex
    _guard(ex, (DRAFT, PENDING, SCHEDULED, ACTIVE), "revoke")
    ex.status = REVOKED
    ex.revoked_at, ex.revoked_by = at, actor[:64]
    if reason:
        ex.reason = (ex.reason + f" | revoked: {reason}")[:512]
    _record_event(session, ex, E_REVOKED, f"{ex.id}:REVOKED",
                  {"reason": reason}, actor=actor, at=at)
    session.commit()
    session.refresh(ex)
    return ex


# ---------------------------------------------------------------------------
# clock-driven transitions: activate / expire (idempotent catch-up)
# ---------------------------------------------------------------------------

def activate(session: Session, exc_id: int,
             at: Optional[dt.datetime] = None) -> dbmod.PolicyException:
    """
    scheduled -> active when start <= at < end.

    Idempotent / late-timer safe:
      * already active  -> no-op, no event
      * expired/revoked -> no-op (a late activate never resurrects)
      * at >= end       -> expires instead (catch-up via expire())
      * needs_review    -> stays scheduled (must be confirmed first)
    """
    at = at or clock.now()
    ex = _get_exc(session, exc_id)
    if ex.status != SCHEDULED:
        return ex                       # active/terminal: idempotent no-op
    if ex.needs_review:
        return ex                       # blocked pending human re-review
    if at < aware(ex.start_at):
        return ex                       # timer early; still in the future
    if at >= aware(ex.end_at):
        session.commit()
        return expire(session, exc_id, at=at)
    ex.status = ACTIVE
    ex.activated_at = at
    _record_event(session, ex, E_ACTIVATED, f"{ex.id}:ACTIVATED", at=at)
    session.commit()
    session.refresh(ex)
    return ex


def expire(session: Session, exc_id: int,
           at: Optional[dt.datetime] = None) -> dbmod.PolicyException:
    """
    scheduled|active -> expired when at >= end.

    Idempotent / out-of-order safe: already expired (or revoked) -> no-op and
    no second EXPIRED history row, even when the catch-up runs twice across a
    process restart.
    """
    at = at or clock.now()
    ex = _get_exc(session, exc_id)
    if ex.status not in (SCHEDULED, ACTIVE):
        return ex                       # expired/revoked/draft/pending: no-op
    if at < aware(ex.end_at):
        return ex                       # timer early
    ex.status = EXPIRED
    ex.expires_at = at
    _record_event(session, ex, E_EXPIRED, f"{ex.id}:EXPIRED", at=at)
    session.commit()
    session.refresh(ex)
    return ex


def run_due_ticks(session: Session,
                  at: Optional[dt.datetime] = None) -> dict:
    """
    Catch up ALL due activations/expiries for the injected time ``at``
    (default clock.now()). Called on API startup and by the scheduler; safe
    to run any number of times in any order.
    """
    at = at or clock.now()
    activated, expired, blocked = [], [], []
    candidates = session.scalars(
        select(dbmod.PolicyException).where(
            dbmod.PolicyException.status.in_([SCHEDULED, ACTIVE]))
    ).all()
    for ex in candidates:
        before = ex.status
        if before == ACTIVE:
            out = expire(session, ex.id, at=at)
            if out.status == EXPIRED:
                expired.append(ex.id)
            continue
        # scheduled
        if ex.needs_review:
            blocked.append(ex.id)
            continue
        if at >= aware(ex.end_at):
            expire(session, ex.id, at=at)
            expired.append(ex.id)
        elif at >= aware(ex.start_at):
            activate(session, ex.id, at=at)
            activated.append(ex.id)
    return {"at": aware(at).isoformat(), "activated": activated,
            "expired": expired, "review_blocked": blocked}


# ---------------------------------------------------------------------------
# baseline publication / superseding
# ---------------------------------------------------------------------------

def publish_baseline(session: Session, policy_id: int, label: str = "",
                     created_by: str = "lab") -> dbmod.Snapshot:
    """
    Freeze current live rules into a new immutable snapshot and move the
    policy baseline pointer. Pre-effective exceptions (pending/scheduled)
    bound to the previous baseline become needs_review and must be
    re-previewed + confirmed; active/terminal ones keep their bound baseline
    and are not disturbed.
    """
    pol = _get_policy(session, policy_id)
    snap = service_create_snapshot(session, pol, label=label,
                                   created_by=created_by)
    pol.baseline_snapshot_id = snap.id
    session.flush()
    stale = session.scalars(
        select(dbmod.PolicyException).where(
            dbmod.PolicyException.policy_id == pol.id,
            dbmod.PolicyException.status.in_(list(PRE_EFFECTIVE)),
            dbmod.PolicyException.snapshot_id != snap.id,
        )
    ).all()
    for ex in stale:
        if not ex.needs_review or ex.reviewed_snapshot_id != snap.id:
            ex.needs_review = True
            _record_event(
                session, ex, E_STALED, f"{ex.id}:{E_STALED}:{snap.id}",
                {"bound_snapshot_id": ex.snapshot_id,
                 "current_snapshot_id": snap.id},
                actor=created_by, at=clock.now())
    session.commit()
    session.refresh(snap)
    return snap


def service_create_snapshot(session, pol, **kw):
    # local import avoids a circular import at module load
    from . import service
    return service.create_snapshot(session, pol, **kw)


# ---------------------------------------------------------------------------
# composition: baseline + active exceptions
# ---------------------------------------------------------------------------

def _engine_policy_from_snap(snap: dbmod.Snapshot,
                             name: Optional[str] = None) -> EnginePolicy:
    p = snap.payload
    return policy_from_dicts(
        name=name or p["name"], rules=p["rules"],
        default_action=p["default_action"], family=p["family"],
    )


def active_exceptions(session: Session, policy_id: int,
                      at: dt.datetime) -> List[dbmod.PolicyException]:
    """
    Exceptions effectively active at instant ``at`` against the CURRENT
    baseline: approved (scheduled/active rows), window open, not revoked and
    not blocked awaiting baseline re-review.
    """
    out = []
    rows = session.scalars(
        select(dbmod.PolicyException)
        .where(dbmod.PolicyException.policy_id == policy_id)
        .order_by(dbmod.PolicyException.priority.asc(),
                  dbmod.PolicyException.id.asc())
    ).all()
    for ex in rows:
        if ex.status not in (SCHEDULED, ACTIVE):
            continue
        if ex.needs_review:
            continue
        if aware(ex.start_at) <= at < aware(ex.end_at):
            out.append(ex)
    return out


def compose(baseline: EnginePolicy,
            exceptions: List[dbmod.PolicyException],
            name: Optional[str] = None
            ) -> tuple[EnginePolicy, dict]:
    """
    Layer exception entries ON TOP of the baseline WITHOUT mutating it.

    The synthesized (and FRR-installed) order is total and deterministic:

        1. exception entries, by (priority asc, exception id asc, match idx)
        2. baseline rules in their original seq order

    Exceptions come FIRST because FRR prefix-lists (and this engine) use
    first-match: appending an override after a baseline rule that already
    matches would make the override unreachable. The baseline rules remain in
    the list unchanged and still decide every prefix the overlay does not
    cover; the implicit default is untouched. Dense 1..N seq numbers keep the
    rendered config FRR-safe while ``seq_map`` records each entry's identity.
    """
    rules: List[EngineRule] = []
    seq_map: dict = {}
    dense = 0
    for ex in sorted(exceptions, key=lambda e: (e.priority, e.id)):
        for m in ex.matches:
            dense += 1
            rules.append(EngineRule(
                seq=dense, prefix=m["prefix"], action=Action(ex.action),
                ge=m.get("ge"), le=m.get("le"),
                remark=f"exception#{ex.id} {ex.name}"))
            seq_map[dense] = {"layer": "exception", "exception_id": ex.id,
                              "name": ex.name, "priority": ex.priority,
                              "action": ex.action}
    for r in baseline.rules:
        dense += 1
        rules.append(EngineRule(
            seq=dense, prefix=r.prefix, action=r.action, ge=r.ge, le=r.le,
            remark=r.remark, id=r.id))
        seq_map[dense] = {"layer": "baseline", "orig_seq": r.seq,
                          "rule_id": r.id}
    fam = baseline.family
    composed = EnginePolicy(
        name=name or f"{baseline.name}-composed", rules=rules,
        default_action=baseline.default_action, family=fam)
    return composed, seq_map


def composed_policy_at(session: Session, policy_id: int,
                       at: Optional[dt.datetime] = None,
                       name: Optional[str] = None
                       ) -> tuple[EnginePolicy, dict, List[dbmod.PolicyException],
                                  dbmod.Snapshot]:
    pol = _get_policy(session, policy_id)
    if pol.baseline_snapshot_id is None:
        raise ExceptionError("policy has no baseline snapshot")
    at = at or clock.now()
    snap = session.get(dbmod.Snapshot, pol.baseline_snapshot_id)
    baseline = _engine_policy_from_snap(snap)
    excs = active_exceptions(session, policy_id, at)
    composed, seq_map = compose(baseline, excs, name=name)
    return composed, seq_map, excs, snap


def enriched_classify(session: Session, policy_id: int, prefix: str,
                      at: Optional[dt.datetime] = None) -> dict:
    """Final hit chain for one prefix, labelling baseline vs exception layer."""
    at = at or clock.now()
    composed, seq_map, excs, snap = composed_policy_at(
        session, policy_id, at=at)
    hit = composed.classify(prefix).to_dict()
    for e in hit["chain"]:
        e["layer"] = seq_map.get(e["seq"], {}).get("layer", "default")
        e["owner"] = seq_map.get(e["seq"])
    if hit["matched_seq"] is not None:
        hit["matched_layer"] = seq_map[hit["matched_seq"]]["layer"]
        hit["matched_owner"] = seq_map[hit["matched_seq"]]
    else:
        hit["matched_layer"] = "default"
        hit["matched_owner"] = None
    hit["at"] = aware(at).isoformat()
    hit["baseline_snapshot_id"] = snap.id
    hit["active_exception_ids"] = [e.id for e in excs]
    return hit


def preview_exception(session: Session, ex: dbmod.PolicyException,
                      baseline_snapshot_id: Optional[int] = None) -> dict:
    """
    Semantic impact of layering ONE (possibly not-yet-approved) exception
    onto a baseline: minimal witness prefixes where the composed decision
    differs from baseline — not a text diff. Defaults to the exception's
    BOUND snapshot; review uses the policy's CURRENT baseline.
    """
    snap_id = baseline_snapshot_id or ex.snapshot_id
    snap = session.get(dbmod.Snapshot, snap_id)
    if snap is None or snap.policy_id != ex.policy_id:
        raise ExceptionError(f"snapshot {snap_id} unavailable for preview")
    baseline = _engine_policy_from_snap(snap)
    composed, seq_map = compose(baseline, [ex])
    witnesses = [w.to_dict() for w in baseline.witness_diff(composed)]
    for w in witnesses:
        new_seq = w["new_seq"]
        if new_seq is not None and seq_map.get(new_seq, {}).get("layer") == "exception":
            w["decided_by"] = {"type": "exception", "exception_id": ex.id,
                               "priority": ex.priority}
        else:
            w["decided_by"] = {"type": "baseline", "seq": new_seq}
    return {
        "exception_id": ex.id,
        "baseline_snapshot_id": snap_id,
        "bound_snapshot_id": ex.snapshot_id,
        "baseline_is_current": snap_id == session.get(
            dbmod.Policy, ex.policy_id).baseline_snapshot_id,
        "witness_count": len(witnesses),
        "witnesses": witnesses,
        "composed_frr_config": composed.to_frr_prefix_list(),
    }


def effective_view(session: Session, policy_id: int,
                   at: Optional[dt.datetime] = None) -> dict:
    """Current (or at-time) synthesized policy: config, witnesses, chain meta."""
    at = at or clock.now()
    pol = _get_policy(session, policy_id)
    composed, seq_map, excs, snap = composed_policy_at(
        session, policy_id, at=at,
        name=f"xc-p{pol.id}")
    baseline = _engine_policy_from_snap(snap)
    witnesses = [w.to_dict() for w in baseline.witness_diff(composed)]
    return {
        "policy_id": pol.id, "at": aware(at).isoformat(),
        "baseline_snapshot_id": snap.id,
        "active_exceptions": [exception_brief(e) for e in excs],
        "frr_config": composed.to_frr_prefix_list(),
        "seq_map": {str(k): v for k, v in seq_map.items()},
        "witness_count": len(witnesses),
        "witnesses": witnesses,
    }


# ---------------------------------------------------------------------------
# timeline
# ---------------------------------------------------------------------------

def timeline(session: Session, policy_id: int,
             at: Optional[dt.datetime] = None) -> dict:
    """
    Deterministic projection of every exception across its lifecycle plus the
    effective sets at each window boundary, so the UI can render a timeline
    and the semantic impact at every change point — without mutating state.
    """
    pol = _get_policy(session, policy_id)
    nowt = at or clock.now()
    rows = session.scalars(
        select(dbmod.PolicyException)
        .where(dbmod.PolicyException.policy_id == policy_id)
        .order_by(dbmod.PolicyException.id)
    ).all()
    events = session.scalars(
        select(dbmod.ExceptionEvent)
        .join(dbmod.PolicyException,
              dbmod.PolicyException.id == dbmod.ExceptionEvent.exception_id)
        .where(dbmod.PolicyException.policy_id == policy_id)
        .order_by(dbmod.ExceptionEvent.occurred_at.asc(),
                  dbmod.ExceptionEvent.id.asc())
    ).all()

    boundary_set = sorted({aware(nowt)} | {b for ex in rows for b in
                          (aware(ex.start_at), aware(ex.end_at))})

    def active_at(ex, t):
        if ex.status not in (SCHEDULED, ACTIVE):
            return False
        if ex.needs_review:
            return False
        return aware(ex.start_at) <= t < aware(ex.end_at)

    boundaries = []
    for t in boundary_set:
        ids = [ex.id for ex in rows if active_at(ex, t)]
        boundaries.append({"at": t.isoformat(), "active_exception_ids": ids})

    return {
        "policy_id": policy_id,
        "now": aware(nowt).isoformat(),
        "current_baseline_snapshot_id": pol.baseline_snapshot_id,
        "exceptions": [exception_dict(session, ex, now=nowt) for ex in rows],
        "events": [
            {"id": ev.id, "exception_id": ev.exception_id,
             "event_type": ev.event_type, "detail": ev.detail,
             "actor": ev.actor, "occurred_at": _iso(ev.occurred_at),
             "recorded_at": _iso(ev.recorded_at)}
            for ev in events
        ],
        "boundaries": boundaries,
    }


def event_history(session: Session, exc_id: int) -> List[dict]:
    ex = _get_exc(session, exc_id)
    evs = session.scalars(
        select(dbmod.ExceptionEvent)
        .where(dbmod.ExceptionEvent.exception_id == exc_id)
        .order_by(dbmod.ExceptionEvent.occurred_at.asc(),
                  dbmod.ExceptionEvent.id.asc())
    ).all()
    return [
        {"id": ev.id, "event_type": ev.event_type, "detail": ev.detail,
         "actor": ev.actor, "occurred_at": _iso(ev.occurred_at),
         "recorded_at": _iso(ev.recorded_at)}
        for ev in evs
    ]


# ---------------------------------------------------------------------------
# serialization
# ---------------------------------------------------------------------------

def projected_status(ex: dbmod.PolicyException,
                     now: Optional[dt.datetime] = None) -> str:
    """What the state WOULD be at ``now`` without writing anything."""
    now = now or clock.now()
    s = ex.status
    if s in (DRAFT, PENDING, EXPIRED, REVOKED):
        return s
    if ex.needs_review:
        return s            # scheduled stays scheduled but flagged blocked
    if now >= aware(ex.end_at):
        return EXPIRED
    if s == SCHEDULED and now >= aware(ex.start_at):
        return ACTIVE
    return s


def exception_brief(ex: dbmod.PolicyException) -> dict:
    return {"id": ex.id, "name": ex.name, "action": ex.action,
            "priority": ex.priority, "start_at": _iso(ex.start_at),
            "end_at": _iso(ex.end_at)}


def exception_dict(session: Session, ex: dbmod.PolicyException,
                   now: Optional[dt.datetime] = None) -> dict:
    now = now or clock.now()
    pol = session.get(dbmod.Policy, ex.policy_id)
    return {
        "id": ex.id,
        "policy_id": ex.policy_id,
        "name": ex.name,
        "family": ex.family,
        "snapshot_id": ex.snapshot_id,
        "baseline_is_current": pol.baseline_snapshot_id == ex.snapshot_id,
        "current_baseline_snapshot_id": pol.baseline_snapshot_id,
        "matches": ex.matches,
        "action": ex.action,
        "priority": ex.priority,
        "start_at": _iso(ex.start_at),
        "end_at": _iso(ex.end_at),
        "reason": ex.reason,
        "requested_by": ex.requested_by,
        "status": ex.status,
        "projected_status": projected_status(ex, now),
        "approved_by": ex.approved_by,
        "approved_at": _iso(ex.approved_at),
        "activated_at": _iso(ex.activated_at),
        "expires_at": _iso(ex.expires_at),
        "revoked_at": _iso(ex.revoked_at),
        "revoked_by": ex.revoked_by,
        "needs_review": ex.needs_review,
        "reviewed_snapshot_id": ex.reviewed_snapshot_id,
        "reviewed_at": _iso(ex.reviewed_at),
        "reviewed_by": ex.reviewed_by,
        "review_preview": ex.review_preview or None,
        "created_at": _iso(ex.created_at),
        "updated_at": _iso(ex.updated_at),
    }
