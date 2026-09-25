"""HTTP API for time-bounded policy exceptions."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import clock, db as dbmod
from .. import exceptions_service as xs
from ..engine import PolicyError
from ..frr_bridge import FRRUnavailable
from ..schemas import (
    ActorIn, ApproveIn, AtIn, BaselinePublishIn, CrossValidateEffectiveIn,
    ExceptionIn, ExceptionPatchIn, ReviewIn, RevokeIn, TickIn,
)
from ..validate import cross_validate

router = APIRouter(prefix="/api")


def get_db():
    s = dbmod.SessionLocal()
    try:
        yield s
    finally:
        s.close()


# ------------------------------------------------------------ lab clock
class ClockIn(TickIn):
    pass


@router.get("/clock")
def get_clock_state():
    from ..clock import FixedClock
    c = clock.get_clock()
    return {"mode": "fixed" if isinstance(c, FixedClock) else "system",
            "now": c.now().isoformat()}


@router.post("/clock/freeze")
def clock_freeze(body: ClockIn):
    """Install a fixed clock (lab/test only) at `at` or the current time."""
    t = _at(body.at) if body.at else clock.now()
    fixed = clock.freeze(t)
    return {"mode": "fixed", "now": fixed.now().isoformat()}


class ClockAdvanceIn(TickIn):
    seconds: float = 0.0


@router.post("/clock/advance")
def clock_advance(body: ClockAdvanceIn, db: Session = Depends(get_db)):
    """Advance a fixed clock by `seconds` (or set it to `at`) and catch up."""
    import datetime as _dt
    from ..clock import FixedClock
    c = clock.get_clock()
    if not isinstance(c, FixedClock):
        raise HTTPException(409, "clock is system clock; freeze it first")
    if body.at:
        c.set(xs.parse_dt(body.at))
    elif body.seconds:
        c.advance(_dt.timedelta(seconds=body.seconds))
    tick = xs.run_due_ticks(db, at=c.now())
    return {"mode": "fixed", "now": c.now().isoformat(), "tick": tick}


@router.post("/clock/reset")
def clock_reset():
    clock.reset_clock()
    return {"mode": "system", "now": clock.now().isoformat()}


def _at(raw: str | None) -> dt.datetime | None:
    return xs.parse_dt(raw) if raw else None


def _get(db: Session, model, obj_id: int, what: str):
    obj = db.get(model, obj_id)
    if obj is None:
        raise HTTPException(404, f"{what} {obj_id} not found")
    return obj


def _err(e: Exception) -> HTTPException:
    if isinstance(e, xs.ExceptionConflict):
        return HTTPException(409, str(e))
    return HTTPException(422, str(e))


# ------------------------------------------------------------ baseline
@router.post("/policies/{pid}/baseline/publish", status_code=201)
def publish_baseline(pid: int, body: BaselinePublishIn,
                     db: Session = Depends(get_db)):
    pol = _get(db, dbmod.Policy, pid, "policy")
    try:
        snap = xs.publish_baseline(
            db, pol.id, label=body.label, created_by=body.created_by)
    except (xs.ExceptionError, PolicyError, ValueError) as e:
        raise _err(e)
    from ..service import snapshot_dict
    return snapshot_dict(snap)


@router.get("/policies/{pid}/baseline")
def get_baseline(pid: int, db: Session = Depends(get_db)):
    pol = _get(db, dbmod.Policy, pid, "policy")
    if pol.baseline_snapshot_id is None:
        return {"policy_id": pid, "baseline_snapshot_id": None}
    from ..service import snapshot_dict
    return snapshot_dict(db.get(dbmod.Snapshot, pol.baseline_snapshot_id))


# ------------------------------------------------------------ exceptions CRUD
@router.get("/policies/{pid}/exceptions")
def list_exceptions(pid: int, db: Session = Depends(get_db)):
    _get(db, dbmod.Policy, pid, "policy")
    rows = db.scalars(
        select(dbmod.PolicyException)
        .where(dbmod.PolicyException.policy_id == pid)
        .order_by(dbmod.PolicyException.id)
    ).all()
    return [xs.exception_dict(db, e) for e in rows]


@router.post("/policies/{pid}/exceptions", status_code=201)
def create_exception(pid: int, body: ExceptionIn,
                     db: Session = Depends(get_db)):
    try:
        ex = xs.create_exception(
            db, pid, name=body.name, action=body.action,
            start_at=body.start_at, end_at=body.end_at,
            matches=[m.model_dump() for m in body.matches],
            reason=body.reason, priority=body.priority,
            requested_by=body.requested_by, snapshot_id=body.snapshot_id)
    except (xs.ExceptionError, PolicyError, ValueError) as e:
        raise _err(e)
    return xs.exception_dict(db, ex)


@router.get("/exceptions/{eid}")
def get_exception(eid: int, db: Session = Depends(get_db)):
    ex = _get(db, dbmod.PolicyException, eid, "exception")
    return xs.exception_dict(db, ex)


@router.patch("/exceptions/{eid}")
def patch_exception(eid: int, body: ExceptionPatchIn,
                    db: Session = Depends(get_db)):
    changes = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        ex = xs.update_draft(db, eid, changes)
    except (xs.ExceptionError, xs.ExceptionConflict, PolicyError, ValueError) as e:
        raise _err(e)
    return xs.exception_dict(db, ex)


@router.delete("/exceptions/{eid}", status_code=204)
def delete_exception(eid: int, db: Session = Depends(get_db)):
    try:
        xs.delete_exception(db, eid)
    except (xs.ExceptionError, xs.ExceptionConflict) as e:
        raise _err(e)


# ------------------------------------------------------------ lifecycle
@router.post("/exceptions/{eid}/submit")
def submit_exception(eid: int, body: ActorIn, db: Session = Depends(get_db)):
    try:
        ex = xs.submit(db, eid, actor=body.actor)
    except (xs.ExceptionError, xs.ExceptionConflict) as e:
        raise _err(e)
    return xs.exception_dict(db, ex)


@router.post("/exceptions/{eid}/approve")
def approve_exception(eid: int, body: ApproveIn, db: Session = Depends(get_db)):
    try:
        ex = xs.approve(db, eid, approver=body.approver, at=_at(body.at))
    except (xs.ExceptionError, xs.ExceptionConflict) as e:
        raise _err(e)
    return xs.exception_dict(db, ex)


@router.post("/exceptions/{eid}/review")
def review_exception(eid: int, body: ReviewIn, db: Session = Depends(get_db)):
    try:
        ex = xs.confirm_review(db, eid, reviewer=body.reviewer, at=_at(body.at))
    except (xs.ExceptionError, xs.ExceptionConflict, PolicyError) as e:
        raise _err(e)
    return xs.exception_dict(db, ex)


@router.post("/exceptions/{eid}/revoke")
def revoke_exception(eid: int, body: RevokeIn, db: Session = Depends(get_db)):
    try:
        ex = xs.revoke(db, eid, actor=body.actor, reason=body.reason)
    except (xs.ExceptionError, xs.ExceptionConflict) as e:
        raise _err(e)
    return xs.exception_dict(db, ex)


@router.post("/exceptions/{eid}/activate")
def activate_exception(eid: int, body: TickIn, db: Session = Depends(get_db)):
    try:
        ex = xs.activate(db, eid, at=_at(body.at))
    except (xs.ExceptionError, PolicyError) as e:
        raise _err(e)
    return xs.exception_dict(db, ex)


@router.post("/exceptions/{eid}/expire")
def expire_exception(eid: int, body: TickIn, db: Session = Depends(get_db)):
    try:
        ex = xs.expire(db, eid, at=_at(body.at))
    except (xs.ExceptionError, PolicyError) as e:
        raise _err(e)
    return xs.exception_dict(db, ex)


@router.get("/exceptions/{eid}/history")
def exception_history(eid: int, db: Session = Depends(get_db)):
    try:
        return xs.event_history(db, eid)
    except xs.ExceptionError as e:
        raise _err(e)


@router.post("/exceptions/tick")
def tick_all(body: TickIn, db: Session = Depends(get_db)):
    """Manually run the idempotent activation/expiry catch-up."""
    return xs.run_due_ticks(db, at=_at(body.at) or clock.now())


# ------------------------------------------------------------ views / preview
@router.get("/exceptions/{eid}/preview")
def preview_exception(eid: int, baseline_snapshot_id: int | None = None,
                      db: Session = Depends(get_db)):
    ex = _get(db, dbmod.PolicyException, eid, "exception")
    try:
        return xs.preview_exception(db, ex, baseline_snapshot_id)
    except (xs.ExceptionError, PolicyError) as e:
        raise _err(e)


@router.get("/policies/{pid}/effective")
def effective_policy(pid: int, at: str | None = None,
                     db: Session = Depends(get_db)):
    try:
        return xs.effective_view(db, pid, at=_at(at) or clock.now())
    except (xs.ExceptionError, xs.ExceptionConflict, PolicyError) as e:
        raise _err(e)


class EffectiveClassifyIn(AtIn):
    prefix: str


@router.post("/policies/{pid}/effective/classify")
def effective_classify(pid: int, body: EffectiveClassifyIn,
                       db: Session = Depends(get_db)):
    try:
        return xs.enriched_classify(
            db, pid, body.prefix, at=_at(body.at) or clock.now())
    except (xs.ExceptionError, PolicyError, ValueError) as e:
        raise _err(e)


@router.get("/policies/{pid}/timeline")
def policy_timeline(pid: int, at: str | None = None,
                    db: Session = Depends(get_db)):
    try:
        return xs.timeline(db, pid, at=_at(at) or clock.now())
    except xs.ExceptionError as e:
        raise _err(e)


@router.post("/policies/{pid}/effective/cross-validate")
def cross_validate_effective(pid: int, body: CrossValidateEffectiveIn,
                             db: Session = Depends(get_db)):
    """
    Install the CURRENT synthesized config (baseline + active exceptions) in
    the isolated local FRR node and compare each probe with the simulator.
    The prefix-list is removed afterwards.
    """
    try:
        composed, seq_map, excs, snap = xs.composed_policy_at(
            db, pid, at=_at(body.at) or clock.now(),
            name=f"xc-p{pid}")
        result = cross_validate(composed, body.probes, node=body.node)
    except FRRUnavailable as e:
        raise HTTPException(503, str(e))
    except (xs.ExceptionError, PolicyError, ValueError) as e:
        raise _err(e)
    # translate dense FRR seq numbers back to layer owners
    for row in result["rows"]:
        row["sim_owner"] = seq_map.get(row["sim_seq"])
        row["frr_owner"] = seq_map.get(row["frr_seq"])
    run = dbmod.Run(
        snapshot_id=snap.id, node=body.node, status=result["status"],
        detail={"kind": "effective", "policy_id": pid,
                "active_exception_ids": [e.id for e in excs],
                "mismatch_count": result["mismatch_count"],
                "probes": body.probes, "mismatches": result["mismatches"],
                "setup_error": result.get("setup_error")})
    db.add(run)
    db.commit()
    result["run_id"] = run.id
    result["baseline_snapshot_id"] = snap.id
    result["active_exception_ids"] = [e.id for e in excs]
    return result
