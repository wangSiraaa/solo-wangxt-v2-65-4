"""HTTP API for time-bounded policy exceptions."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import db as dbmod, exception_service as es
from ..clock import as_utc, clock
from ..engine import PolicyError
from ..frr_bridge import FRRUnavailable
from ..schemas import (
    ApproveIn, ClockIn, EffectiveClassifyIn, EffectiveIn, EventAtIn,
    ExceptionIn, ExceptionPatch, ExceptionPreviewIn, ReconfirmIn, RejectIn,
    RevokeIn, SweepIn,
)
from ..validate import cross_validate_effective

router = APIRouter(prefix="/api")


def get_db():
    s = dbmod.SessionLocal()
    try:
        yield s
    finally:
        s.close()


def _get_exc(db: Session, exc_id: int) -> dbmod.PolicyException:
    exc = db.get(dbmod.PolicyException, exc_id)
    if exc is None:
        raise HTTPException(404, f"exception {exc_id} not found")
    return exc


def _parse_at(raw):
    if raw is None:
        return None
    try:
        return as_utc(raw if isinstance(raw, dt.datetime)
                      else dt.datetime.fromisoformat(raw))
    except ValueError:
        raise HTTPException(422, f"bad datetime {raw!r}")


def _error(e):
    if isinstance(e, es.ValidationError):
        return HTTPException(404 if "not found" in str(e) else 422, str(e))
    if isinstance(e, es.Conflict):
        return HTTPException(409, str(e))
    if isinstance(e, PolicyError):
        return HTTPException(422, str(e))
    return HTTPException(400, str(e))


# -------------------------------------------------------------------- clock
@router.get("/clock")
def get_clock():
    return {"now": clock.now().isoformat(),
            "override": clock.override.isoformat() if clock.override else None,
            "real": clock.override is None}


@router.post("/clock")
def set_clock(body: ClockIn):
    if body.reset:
        clock.reset()
    else:
        clock.set(body.at)
    return {"now": clock.now().isoformat(),
            "override": clock.override.isoformat() if clock.override else None}


# ---------------------------------------------------------------- exceptions
@router.get("/policies/{pid}/exceptions")
def list_for_policy(pid: int, db: Session = Depends(get_db)):
    if db.get(dbmod.Policy, pid) is None:
        raise HTTPException(404, "policy not found")
    rows = db.scalars(
        select(dbmod.PolicyException)
        .where(dbmod.PolicyException.policy_id == pid)
        .order_by(dbmod.PolicyException.starts_at, dbmod.PolicyException.id)).all()
    out = []
    for r in rows:
        d = es.exception_dict(r)
        d["events"] = es.list_events(db, r.id)
        out.append(d)
    return out


@router.get("/exceptions")
def list_all(status: str | None = None, db: Session = Depends(get_db)):
    q = select(dbmod.PolicyException).order_by(
        dbmod.PolicyException.starts_at, dbmod.PolicyException.id)
    if status:
        q = q.where(dbmod.PolicyException.status == status)
    return [es.exception_dict(r) for r in db.scalars(q)]


@router.post("/policies/{pid}/exceptions", status_code=201)
def create(pid: int, body: ExceptionIn, db: Session = Depends(get_db)):
    try:
        exc = es.create_exception(
            db, pid, body.model_dump(),
            baseline_snapshot_id=body.baseline_snapshot_id)
    except Exception as e:  # noqa: BLE001 - mapped below
        raise _error(e)
    d = es.exception_dict(exc)
    d["events"] = es.list_events(db, exc.id)
    return d


@router.get("/exceptions/{exc_id}")
def get_one(exc_id: int, db: Session = Depends(get_db)):
    exc = _get_exc(db, exc_id)
    d = es.exception_dict(exc)
    d["events"] = es.list_events(db, exc_id)
    return d


@router.patch("/exceptions/{exc_id}")
def edit(exc_id: int, body: ExceptionPatch, db: Session = Depends(get_db)):
    try:
        exc = es.update_draft(db, exc_id,
                              {k: v for k, v in body.model_dump().items()
                               if v is not None})
    except Exception as e:  # noqa: BLE001
        raise _error(e)
    d = es.exception_dict(exc)
    d["events"] = es.list_events(db, exc_id)
    return d


@router.post("/exceptions/{exc_id}/submit")
def submit(exc_id: int, db: Session = Depends(get_db)):
    try:
        exc = es.submit(db, exc_id)
    except Exception as e:  # noqa: BLE001
        raise _error(e)
    return es.exception_dict(exc)


@router.post("/exceptions/{exc_id}/approve")
def approve(exc_id: int, body: ApproveIn, db: Session = Depends(get_db)):
    try:
        exc = es.approve(db, exc_id, approver=body.approver,
                         now=_parse_at(body.at))
    except Exception as e:  # noqa: BLE001
        raise _error(e)
    return es.exception_dict(exc)


@router.post("/exceptions/{exc_id}/reject")
def reject(exc_id: int, body: RejectIn, db: Session = Depends(get_db)):
    try:
        exc = es.reject(db, exc_id, note=body.note)
    except Exception as e:  # noqa: BLE001
        raise _error(e)
    return es.exception_dict(exc)


@router.post("/exceptions/{exc_id}/revise")
def revise(exc_id: int, db: Session = Depends(get_db)):
    exc = _get_exc(db, exc_id)
    try:
        es._transition(db, exc, "revise")
        db.commit()
        db.refresh(exc)
    except Exception as e:  # noqa: BLE001
        raise _error(e)
    return es.exception_dict(exc)


@router.post("/exceptions/{exc_id}/activate")
def activate(exc_id: int, body: EventAtIn, db: Session = Depends(get_db)):
    try:
        return es.activate(db, exc_id, at=_parse_at(body.at))
    except Exception as e:  # noqa: BLE001
        raise _error(e)


@router.post("/exceptions/{exc_id}/expire")
def expire(exc_id: int, body: EventAtIn, db: Session = Depends(get_db)):
    try:
        return es.expire(db, exc_id, at=_parse_at(body.at))
    except Exception as e:  # noqa: BLE001
        raise _error(e)


@router.post("/exceptions/{exc_id}/revoke")
def revoke(exc_id: int, body: RevokeIn, db: Session = Depends(get_db)):
    try:
        return es.revoke(db, exc_id, at=_parse_at(body.at), note=body.note)
    except Exception as e:  # noqa: BLE001
        raise _error(e)


@router.get("/exceptions/{exc_id}/events")
def events(exc_id: int, db: Session = Depends(get_db)):
    _get_exc(db, exc_id)
    return es.list_events(db, exc_id)


# ------------------------------------------------------------ preview etc.
@router.get("/exceptions/{exc_id}/preview")
def preview_get(exc_id: int, at: str | None = None,
                snapshot_id: int | None = None, db: Session = Depends(get_db)):
    try:
        return es.preview_exception(
            db, exc_id=exc_id, at=_parse_at(at), snapshot_id=snapshot_id)
    except Exception as e:  # noqa: BLE001
        raise _error(e)


@router.post("/policies/{pid}/exceptions/preview")
def preview_post(pid: int, body: ExceptionPreviewIn,
                 db: Session = Depends(get_db)):
    if body.candidate is None:
        raise HTTPException(422, "candidate body required")
    try:
        return es.preview_exception(
            db, policy_id=pid, candidate=body.candidate.model_dump(),
            at=_parse_at(body.at), snapshot_id=body.snapshot_id)
    except Exception as e:  # noqa: BLE001
        raise _error(e)


@router.post("/exceptions/{exc_id}/reconfirm")
def reconfirm(exc_id: int, body: ReconfirmIn, db: Session = Depends(get_db)):
    _get_exc(db, exc_id)
    try:
        exc = es.reconfirm(db, exc_id, body.snapshot_id, body.signature,
                           body.witness_count)
    except Exception as e:  # noqa: BLE001
        raise _error(e)
    d = es.exception_dict(exc)
    d["events"] = es.list_events(db, exc_id)
    return d


# ------------------------------------------------------ effective policy
@router.get("/policies/{pid}/effective")
def effective(pid: int, at: str | None = None,
              snapshot_id: int | None = None, db: Session = Depends(get_db)):
    try:
        composed = es.effective_at(
            db, pid, at=_parse_at(at), snapshot_id=snapshot_id)
    except Exception as e:  # noqa: BLE001
        raise _error(e)
    return {
        "policy_id": pid,
        "at": (_parse_at(at) or clock.now()).isoformat(),
        "active_exceptions": [
            {"id": s.id, "name": s.name, "prefix": s.prefix,
             "action": s.action.value, "ge": s.ge, "le": s.le,
             "priority": s.priority}
            for s in composed.exceptions],
        "frr_config": composed.policy.to_frr_prefix_list(),
        "seq_map": {str(k): v for k, v in composed.seq_map.items()},
        "default_action": composed.policy.default_action.value,
    }


@router.post("/policies/{pid}/effective/classify")
def effective_classify_endpoint(pid: int, body: EffectiveClassifyIn,
                                 db: Session = Depends(get_db)):
    try:
        return es.classify_effective(
            db, pid, body.prefix, at=_parse_at(body.at),
            snapshot_id=body.snapshot_id)
    except Exception as e:  # noqa: BLE001
        raise _error(e)


@router.post("/policies/{pid}/effective/cross-validate")
def effective_cv(pid: int, body: EffectiveIn, db: Session = Depends(get_db)):
    at = _parse_at(body.at)
    try:
        composed = es.effective_at(
            db, pid, at=at, snapshot_id=body.snapshot_id)
        return cross_validate_effective(
            db, composed, body.probes, node=body.node,
            at_iso=(at or clock.now()).isoformat(),
            snapshot_id=body.snapshot_id)
    except FRRUnavailable as e:
        raise HTTPException(503, str(e))
    except Exception as e:  # noqa: BLE001
        raise _error(e)


# ------------------------------------------------------------- sweep timer
@router.post("/exceptions/sweep/run")
def run_sweep(body: SweepIn, db: Session = Depends(get_db)):
    return es.sweep(db, now=_parse_at(body.at))
