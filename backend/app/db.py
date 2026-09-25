"""SQLAlchemy models: neighbors, policies + ordered rules, snapshots, runs."""
from __future__ import annotations

import datetime as dt
from typing import List

from sqlalchemy import (
    JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, TypeDecorator,
    UniqueConstraint, create_engine, inspect, select, text,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session,
)

from .config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


class TZDateTime(TypeDecorator):
    """
    Timezone-aware UTC datetimes on every backend (SQLite drops tzinfo on
    store; DateTime(timezone=True) helps PostgreSQL, this normalizes reads).
    """
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Neighbor(Base):
    __tablename__ = "neighbors"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    ip: Mapped[str] = mapped_column(String(64))
    family: Mapped[int] = mapped_column(Integer, default=4)
    asn: Mapped[int] = mapped_column(Integer, nullable=True)
    inbound_policy: Mapped[str | None] = mapped_column(String(128), nullable=True)
    outbound_policy: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[dt.datetime] = mapped_column(TZDateTime, default=utcnow)


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    family: Mapped[int] = mapped_column(Integer, default=4)       # 4 or 6
    default_action: Mapped[str] = mapped_column(String(8), default="deny")
    description: Mapped[str] = mapped_column(String(256), default="")
    draft: Mapped[bool] = mapped_column(Boolean, default=True)
    # The currently active, immutable baseline snapshot. Exceptions bind to a
    # snapshot id (not to mutable live rules); publishing a new baseline moves
    # this pointer while old snapshots stay untouched.
    baseline_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(TZDateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        TZDateTime, default=utcnow, onupdate=utcnow)

    rules: Mapped[List["Rule"]] = relationship(
        back_populates="policy",
        cascade="all, delete-orphan",
        order_by="Rule.seq",
    )
    snapshots: Mapped[List["Snapshot"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan",
        order_by="Snapshot.version.desc()",
        foreign_keys="Snapshot.policy_id",
    )
    baseline_snapshot: Mapped["Snapshot | None"] = relationship(
        foreign_keys=[baseline_snapshot_id])
    exceptions: Mapped[List["PolicyException"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan",
        order_by="PolicyException.id",
    )


class Rule(Base):
    __tablename__ = "rules"
    __table_args__ = (UniqueConstraint("policy_id", "seq", name="uq_policy_seq"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)
    prefix: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(8))                  # permit/deny
    ge: Mapped[int | None] = mapped_column(Integer, nullable=True)
    le: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remark: Mapped[str] = mapped_column(String(256), default="")

    policy: Mapped[Policy] = relationship(back_populates="rules")


class Snapshot(Base):
    """
    Immutable configuration snapshot.  payload is the exact, replayable
    policy body: ordered rules + default action + family, plus FRR-rendered
    config and metadata.  Replays never depend on later edits.
    """
    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    label: Mapped[str] = mapped_column(String(128), default="")
    payload: Mapped[dict] = mapped_column(JSON)
    frr_config: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(TZDateTime, default=utcnow)
    created_by: Mapped[str] = mapped_column(String(64), default="lab")

    policy: Mapped[Policy] = relationship(
        back_populates="snapshots", foreign_keys=[policy_id])
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_version"),)


class Scenario(Base):
    """Saved replay bundle: from/to snapshots, probe inputs, observed results."""
    __tablename__ = "scenarios"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    from_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    to_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    probes: Mapped[list] = mapped_column(JSON, default=list)   # ordered prefix list
    results: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(TZDateTime, default=utcnow)


class Run(Base):
    """One cross-validation run against a local FRR container."""
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    node: Mapped[str] = mapped_column(String(16), default="a")      # router-a/b
    status: Mapped[str] = mapped_column(String(16), default="ok")   # ok/mismatch/error
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(TZDateTime, default=utcnow)


# ---------------------------------------------------------------------------
# Time-bounded policy exceptions
# ---------------------------------------------------------------------------

class PolicyException(Base):
    """
    A time-bounded permit/deny exception layered ON TOP of an immutable
    baseline snapshot. Baseline rules are never modified: synthesis evaluates
    the baseline first and lets active exception entries override it only
    inside their match scope and validity window.

    Lifecycle (see exceptions_service):
        draft -> pending -> scheduled -> active -> expired
        any pre-terminal state -> revoked
    When the policy's baseline pointer moves to a newer snapshot, every
    not-yet-effective exception is marked needs_review and must be
    re-previewed and explicitly confirmed against the new baseline before it
    can schedule/activate.
    """
    __tablename__ = "policy_exceptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(128))
    family: Mapped[int] = mapped_column(Integer)                      # 4 | 6
    # Immutable baseline binding (snapshot payload self-contained; the row is
    # never rewritten). If the snapshot itself is deleted the exception
    # becomes un-synthesizable and is flagged, not rebound silently.
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"))
    # Match scope: one or more (prefix, ge, le) entries, same geometry as
    # rules; stored as an ordered JSON list.
    matches: Mapped[list] = mapped_column(JSON, default=list)
    action: Mapped[str] = mapped_column(String(8))                    # permit/deny
    priority: Mapped[int] = mapped_column(Integer, default=100)
    start_at: Mapped[dt.datetime] = mapped_column(TZDateTime)
    end_at: Mapped[dt.datetime] = mapped_column(TZDateTime)
    reason: Mapped[str] = mapped_column(String(512), default="")
    requested_by: Mapped[str] = mapped_column(String(64), default="lab")

    status: Mapped[str] = mapped_column(String(16), default="draft")
    # draft|pending|scheduled|active|expired|revoked
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[dt.datetime | None] = mapped_column(TZDateTime, nullable=True)
    # set once the exception has actually been active (first ACTIVATED event);
    # an "activate" arriving after that must be a no-op, never resurrecting.
    activated_at: Mapped[dt.datetime | None] = mapped_column(TZDateTime, nullable=True)
    expires_at: Mapped[dt.datetime | None] = mapped_column(TZDateTime, nullable=True)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(TZDateTime, nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # set when the policy baseline pointer moved before this took effect
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False)
    reviewed_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    reviewed_at: Mapped[dt.datetime | None] = mapped_column(TZDateTime, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # cached preview (witness set) at review time, for the UI/audit
    review_preview: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[dt.datetime] = mapped_column(TZDateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow)

    policy: Mapped[Policy] = relationship(back_populates="exceptions")
    snapshot: Mapped[Snapshot] = relationship(foreign_keys=[snapshot_id])


class ExceptionEvent(Base):
    """
    Append-only history of exception lifecycle events.

    Exactly-once guarantee: ``idem_key`` is unique. Terminal/lifecycle events
    get a fixed key per exception ("<id>:ACTIVATED", "<id>:EXPIRED",
    "<id>:REVOKED", ...) so duplicated or late/out-of-order ticks — including
    catch-up expiry after a process restart — can never insert a second
    history row. Per-target events key additionally on the target snapshot
    (BASELINE_STALED:<snap>, REVIEWED:<snap>) so repeated baseline changes and
    re-reviews are each recorded exactly once.
    """
    __tablename__ = "exception_events"
    __table_args__ = (
        UniqueConstraint("idem_key", name="uq_exception_event_idem"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    exception_id: Mapped[int] = mapped_column(
        ForeignKey("policy_exceptions.id", ondelete="CASCADE"), index=True)
    # CREATED|SUBMITTED|APPROVED|SCHEDULED|ACTIVATED|EXPIRED|REVOKED|
    # BASELINE_STALED|REVIEWED
    event_type: Mapped[str] = mapped_column(String(24))
    idem_key: Mapped[str] = mapped_column(String(96))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    actor: Mapped[str] = mapped_column(String(64), default="lab")
    # effective time of the transition per the injected clock; also guards
    # "a late timer must not resurrect an old exception".
    occurred_at: Mapped[dt.datetime] = mapped_column(TZDateTime)
    # wall-clock insert time (system UTC), purely diagnostic.
    recorded_at: Mapped[dt.datetime] = mapped_column(TZDateTime, default=utcnow)


def init_db() -> None:
    Base.metadata.create_all(engine)
    _lightweight_migrate()


# Columns added after the first release; create_all handles fresh DBs, and
# these ALTERs upgrade an existing SQLite/PostgreSQL lab database in place.
_ADDED_COLUMNS = {
    "policies": [("baseline_snapshot_id", "INTEGER")],
}


def _lightweight_migrate() -> None:
    with engine.begin() as conn:
        inspector = inspect(conn)
        existing_tables = set(inspector.get_table_names())
        for table, cols in _ADDED_COLUMNS.items():
            if table not in existing_tables:
                continue
            have = {c["name"] for c in inspector.get_columns(table)}
            for name, sqltype in cols:
                if name not in have:
                    conn.execute(text(
                        f"ALTER TABLE {table} ADD COLUMN {name} {sqltype}"))


def get_session() -> Session:
    return SessionLocal()
