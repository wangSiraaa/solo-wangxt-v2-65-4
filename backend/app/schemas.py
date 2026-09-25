"""Pydantic request/response schemas."""
from __future__ import annotations

import datetime as dt
from typing import List, Optional

from pydantic import BaseModel, Field


class RuleIn(BaseModel):
    seq: int = Field(ge=1, le=4294967295)
    prefix: str
    action: str = Field(pattern="^(permit|deny)$")
    ge: Optional[int] = Field(default=None, ge=0, le=128)
    le: Optional[int] = Field(default=None, ge=0, le=128)
    remark: str = ""


class PolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    family: int = Field(default=4, ge=4, le=6)
    default_action: str = Field(default="deny", pattern="^(permit|deny)$")
    description: str = ""


class PolicyRulesIn(BaseModel):
    rules: List[RuleIn]
    default_action: Optional[str] = Field(default=None, pattern="^(permit|deny)$")


class SnapshotIn(BaseModel):
    label: str = ""
    created_by: str = "lab"


class ClassifyIn(BaseModel):
    prefix: str


class ProbesIn(BaseModel):
    probes: List[str]
    node: str = "a"
    install: bool = True


class DiffIn(BaseModel):
    old_snapshot_id: int
    new_snapshot_id: int


class ScenarioIn(BaseModel):
    name: str
    description: str = ""
    from_snapshot_id: Optional[int] = None
    to_snapshot_id: Optional[int] = None
    probes: List[str] = []


class NeighborIn(BaseModel):
    name: str
    ip: str
    family: int = 4
    asn: Optional[int] = None
    inbound_policy: Optional[str] = None
    outbound_policy: Optional[str] = None
    description: str = ""


# ------------------------------------------------------- timed exceptions
class ExceptionIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    prefix: str
    action: str = Field(pattern="^(permit|deny)$")
    ge: Optional[int] = Field(default=None, ge=0, le=128)
    le: Optional[int] = Field(default=None, ge=0, le=128)
    priority: int = Field(default=100, ge=0, le=1_000_000)
    starts_at: dt.datetime
    ends_at: dt.datetime
    reason: str = ""
    requested_by: str = "lab"
    baseline_snapshot_id: Optional[int] = None


class ExceptionPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    prefix: Optional[str] = None
    action: Optional[str] = Field(default=None, pattern="^(permit|deny)$")
    ge: Optional[int] = Field(default=None, ge=0, le=128)
    le: Optional[int] = Field(default=None, ge=0, le=128)
    priority: Optional[int] = Field(default=None, ge=0, le=1_000_000)
    starts_at: Optional[dt.datetime] = None
    ends_at: Optional[dt.datetime] = None
    reason: Optional[str] = None
    requested_by: Optional[str] = None


class ApproveIn(BaseModel):
    approver: str = "approver"
    at: Optional[dt.datetime] = None


class RejectIn(BaseModel):
    note: str = ""


class RevokeIn(BaseModel):
    note: str = ""
    at: Optional[dt.datetime] = None


class EventAtIn(BaseModel):
    at: Optional[dt.datetime] = None


class SweepIn(BaseModel):
    at: Optional[dt.datetime] = None


class ExceptionPreviewIn(BaseModel):
    at: Optional[dt.datetime] = None
    snapshot_id: Optional[int] = None
    candidate: Optional[ExceptionIn] = None


class EffectiveIn(BaseModel):
    probes: List[str]
    at: Optional[dt.datetime] = None
    snapshot_id: Optional[int] = None
    node: str = "a"


class EffectiveClassifyIn(BaseModel):
    prefix: str
    at: Optional[dt.datetime] = None
    snapshot_id: Optional[int] = None


class ReconfirmIn(BaseModel):
    snapshot_id: int
    signature: str
    witness_count: int = Field(ge=0)


class ClockIn(BaseModel):
    at: Optional[dt.datetime] = None
    reset: bool = False
