"""Pydantic request/response schemas."""
from __future__ import annotations

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


# ----------------------------------------------------------- time exceptions
class MatchScopeIn(BaseModel):
    prefix: str
    ge: Optional[int] = Field(default=None, ge=0, le=128)
    le: Optional[int] = Field(default=None, ge=0, le=128)


class ExceptionIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    action: str = Field(pattern="^(permit|deny)$")
    start_at: str            # ISO-8601, UTC preferred
    end_at: str
    matches: List[MatchScopeIn]
    reason: str = ""
    priority: int = Field(default=100, ge=1, le=10_000_000)
    requested_by: str = "lab"
    snapshot_id: Optional[int] = None


class ExceptionPatchIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    action: Optional[str] = Field(default=None, pattern="^(permit|deny)$")
    start_at: Optional[str] = None
    end_at: Optional[str] = None
    matches: Optional[List[MatchScopeIn]] = None
    reason: Optional[str] = None
    priority: Optional[int] = Field(default=None, ge=1, le=10_000_000)


class ActorIn(BaseModel):
    actor: str = "lab"
    at: Optional[str] = None


class ApproveIn(BaseModel):
    approver: str = "approver"
    at: Optional[str] = None


class ReviewIn(BaseModel):
    reviewer: str = "reviewer"
    at: Optional[str] = None


class RevokeIn(BaseModel):
    actor: str = "operator"
    reason: str = ""
    at: Optional[str] = None


class AtIn(BaseModel):
    at: Optional[str] = None


class TickIn(BaseModel):
    at: Optional[str] = None


class BaselinePublishIn(BaseModel):
    label: str = ""
    created_by: str = "lab"


class CrossValidateEffectiveIn(BaseModel):
    probes: List[str]
    node: str = "a"
    at: Optional[str] = None
