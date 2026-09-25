"""
Time-bounded exception composition engine (pure: no DB, no clock).

An *exception* is a temporary, explicitly prioritized override over an
immutable baseline Policy. The baseline rules are NEVER modified: a composed
policy is a fresh engine Policy whose ordered rules are

    [active exception rules, in explicit precedence order]
    + [baseline rules, with virtualized seqs]

so FRR's first-match semantics directly implement the precedence. Overlapping
exceptions resolve via a total, deterministic ordering
``priority_key`` — there is never a tie.

This module provides:

* ExceptionSpec           parsed/validated one override (reuses engine.Rule)
* priority_key            explicit total order for overlaps
* compose_policy          baseline + active exceptions -> new Policy (no
                          mutation of the baseline), with a virtual-seq map
* effective_classify      layered hit chain: exception layer + full baseline
                          chain (so the UI can show what is being overridden)
* overlap_witnesses       pairwise overlap regions with a minimal witness
                          prefix and the deterministic winner
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .engine import (
    Action, ChainEntry, HitResult, Policy, PolicyError, Rule,
    policy_from_dicts,
)

# Virtual seq layout inside the composed list. Exceptions take the low seq
# band in precedence order; baseline rules keep their relative order in a
# high band (FRR seq max is 2^32-1, so these stay well inside it).
EXC_SEQ_STEP = 10
BASELINE_SEQ_BASE = 1_000_000


@dataclass(frozen=True)
class ExceptionSpec:
    """One active (or previewed) exception's match scope + decision."""
    id: Optional[int]
    name: str
    prefix: str
    action: Action
    ge: Optional[int] = None
    le: Optional[int] = None
    priority: int = 100
    # ---- derived ----
    rule: Rule = field(default=None, compare=False, repr=False)  # type: ignore

    def __post_init__(self):
        r = Rule(seq=1, prefix=self.prefix, action=self.action,
                 ge=self.ge, le=self.le, remark=f"exception:{self.name}")
        # Rule canonicalizes prefix; keep the canonical form too.
        if r.prefix != self.prefix:
            object.__setattr__(self, "prefix", r.prefix)
        object.__setattr__(self, "rule", r)

    @property
    def family(self) -> int:
        return self.rule.family


def priority_key(spec: ExceptionSpec) -> Tuple:
    """
    Explicit total ordering for overlapping exceptions.

    Higher ``priority`` wins; on equal priority the more SPECIFIC scope wins
    (longest base prefix, then wider ge floor / tighter le cap), then the
    smallest id (creation order) as the final deterministic tiebreak. Pending
    specs without an id sort before committed ones only during preview.
    """
    r = spec.rule
    return (
        -spec.priority,
        -r.net.prefixlen,
        -(r.min_len or 0),
        (r.max_len or 0),
        spec.id if spec.id is not None else -1,
    )


def order_exceptions(specs: List[ExceptionSpec]) -> List[ExceptionSpec]:
    return sorted(specs, key=priority_key)


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------

@dataclass
class ComposedPolicy:
    policy: Policy                          # exceptions first, baseline after
    baseline: Policy
    exceptions: List[ExceptionSpec]         # in precedence order
    # virtual seq -> ("exception"|"baseline", source id/seq)
    seq_map: Dict[int, dict]

    def source_of(self, seq: Optional[int]) -> Optional[dict]:
        return self.seq_map.get(seq) if seq is not None else None


def compose_policy(baseline: Policy,
                   exceptions: List[ExceptionSpec],
                   name: Optional[str] = None) -> ComposedPolicy:
    """
    Build the effective policy. Baseline rules are copied with virtualized
    seqs; nothing mutates ``baseline``. Family mixing is rejected.
    """
    fam = baseline.family
    ordered = order_exceptions(exceptions)
    for s in ordered:
        if fam is not None and s.family != fam:
            raise PolicyError(
                f"exception {s.name!r} is IPv{s.family} but baseline is "
                f"IPv{fam}: address families must not be mixed"
            )

    seq_map: Dict[int, dict] = {}
    rule_dicts: List[dict] = []

    for i, spec in enumerate(ordered):
        vseq = (i + 1) * EXC_SEQ_STEP
        seq_map[vseq] = {"layer": "exception", "exception_id": spec.id,
                         "name": spec.name, "priority": spec.priority}
        rule_dicts.append({
            "seq": vseq, "prefix": spec.prefix, "action": spec.action.value,
            "ge": spec.ge, "le": spec.le, "remark": f"exception:{spec.name}",
        })

    for r in baseline.rules:
        vseq = BASELINE_SEQ_BASE + r.seq
        seq_map[vseq] = {"layer": "baseline", "seq": r.seq,
                         "rule_id": r.id, "prefix": r.prefix}
        rule_dicts.append({
            "seq": vseq, "prefix": r.prefix, "action": r.action.value,
            "ge": r.ge, "le": r.le, "remark": r.remark,
        })

    eff_name = name or f"{baseline.name}-effective"
    composed = policy_from_dicts(
        eff_name, rule_dicts,
        default_action=baseline.default_action.value, family=fam,
    )
    return ComposedPolicy(composed, baseline, ordered, seq_map)


# ---------------------------------------------------------------------------
# Layered hit chain
# ---------------------------------------------------------------------------

@dataclass
class EffectiveHit:
    prefix: str
    final_action: Action
    # chain entries over EXCEPTIONS only (containment/window per exception)
    exception_chain: List[dict]
    winning_exception: Optional[ExceptionSpec]
    # the baseline's own decision, even when an exception overrides it
    baseline_hit: HitResult
    terminal: str                          # "exception" | "rule" | "default"

    def to_dict(self) -> dict:
        return {
            "prefix": self.prefix,
            "family": self.baseline_hit.family,
            "final_action": self.final_action.value,
            "terminal": self.terminal,
            "winning_exception": (
                None if self.winning_exception is None
                else {
                    "id": self.winning_exception.id,
                    "name": self.winning_exception.name,
                    "prefix": self.winning_exception.prefix,
                    "action": self.winning_exception.action.value,
                    "ge": self.winning_exception.ge, "le": self.winning_exception.le,
                    "priority": self.winning_exception.priority,
                }
            ),
            "exception_chain": self.exception_chain,
            "baseline_action": self.baseline_hit.final_action.value,
            "baseline_terminal": self.baseline_hit.terminal,
            "baseline_matched_seq": (
                self.baseline_hit.rule.seq if self.baseline_hit.rule else None),
            "baseline_chain": [_chain_entry(e) for e in self.baseline_hit.chain],
            "overridden": (
                self.winning_exception is not None
                and self.winning_exception.action != self.baseline_hit.final_action
            ),
        }


def _chain_entry(e: ChainEntry) -> dict:
    return {
        "seq": e.seq, "rule_id": e.rule_id, "prefix": e.prefix,
        "action": e.action.value, "ge": e.ge, "le": e.le,
        "contained": e.contained, "length_ok": e.length_ok,
        "matched": e.matched, "reason": e.reason,
    }


def effective_classify(composed: ComposedPolicy, prefix: str) -> EffectiveHit:
    """
    Evaluate one prefix against exceptions (explicit precedence) and record
    the full baseline chain for comparison. Raises on family mismatch.
    """
    cand = ipaddress.ip_network(prefix, strict=True)
    base = composed.baseline
    if base.family is not None and cand.version != base.family:
        raise PolicyError(
            f"{prefix} is IPv{cand.version} but policy is IPv{base.family}: "
            "address families must not be mixed"
        )

    chain: List[dict] = []
    winner: Optional[ExceptionSpec] = None
    for rank, spec in enumerate(composed.exceptions):
        r = spec.rule
        contained = r.contains(cand)
        length_ok = r.length_covers(cand.prefixlen)
        matched = contained and length_ok
        if not contained:
            reason = "no-containment: candidate outside exception scope"
        elif not length_ok:
            reason = "containment-only: prefix length out of ge/le window"
        else:
            reason = "match"
        chain.append({
            "rank": rank, "exception_id": spec.id, "name": spec.name,
            "prefix": spec.prefix, "action": spec.action.value,
            "ge": spec.ge, "le": spec.le, "priority": spec.priority,
            "contained": contained, "length_ok": length_ok,
            "matched": matched, "reason": reason,
        })
        if matched and winner is None:
            # exceptions are already in precedence order: first match wins
            winner = spec

    baseline_hit = base.classify(prefix)
    if winner is not None:
        final, terminal = winner.action, "exception"
    elif baseline_hit.rule is not None:
        final, terminal = baseline_hit.final_action, "rule"
    else:
        final, terminal = baseline_hit.final_action, "default"
    return EffectiveHit(
        prefix=str(cand), final_action=final,
        exception_chain=chain, winning_exception=winner,
        baseline_hit=baseline_hit, terminal=terminal,
    )


# ---------------------------------------------------------------------------
# Overlap analysis with minimal witness prefixes
# ---------------------------------------------------------------------------

@dataclass
class OverlapWitness:
    winner_id: Optional[int]
    loser_id: Optional[int]
    winner_name: str
    loser_name: str
    prefix: str
    winner_action: Action
    loser_action: Action
    conflicting: bool

    def to_dict(self) -> dict:
        return {
            "winner_id": self.winner_id, "loser_id": self.loser_id,
            "winner_name": self.winner_name, "loser_name": self.loser_name,
            "prefix": self.prefix,
            "winner_action": self.winner_action.value,
            "loser_action": self.loser_action.value,
            "conflicting": self.conflicting,
            "resolution": (
                f"{self.winner_name!r} (priority order) overrides "
                f"{self.loser_name!r}"
            ),
        }


def _scope_intersection(a: ExceptionSpec, b: ExceptionSpec) -> Optional[Rule]:
    """A rule whose match region is exactly scope(a) ∩ scope(b), or None."""
    ra, rb = a.rule, b.rule
    if ra.family != rb.family:
        return None
    # address intersection
    if ra.net.subnet_of(rb.net):
        net = ra.net
    elif rb.net.subnet_of(ra.net):
        net = rb.net
    else:
        return None
    base_len = net.prefixlen
    ge = max(ra.min_len, rb.min_len)
    le = min(ra.max_len, rb.max_len)
    if ge > le:
        return None
    # Rule needs ge > base_len; normalize ge=base_len to unset
    ge_arg = ge if ge > base_len else None
    le_arg = le if le >= base_len else None
    # if the deeper base enforces a min above the shallower's base_len,
    # that is captured by base_len itself; keep le only when > base_len.
    le_arg = le if le > base_len else None
    try:
        return Rule(seq=1, prefix=str(net), action=Action.PERMIT,
                    ge=ge_arg, le=le_arg)
    except PolicyError:
        return None


def _minimal_prefix_in(rule: Rule) -> str:
    """Shallowest prefix that matches the given scope rule."""
    return f"{rule.net.network_address}/{rule.min_len}"


def overlap_witnesses(specs: List[ExceptionSpec]) -> List[OverlapWitness]:
    """
    For every overlapping pair (in precedence order), produce one minimal
    witness prefix in the intersection and state the deterministic winner.
    Pairs whose actions disagree are flagged ``conflicting``.
    """
    ordered = order_exceptions(specs)
    out: List[OverlapWitness] = []
    for i, hi in enumerate(ordered):
        for lo in ordered[i + 1:]:
            inter = _scope_intersection(hi, lo)
            if inter is None:
                continue
            w = _minimal_prefix_in(inter)
            # sanity: both must actually match the witness
            assert hi.rule.matches(ipaddress.ip_network(w))
            assert lo.rule.matches(ipaddress.ip_network(w))
            out.append(OverlapWitness(
                winner_id=hi.id, loser_id=lo.id,
                winner_name=hi.name, loser_name=lo.name,
                prefix=w, winner_action=hi.action, loser_action=lo.action,
                conflicting=hi.action != lo.action,
            ))
    return out
