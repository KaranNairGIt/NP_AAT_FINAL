"""Trust-weighted evidence aggregation (NOT a Byzantine consensus protocol).

weighted_support = sum(trust(sender) * confidence) over distinct eligible senders
INTRUSION if  (weighted_support >= quorum_threshold and sources >= min_sources)
          or  the node's own detector is strong (local override, so a concentrated
              attack seen by one node is not ignored for lack of peers).
Senders below `min_trust_to_count` are not eligible. Severity is informational.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import EvidenceRecord
from .trust_manager import TrustManager


@dataclass
class Verdict:
    verdict: bool
    score: float
    sources: list[str]
    explanation: str


def trust_weighted_decision(evidence: dict[str, EvidenceRecord], trust: TrustManager,
                            own_id: str, quorum_threshold: float, min_sources: int,
                            min_trust: float, available_peers: int) -> Verdict:
    eligible = {s: r for s, r in evidence.items()
                if s == own_id or trust.get(s) >= min_trust}
    ignored = sorted(set(evidence) - set(eligible))
    score = round(sum(trust.get(s) * r.confidence for s, r in eligible.items()), 4)
    sources = sorted(eligible)
    own = evidence.get(own_id)
    override = own is not None and own.confidence >= 1.0
    quorum = score >= quorum_threshold and len(sources) >= min_sources
    verdict = override or quorum
    parts = [f"support={score:.2f} (threshold {quorum_threshold}) from "
             f"{len(sources)} source(s) {sources} (need {min_sources})"]
    if ignored:
        parts.append(f"ignored low-trust {ignored}")
    if override:
        parts.append("own detector is strong -> local override")
    elif quorum:
        parts.append("quorum reached")
    elif score >= quorum_threshold:
        parts.append("insufficient independent sources")
    else:
        parts.append("support below threshold")
    if available_peers + 1 < min_sources:
        parts.append("reduced confidence: too few reachable peers")
    return Verdict(verdict, score, sources, "; ".join(parts))
