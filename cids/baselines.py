"""Baselines evaluated on exactly the same events and messages.

A. local-only: a node flags a key only from its own strong detection.
B. ordinary majority voting: flag if more than half of ALL configured nodes
   (self included) currently report the key -- no trust weighting.
"""
from __future__ import annotations

from .models import EvidenceRecord


def local_only_decision(evidence: dict[str, EvidenceRecord], own_id: str) -> bool:
    own = evidence.get(own_id)
    return own is not None and own.confidence >= 1.0


def majority_decision(evidence: dict[str, EvidenceRecord], num_nodes: int) -> bool:
    return len(evidence) >= num_nodes // 2 + 1
