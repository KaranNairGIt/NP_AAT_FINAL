"""Typed records shared by every module."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from .config import PROTOCOL_VERSION


@dataclass(frozen=True)
class Event:
    """One synthetic network observation made by one node."""
    event_id: str
    time: int
    observer: str
    source_ip: str
    target_id: str
    event_type: str
    incident_id: Optional[str] = None  # ground truth, NEVER used by detectors


@dataclass
class Incident:
    """Ground-truth description of an injected scenario (evaluation only)."""
    incident_id: str
    kind: str
    target_id: str
    event_type: str
    start: int
    end: int
    is_attack: bool
    observers: list[str]

    @property
    def key(self) -> tuple[str, str]:
        return (self.target_id, self.event_type)


ALERT_FIELDS: dict[str, tuple[type, ...]] = {
    "alert_id": (str,),
    "event_id": (str,),
    "sender_id": (str,),
    "timestamp": (int,),
    "event_type": (str,),
    "target_id": (str,),
    "severity": (str,),
    "confidence": (int, float),
    "evidence_summary": (str,),
    "protocol_version": (str,),
    "signature": (str,),
}


@dataclass
class Alert:
    """The message exchanged between nodes (compact, versioned, signed)."""
    alert_id: str
    event_id: str
    sender_id: str
    timestamp: int
    event_type: str
    target_id: str
    severity: str
    confidence: float
    evidence_summary: str
    protocol_version: str = PROTOCOL_VERSION
    signature: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return (self.target_id, self.event_type)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Alert":
        return cls(**{k: d[k] for k in ALERT_FIELDS})


@dataclass
class EvidenceRecord:
    """Latest evidence from one sender about one correlation key."""
    sender_id: str
    alert_id: str
    confidence: float
    timestamp: int
    first_seen: int
    corroborated: bool = False


@dataclass
class Decision:
    round: int
    node_id: str
    target_id: str
    event_type: str
    verdict: bool
    score: float
    sources: list[str] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["sources"] = ",".join(self.sources)
        return d
