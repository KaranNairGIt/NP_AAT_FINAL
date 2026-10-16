"""Simulation settings, node identities and validation.

Every value the dashboard exposes lives here, so the CLI, the dashboard and
the tests all drive the simulation through the same object.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any

PROTOCOL_VERSION = "1.0"
SUSPICIOUS_TYPES = ("syn_flood", "port_scan", "brute_force")
BENIGN_TYPES = ("http_request", "dns_query", "login_ok")


def make_node_ids(n: int) -> list[str]:
    """Node identities are N1..Nn."""
    return [f"N{i}" for i in range(1, n + 1)]


@dataclass
class SimConfig:
    # Network / run
    num_nodes: int = 4
    seed: int = 42
    duration: int = 60  # simulated seconds; one round = one simulated second

    # Event mix (number of incidents of each kind)
    n_concentrated: int = 1      # one node sees a high-rate attack
    n_distributed: int = 1       # several nodes each see part of an attack
    n_low_rate: int = 1          # every node sees a little; only the sum is suspicious
    n_benign_lookalike: int = 2  # benign bursts that look suspicious
    background_rate: float = 3.0  # benign background events per node per second

    # Local detection
    detection_window: int = 10   # seconds of history the local detector looks at
    weak_threshold: int = 2      # events needed to emit a (weak) alert to peers
    strong_threshold: int = 8    # events needed for a confident local detection

    # Correlation and collective decision
    correlation_window: int = 12  # seconds a peer alert stays usable as evidence
    quorum_threshold: float = 0.9  # trust-weighted support needed
    min_sources: int = 2           # distinct reporting nodes needed

    # Trust
    initial_trust: float = 0.5
    trust_reward: float = 0.05
    trust_penalty: float = 0.10
    invalid_penalty: float = 0.15
    min_trust_to_count: float = 0.2

    # Message security
    max_message_age: int = 5      # seconds; older alerts are rejected as stale
    max_frame_bytes: int = 8192

    # Fault and attack injection
    offline_nodes: list[str] = field(default_factory=list)
    offline_from: int = 0          # round at which offline nodes go down
    malicious_nodes: list[str] = field(default_factory=list)
    duplicate_factor: int = 1      # >1 = every alert is sent this many times
    replay_attack: bool = False
    invalid_messages: bool = False
    delay_rounds: int = 0          # extra network delay in seconds
    drop_rate: float = 0.0         # probability a message is lost (reduced availability)

    # ------------------------------------------------------------------
    def node_ids(self) -> list[str]:
        return make_node_ids(self.num_nodes)

    def honest_nodes(self) -> list[str]:
        return [n for n in self.node_ids() if n not in self.malicious_nodes]

    def validate(self) -> "SimConfig":
        errors: list[str] = []

        def check(ok: bool, msg: str) -> None:
            if not ok:
                errors.append(msg)

        check(2 <= self.num_nodes <= 12, "num_nodes must be between 2 and 12")
        check(20 <= self.duration <= 600, "duration must be between 20 and 600")
        for name in ("n_concentrated", "n_distributed", "n_low_rate", "n_benign_lookalike"):
            check(0 <= getattr(self, name) <= 20, f"{name} must be between 0 and 20")
        check(0 <= self.background_rate <= 50, "background_rate must be between 0 and 50")
        check(self.detection_window >= 1, "detection_window must be >= 1")
        check(1 <= self.weak_threshold < self.strong_threshold,
              "need 1 <= weak_threshold < strong_threshold")
        check(self.correlation_window >= 1, "correlation_window must be >= 1")
        check(self.quorum_threshold > 0, "quorum_threshold must be > 0")
        check(1 <= self.min_sources <= self.num_nodes, "min_sources must be between 1 and num_nodes")
        for name in ("initial_trust", "trust_reward", "trust_penalty",
                     "invalid_penalty", "min_trust_to_count"):
            check(0.0 <= getattr(self, name) <= 1.0, f"{name} must be between 0 and 1")
        check(self.max_message_age >= 1, "max_message_age must be >= 1")
        check(512 <= self.max_frame_bytes <= 1_000_000, "max_frame_bytes must be 512..1000000")
        ids = set(self.node_ids())
        bad = (set(self.offline_nodes) | set(self.malicious_nodes)) - ids
        check(not bad, f"unknown node ids in fault settings: {sorted(bad)}")
        check(not (set(self.offline_nodes) & set(self.malicious_nodes)),
              "a node cannot be both offline and malicious")
        check(len(ids - set(self.offline_nodes) - set(self.malicious_nodes)) >= 1,
              "at least one honest online node is required")
        check(self.offline_from >= 0, "offline_from must be >= 0")
        check(1 <= self.duplicate_factor <= 20, "duplicate_factor must be between 1 and 20")
        check(0 <= self.delay_rounds <= 20, "delay_rounds must be between 0 and 20")
        check(0.0 <= self.drop_rate < 1.0, "drop_rate must be in [0, 1)")
        if errors:
            raise ValueError("; ".join(errors))
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SimConfig":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def replace(self, **changes: Any) -> "SimConfig":
        d = self.to_dict()
        d.update(changes)
        return SimConfig.from_dict(d)
