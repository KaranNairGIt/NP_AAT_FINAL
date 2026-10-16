"""Transparent sliding-window threshold detector (no trained model).

For every (target, event_type) pair the node keeps the times of suspicious
events seen in the last `window` seconds.

* count >= weak_threshold   -> weak alert, shared with peers
* count >= strong_threshold -> strong (confidence 1.0) local detection
confidence = min(1, count / strong_threshold)
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .config import SUSPICIOUS_TYPES
from .models import Event


@dataclass
class Detection:
    target_id: str
    event_type: str
    count: int
    confidence: float
    strong: bool
    last_event_id: str
    explanation: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.target_id, self.event_type)


class LocalDetector:
    def __init__(self, window: int, weak: int, strong: int) -> None:
        if not 1 <= weak < strong:
            raise ValueError("need 1 <= weak < strong")
        self.window, self.weak, self.strong = window, weak, strong
        self._hist: dict[tuple[str, str], deque[tuple[int, str]]] = {}

    def observe(self, ev: Event) -> None:
        if ev.event_type in SUSPICIOUS_TYPES:
            self._hist.setdefault((ev.target_id, ev.event_type), deque()).append(
                (ev.time, ev.event_id))

    def evaluate(self, now: int) -> list[Detection]:
        out: list[Detection] = []
        for key in list(self._hist):
            dq = self._hist[key]
            while dq and dq[0][0] <= now - self.window:
                dq.popleft()
            if not dq:
                del self._hist[key]
                continue
            c = len(dq)
            if c >= self.weak:
                conf = min(1.0, c / self.strong)
                strong = c >= self.strong
                out.append(Detection(
                    key[0], key[1], c, round(conf, 4), strong, dq[-1][1],
                    f"{c} {key[1]} events on {key[0]} in last {self.window}s "
                    f"(weak>={self.weak}, strong>={self.strong})"))
        return out
