"""Groups evidence by correlation key = (target_id, event_type).

* One record per (key, sender): repeated messages from one sender never count
  as extra corroboration.
* Evidence older than `window` seconds is expired.
* A record is "corroborated" if another independent node reported the same
  key while it was active. This flag (not the collective decision) feeds trust.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Alert, EvidenceRecord

Key = tuple[str, str]


@dataclass
class ExpiredRecord:
    key: Key
    record: EvidenceRecord


class Correlator:
    def __init__(self, own_id: str, window: int) -> None:
        self.own_id = own_id
        self.window = window
        self._ev: dict[Key, dict[str, EvidenceRecord]] = {}
        self.log: list[dict] = []

    def _is_active(self, rec: EvidenceRecord, now: int) -> bool:
        return rec.timestamp > now - self.window

    def add(self, key: Key, sender: str, alert_id: str, confidence: float,
            timestamp: int, now: int) -> str:
        if timestamp <= now - self.window:
            self._log(now, key, sender, "rejected_stale_evidence")
            return "rejected_stale_evidence"
        bucket = self._ev.setdefault(key, {})
        old = bucket.get(sender)
        if old is not None and self._is_active(old, now):
            if timestamp < old.timestamp:
                self._log(now, key, sender, "ignored_older")
                return "ignored_older"
            rec = EvidenceRecord(sender, alert_id, confidence, timestamp,
                                 old.first_seen, old.corroborated)
            action = "updated"
        else:
            rec = EvidenceRecord(sender, alert_id, confidence, timestamp, now)
            action = "new_source"
        bucket[sender] = rec
        others = [r for s, r in bucket.items() if s != sender and self._is_active(r, now)]
        if others:
            rec.corroborated = True
            for r in others:
                r.corroborated = True
        if sender != self.own_id or action == "new_source":
            self._log(now, key, sender, action, len(self.active(key, now)))
        return action

    def add_alert(self, alert: Alert, now: int) -> str:
        return self.add(alert.key, alert.sender_id, alert.alert_id,
                        float(alert.confidence), alert.timestamp, now)

    def active(self, key: Key, now: int) -> dict[str, EvidenceRecord]:
        return {s: r for s, r in self._ev.get(key, {}).items() if self._is_active(r, now)}

    def active_keys(self, now: int) -> list[Key]:
        return [k for k in self._ev if self.active(k, now)]

    def expire(self, now: int) -> list[ExpiredRecord]:
        out: list[ExpiredRecord] = []
        for key in list(self._ev):
            bucket = self._ev[key]
            for sender in list(bucket):
                if not self._is_active(bucket[sender], now):
                    out.append(ExpiredRecord(key, bucket.pop(sender)))
            if not bucket:
                del self._ev[key]
        return out

    def _log(self, now: int, key: Key, sender: str, action: str, sources: int = 0) -> None:
        self.log.append({"round": now, "node": self.own_id, "target_id": key[0],
                         "event_type": key[1], "sender": sender, "action": action,
                         "independent_sources": sources})
