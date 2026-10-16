"""Authentication, schema checks, freshness and replay protection.

Every incoming alert goes through `MessageValidator.validate` BEFORE it can
reach correlation or trust. Keys are per-node lab secrets derived from a
fixed lab master value -- for simulation only, never real credentials.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Optional

from .config import PROTOCOL_VERSION, SUSPICIOUS_TYPES
from .models import ALERT_FIELDS, Alert

LAB_MASTER_SECRET = b"cids-lab-only-not-a-real-secret"
SEVERITIES = ("low", "medium", "high")


def node_secret(node_id: str) -> bytes:
    return hmac.new(LAB_MASTER_SECRET, node_id.encode(), hashlib.sha256).digest()


def canonical_bytes(msg: dict[str, Any]) -> bytes:
    body = {k: v for k, v in msg.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign_message(msg: dict[str, Any], secret: bytes) -> str:
    return hmac.new(secret, canonical_bytes(msg), hashlib.sha256).hexdigest()


def sign_alert(alert: Alert, secret: bytes) -> dict[str, Any]:
    d = alert.to_dict()
    d["signature"] = sign_message(d, secret)
    alert.signature = d["signature"]
    return d


@dataclass
class ValidationResult:
    alert: Optional[Alert]
    reason: str               # "ok" or the rejection reason
    authenticated: bool       # True when the HMAC was valid
    claimed_sender: str = ""


class MessageValidator:
    def __init__(self, own_id: str, secrets: dict[str, bytes], max_age: int,
                 max_future: int = 1) -> None:
        self.own_id = own_id
        self.secrets = secrets
        self.max_age = max_age
        self.max_future = max_future
        self._seen: dict[str, int] = {}  # alert_id -> round first accepted

    def validate(self, msg: Any, now: int) -> ValidationResult:
        if not isinstance(msg, dict):
            return ValidationResult(None, "malformed", False)
        claimed = msg.get("sender_id", "") if isinstance(msg.get("sender_id"), str) else ""
        if set(msg) != set(ALERT_FIELDS):
            return ValidationResult(None, "schema", False, claimed)
        for name, types in ALERT_FIELDS.items():
            v = msg[name]
            if isinstance(v, bool) or not isinstance(v, types):
                return ValidationResult(None, "schema", False, claimed)
        if msg["protocol_version"] != PROTOCOL_VERSION:
            return ValidationResult(None, "bad_version", False, claimed)
        sender = msg["sender_id"]
        if sender == self.own_id or sender not in self.secrets:
            return ValidationResult(None, "unknown_sender", False, claimed)
        expected = sign_message(msg, self.secrets[sender])
        if not hmac.compare_digest(expected, msg["signature"]):
            return ValidationResult(None, "bad_signature", False, claimed)
        # From here on the sender is authenticated.
        if not 0.0 <= float(msg["confidence"]) <= 1.0 or msg["severity"] not in SEVERITIES \
                or msg["event_type"] not in SUSPICIOUS_TYPES or len(msg["evidence_summary"]) > 200:
            return ValidationResult(None, "invalid_content", True, sender)
        ts = msg["timestamp"]
        if ts < now - self.max_age:
            return ValidationResult(None, "stale", True, sender)
        if ts > now + self.max_future:
            return ValidationResult(None, "future_timestamp", True, sender)
        aid = msg["alert_id"]
        if aid in self._seen:
            reason = "duplicate" if self._seen[aid] == now else "replay"
            return ValidationResult(None, reason, True, sender)
        self._seen[aid] = now
        self._prune(now)
        return ValidationResult(Alert.from_dict(msg), "ok", True, sender)

    def _prune(self, now: int) -> None:
        # Anything older than max_age is caught by the stale check anyway.
        if len(self._seen) > 5000:
            cutoff = now - self.max_age - 2
            self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}
