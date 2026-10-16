"""External attacker on the lab network: replays captured frames and sends
invalid ones over real TCP connections. Used only against our own localhost nodes."""
from __future__ import annotations

import asyncio
import json
import random

from .config import PROTOCOL_VERSION
from .socket_transport import HEADER, encode_frame


class FaultInjector:
    KINDS = ("bad_signature", "malformed_json", "schema_violation",
             "unknown_sender", "oversized", "truncated")

    def __init__(self, cfg, rng: random.Random) -> None:
        self.cfg = cfg
        self.rng = rng
        self.captured: list[tuple[int, str, bytes]] = []
        self.frames_out = 0
        self.log: list[dict] = []
        self._kind_idx = 0

    def capture(self, now: int, dest: str, frame: bytes) -> None:
        if self.rng.random() < 0.3:
            self.captured.append((now, dest, frame))
            self.captured = self.captured[-200:]

    async def act(self, now: int, ports: dict[str, int], online: set[str]) -> None:
        jobs: list[tuple[str, bytes, str]] = []
        if self.cfg.replay_attack and now % 3 == 2 and self.captured:
            recent = [c for c in self.captured if 1 <= now - c[0] < self.cfg.max_message_age]
            old = [c for c in self.captured if now - c[0] > self.cfg.max_message_age]
            for pool, label in ((recent, "replay_recent"), (old, "replay_old")):
                if pool:
                    _, dest, frame = self.rng.choice(pool)
                    jobs.append((dest, frame, label))
        if self.cfg.invalid_messages and now % 4 == 1:
            kind = self.KINDS[self._kind_idx % len(self.KINDS)]
            self._kind_idx += 1
            jobs.append((self.rng.choice(sorted(ports)), self._craft(kind, now), kind))
        for dest, frame, label in jobs:
            if dest not in online:
                continue
            if await self._send(ports[dest], frame):
                self.frames_out += 1
                self.log.append({"round": now, "target_node": dest, "attack": label})

    def _craft(self, kind: str, now: int) -> bytes:
        nodes = self.cfg.node_ids()
        alert = {"alert_id": f"X-{now}", "event_id": "E0", "sender_id": self.rng.choice(nodes),
                 "timestamp": now, "event_type": "port_scan", "target_id": "10.0.1.1",
                 "severity": "high", "confidence": 1.0, "evidence_summary": "forged",
                 "protocol_version": PROTOCOL_VERSION, "signature": "0" * 64}
        mf = self.cfg.max_frame_bytes
        if kind == "bad_signature":
            return encode_frame(alert, mf)
        if kind == "malformed_json":
            body = b'{"alert_id": "broken'
            return HEADER.pack(len(body)) + body
        if kind == "schema_violation":
            alert.pop("confidence")
            return encode_frame(alert, mf)
        if kind == "unknown_sender":
            alert["sender_id"] = "EVIL"
            return encode_frame(alert, mf)
        if kind == "oversized":
            return HEADER.pack(mf + 1) + b"A" * 64
        # truncated: header promises 100 bytes, only 10 are sent, then close
        return HEADER.pack(100) + json.dumps({"a": 1}).encode()[:10]

    async def _send(self, port: int, frame: bytes) -> bool:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 0.5)
        except (OSError, asyncio.TimeoutError):
            return False
        try:
            w.write(frame)
            await asyncio.wait_for(w.drain(), 0.5)
            return True
        except (OSError, ConnectionError, asyncio.TimeoutError):
            return False
        finally:
            w.close()
