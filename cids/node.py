"""One IDS node: TCP server, local detector, validation, correlation, trust, decisions."""
from __future__ import annotations

import asyncio
import itertools
import logging
import random
from collections import Counter
from typing import Callable, Optional

from .alert_correlator import Correlator
from .baselines import local_only_decision, majority_decision
from .config import SUSPICIOUS_TYPES, SimConfig
from .consensus_engine import trust_weighted_decision
from .local_detector import LocalDetector
from .message_security import MessageValidator, sign_alert
from .models import Alert, Decision, Event
from .socket_transport import FrameError, PeerLink, decode_payload, encode_frame, read_frame
from .trust_manager import TrustManager

log = logging.getLogger("cids.node")
Key = tuple[str, str]
SENDER_FAULTS = {"invalid_content", "future_timestamp"}


def severity_for(conf: float) -> str:
    return "high" if conf >= 1.0 else ("medium" if conf >= 0.5 else "low")


class IDSNode:
    def __init__(self, node_id: str, cfg: SimConfig, secrets: dict[str, bytes],
                 rng: random.Random, malicious: bool = False) -> None:
        self.id = node_id
        self.cfg = cfg
        self.secret = secrets[node_id]
        self.rng = rng
        self.malicious = malicious
        self.detector = LocalDetector(cfg.detection_window, cfg.weak_threshold, cfg.strong_threshold)
        self.validator = MessageValidator(node_id, secrets, cfg.max_message_age)
        self.correlator = Correlator(node_id, cfg.correlation_window)
        self.trust = TrustManager(node_id, cfg.node_ids(), cfg.initial_trust, cfg.trust_reward,
                                  cfg.trust_penalty, cfg.invalid_penalty)
        self.links: dict[str, PeerLink] = {}
        self.outbox: list[tuple[int, str, bytes]] = []  # (deliver_round, peer, frame)
        self.now = 0
        self.online = False
        self.port: Optional[int] = None
        self._server: Optional[asyncio.base_events.Server] = None
        self._conns: set[asyncio.StreamWriter] = set()
        self._seq = itertools.count(1)
        self._last_sent: dict[Key, tuple[float, int]] = {}
        self.tap: Optional[Callable[[int, str, bytes], None]] = None
        self.frames_in = 0
        self.stats: Counter = Counter()
        self.rejections: Counter = Counter()
        self.sent_log: list[dict] = []
        self.recv_log: list[dict] = []
        self.latest: dict[Key, Decision] = {}
        self.decision_log: list[dict] = []

    # ------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        self.online = True
        log.info("%s listening on 127.0.0.1:%s", self.id, self.port)

    async def stop(self) -> None:
        self.online = False
        if self._server is not None:
            self._server.close()
        for w in list(self._conns):
            w.close()
        for link in self.links.values():
            await link.close()
        if self._server is not None:
            try:
                await asyncio.wait_for(self._server.wait_closed(), 1.0)
            except asyncio.TimeoutError:
                pass
            self._server = None
        log.info("%s stopped", self.id)

    def connect_peers(self, ports: dict[str, int]) -> None:
        self.links = {pid: PeerLink(pid, "127.0.0.1", port)
                      for pid, port in ports.items() if pid != self.id}

    # ------------------------------------------------------------ receiving
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._conns.add(writer)
        try:
            while True:
                try:
                    body = await asyncio.wait_for(read_frame(reader, self.cfg.max_frame_bytes), 30)
                except FrameError as e:
                    self.frames_in += 1
                    self._reject(e.reason, "?")
                    break  # stream is out of sync after a framing error
                except (asyncio.TimeoutError, ConnectionError, OSError):
                    break
                if body is None:
                    break
                self.frames_in += 1
                self._process(body)
        finally:
            self._conns.discard(writer)
            writer.close()

    def _process(self, body: bytes) -> None:
        self.stats["bytes_received"] += len(body) + 4
        try:
            payload = decode_payload(body)
        except FrameError as e:
            self._reject(e.reason, "?")
            return
        res = self.validator.validate(payload, self.now)
        if res.alert is None:
            self._reject(res.reason, res.claimed_sender or "?")
            # Only penalise what the sender itself signed wrongly. Duplicates, replays
            # and stale copies can be produced by the network or an attacker, so
            # penalising the signer would let an attacker frame an honest node.
            if res.authenticated and res.reason in SENDER_FAULTS:
                self.trust.invalid(res.claimed_sender, res.reason, self.now)
            return
        a = res.alert
        self.stats["received_valid"] += 1
        self.correlator.add_alert(a, self.now)
        self.recv_log.append({"round": self.now, "receiver": self.id, "sender": a.sender_id,
                              "alert_id": a.alert_id, "target_id": a.target_id,
                              "event_type": a.event_type, "confidence": a.confidence,
                              "severity": a.severity, "evidence": a.evidence_summary})

    def _reject(self, reason: str, sender: str) -> None:
        self.rejections[reason] += 1
        self.stats["rejected"] += 1
        log.info("%s rejected message from %s: %s", self.id, sender, reason)
        self.recv_log.append({"round": self.now, "receiver": self.id, "sender": sender,
                              "alert_id": "", "target_id": "", "event_type": "",
                              "confidence": None, "severity": "", "evidence": f"REJECTED: {reason}"})

    # ------------------------------------------------------------ sending
    def observe(self, events: list[Event]) -> None:
        for e in events:
            self.stats["events_seen"] += 1
            self.detector.observe(e)

    def produce_alerts(self, now: int) -> list[Alert]:
        detections = self.detector.evaluate(now)
        for d in detections:  # own evidence, refreshed every round
            self.correlator.add(d.key, self.id, f"{self.id}-local", d.confidence, now, now)
        if self.malicious:
            return self._fabricate(now)
        keepalive = max(1, self.cfg.correlation_window // 2)
        out: list[Alert] = []
        for d in detections:
            last = self._last_sent.get(d.key)
            if last is None or d.confidence > last[0] + 1e-9 or now - last[1] >= keepalive:
                out.append(self._make_alert(now, d.last_event_id, d.event_type, d.target_id,
                                            d.confidence, d.explanation))
                self._last_sent[d.key] = (d.confidence, now)
        return out

    def _fabricate(self, now: int) -> list[Alert]:
        """Misleading peer: hides real findings, invents confident alerts."""
        if self.rng.random() >= 0.35:
            return []
        target = f"10.0.9.{self.rng.randint(1, 40)}"
        etype = self.rng.choice(SUSPICIOUS_TYPES)
        self.stats["fabricated"] += 1
        return [self._make_alert(now, f"FAKE-{now}", etype, target, 1.0,
                                 f"claimed {self.cfg.strong_threshold}+ {etype} events on {target}")]

    def _make_alert(self, now: int, event_id: str, etype: str, target: str,
                    conf: float, summary: str) -> Alert:
        return Alert(alert_id=f"{self.id}-{next(self._seq):06d}", event_id=event_id,
                     sender_id=self.id, timestamp=now, event_type=etype, target_id=target,
                     severity=severity_for(conf), confidence=round(float(conf), 4),
                     evidence_summary=summary[:200])

    def queue_alerts(self, alerts: list[Alert], now: int) -> None:
        for a in alerts:
            frame = encode_frame(sign_alert(a, self.secret), self.cfg.max_frame_bytes)
            self.stats["alerts_created"] += 1
            self.sent_log.append({"round": now, "sender": self.id, "alert_id": a.alert_id,
                                  "target_id": a.target_id, "event_type": a.event_type,
                                  "confidence": a.confidence, "severity": a.severity,
                                  "evidence": a.evidence_summary, "bytes": len(frame)})
            for peer in self.links:
                for _ in range(self.cfg.duplicate_factor):
                    if self.cfg.drop_rate and self.rng.random() < self.cfg.drop_rate:
                        self.stats["dropped"] += 1
                        continue
                    self.outbox.append((now + self.cfg.delay_rounds, peer, frame))

    async def flush(self, now: int) -> int:
        due: dict[str, list[bytes]] = {}
        keep = []
        for item in self.outbox:
            (due.setdefault(item[1], []).append(item[2]) if item[0] <= now else keep.append(item))
        self.outbox = keep

        async def send_all(peer: str, frames: list[bytes]) -> int:
            ok = 0
            for f in frames:
                if await self.links[peer].send(f, now):
                    ok += 1
                    if self.tap:
                        self.tap(now, peer, f)
            return ok

        results = await asyncio.gather(*(send_all(p, fs) for p, fs in due.items()))
        return sum(results)

    @property
    def frames_out(self) -> int:
        return sum(l.sent for l in self.links.values())

    # ------------------------------------------------------------ decisions
    def end_of_round(self, now: int) -> dict[str, set[Key]]:
        """Update trust from expired evidence, then decide on every active key.

        Returns the keys flagged this round by each approach.
        """
        for ex in self.correlator.expire(now):
            s = ex.record.sender_id
            if s == self.id:
                continue
            if ex.record.corroborated:
                self.trust.corroborated(s, now)
            else:
                self.trust.uncorroborated(s, now)
        available = sum(1 for l in self.links.values() if l.up)
        flagged: dict[str, set[Key]] = {"local_only": set(), "majority": set(), "trust_aware": set()}
        for key in self.correlator.active_keys(now):
            ev = self.correlator.active(key, now)
            if local_only_decision(ev, self.id):
                flagged["local_only"].add(key)
            if majority_decision(ev, self.cfg.num_nodes):
                flagged["majority"].add(key)
            v = trust_weighted_decision(ev, self.trust, self.id, self.cfg.quorum_threshold,
                                        self.cfg.min_sources, self.cfg.min_trust_to_count, available)
            if v.verdict:
                flagged["trust_aware"].add(key)
            dec = Decision(now, self.id, key[0], key[1], v.verdict, v.score, v.sources, v.explanation)
            prev = self.latest.get(key)
            if prev is None or prev.verdict != dec.verdict:
                self.decision_log.append(dec.to_dict())
            self.latest[key] = dec
        return flagged
