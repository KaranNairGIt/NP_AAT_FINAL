"""Runs one complete simulation round by round over real localhost TCP sockets."""
from __future__ import annotations

import asyncio
import logging
import random
import socket
import time
import tracemalloc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from .config import SUSPICIOUS_TYPES, SimConfig
from .event_generator import events_by_round, generate_events
from .fault_injector import FaultInjector
from .message_security import node_secret
from .metrics import evaluate, safe_div
from .models import Incident
from .node import IDSNode

log = logging.getLogger("cids.sim")
APPROACHES = ("local_only", "majority", "trust_aware")
APPROACH_LABELS = {"local_only": "A. Local-only IDS", "majority": "B. Majority voting",
                   "trust_aware": "C. Trust-aware CIDS"}
ProgressCb = Callable[[int, int, dict], None]


@dataclass
class SimResult:
    config: dict
    started_at: str
    incidents: list[dict]
    metrics: dict[str, dict]
    comm: dict[str, Any]
    resources: dict[str, Any]
    nodes: list[dict]
    links: list[dict]
    sent_alerts: list[dict]
    received: list[dict]
    decisions: list[dict]
    correlation_log: list[dict]
    trust_history: list[dict]
    detections: list[dict]
    attacks_injected: list[dict]
    events_total: int
    rounds: int
    wall_seconds: float
    notes: list[str] = field(default_factory=list)


def _free_port() -> int:
    """A port nothing listens on, used for nodes that are offline from the start."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def run_simulation_async(cfg: SimConfig, progress: Optional[ProgressCb] = None) -> SimResult:
    cfg.validate()
    t_wall, t_cpu = time.perf_counter(), time.process_time()
    tracemalloc.start()
    rng = random.Random(cfg.seed + 1)
    events, incidents = generate_events(cfg)
    per_round = events_by_round(events)
    ids = cfg.node_ids()
    secrets = {n: node_secret(n) for n in ids}
    nodes = {n: IDSNode(n, cfg, secrets, random.Random(f"{cfg.seed}-{n}"),
                        malicious=n in cfg.malicious_nodes) for n in ids}
    injector = FaultInjector(cfg, rng)
    notes: list[str] = []

    ports: dict[str, int] = {}
    for n in ids:
        if n in cfg.offline_nodes and cfg.offline_from == 0:
            ports[n] = _free_port()
        else:
            await nodes[n].start()
            ports[n] = nodes[n].port  # type: ignore[assignment]
    for node in nodes.values():
        node.connect_peers(ports)
        if cfg.replay_attack:
            node.tap = injector.capture

    first_flag: dict[str, dict[tuple[str, str], int]] = {a: {} for a in APPROACHES}
    flag_by: dict[str, dict[tuple[str, str], str]] = {a: {} for a in APPROACHES}
    missed_events = 0
    lost_in_transit = 0
    total_rounds = cfg.duration + max(5, cfg.delay_rounds + 2)
    try:
        for t in range(total_rounds):
            for node in nodes.values():
                node.now = t
            if t == cfg.offline_from and t > 0:
                for n in cfg.offline_nodes:
                    await nodes[n].stop()
                    notes.append(f"{n} went offline at t={t}")
            online = {n for n, nd in nodes.items() if nd.online}
            for ev in per_round.get(t, []):
                if ev.observer in online:
                    nodes[ev.observer].observe([ev])
                else:
                    missed_events += 1
            for n in online:
                nodes[n].queue_alerts(nodes[n].produce_alerts(t), t)
            await asyncio.gather(*(nodes[n].flush(t) for n in online))
            await injector.act(t, ports, online)
            # Wait until every frame written this round has been read by its receiver.
            expected = sum(nd.frames_out for nd in nodes.values()) + injector.frames_out
            deadline = time.perf_counter() + 1.0
            while sum(nd.frames_in for nd in nodes.values()) + lost_in_transit < expected:
                if time.perf_counter() > deadline:
                    lost_in_transit = expected - sum(nd.frames_in for nd in nodes.values())
                    break
                await asyncio.sleep(0.001)
            for n in online:
                flagged = nodes[n].end_of_round(t)
                if nodes[n].malicious:
                    continue  # only honest nodes' verdicts are evaluated
                for a in APPROACHES:
                    for key in flagged[a]:
                        if key not in first_flag[a]:
                            first_flag[a][key] = t
                            flag_by[a][key] = n
            if progress:
                progress(t + 1, total_rounds, {
                    "alerts": sum(nd.stats["alerts_created"] for nd in nodes.values()),
                    "rejected": sum(nd.stats["rejected"] for nd in nodes.values()),
                    "flagged": len(first_flag["trust_aware"]),
                    "recent": [r for nd in nodes.values() for r in nd.sent_log[-3:]][-8:]})
    finally:
        for node in nodes.values():
            if node.online:
                await node.stop()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    # ---------------------------------------------------------------- results
    units = {(e.target_id, e.event_type) for e in events if e.event_type in SUSPICIOUS_TYPES}
    for nd in nodes.values():
        units |= {(r["target_id"], r["event_type"]) for r in nd.sent_log}
    metrics = {a: evaluate(units, incidents, first_flag[a]) for a in APPROACHES}

    msgs_sent = sum(nd.frames_out for nd in nodes.values())
    bytes_sent = sum(l.bytes_sent for nd in nodes.values() for l in nd.links.values())
    attempts = sum(l.attempts for nd in nodes.values() for l in nd.links.values())
    failed = sum(l.failed for nd in nodes.values() for l in nd.links.values())
    rejections: dict[str, int] = {}
    for nd in nodes.values():
        for k, v in nd.rejections.items():
            rejections[k] = rejections.get(k, 0) + v
    comm = {
        "messages_sent": msgs_sent,
        "messages_received_valid": sum(nd.stats["received_valid"] for nd in nodes.values()),
        "messages_rejected": sum(nd.stats["rejected"] for nd in nodes.values()),
        "messages_dropped": sum(nd.stats["dropped"] for nd in nodes.values()),
        "send_attempts": attempts, "send_failures": failed,
        "peer_availability": safe_div(attempts - failed, attempts),
        "bytes_sent": bytes_sent, "avg_message_bytes": safe_div(bytes_sent, msgs_sent),
        "reconnects": sum(l.reconnects for nd in nodes.values() for l in nd.links.values()),
        "lost_in_transit": lost_in_transit,
        "injected_attack_frames": injector.frames_out,
        "rejections_by_reason": rejections,
    }
    wall = time.perf_counter() - t_wall
    resources = {"wall_seconds": round(wall, 3),
                 "cpu_seconds": round(time.process_time() - t_cpu, 3),
                 "peak_python_memory_mb": round(peak / 1e6, 2),
                 "note": "environment-dependent"}

    def status(n: str) -> str:
        if n in cfg.malicious_nodes:
            return "malicious"
        if n in cfg.offline_nodes:
            return "offline"
        return "honest"

    node_rows = [{"node": n, "status": status(n), "port": ports[n],
                  "events_seen": nd.stats["events_seen"],
                  "alerts_sent": nd.stats["alerts_created"],
                  "fabricated": nd.stats["fabricated"],
                  "received_valid": nd.stats["received_valid"],
                  "rejected": nd.stats["rejected"], "dropped": nd.stats["dropped"],
                  "trust_given": dict(nd.trust.scores)} for n, nd in nodes.items()]
    link_rows = [{"src": n, "dst": p, "attempts": l.attempts, "sent": l.sent,
                  "failed": l.failed, "bytes": l.bytes_sent}
                 for n, nd in nodes.items() for p, l in nd.links.items()]
    detections = [{"approach": a, "target_id": k[0], "event_type": k[1], "first_round": r,
                   "flagged_by": flag_by[a][k]} for a in APPROACHES for k, r in first_flag[a].items()]
    if missed_events:
        notes.append(f"{missed_events} events were observed by offline nodes and lost")

    return SimResult(
        config=cfg.to_dict(), started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        incidents=[_inc(i) for i in incidents], metrics=metrics, comm=comm, resources=resources,
        nodes=node_rows, links=link_rows,
        sent_alerts=[r for nd in nodes.values() for r in nd.sent_log],
        received=[r for nd in nodes.values() for r in nd.recv_log],
        decisions=[r for nd in nodes.values() for r in nd.decision_log],
        correlation_log=[r for nd in nodes.values() for r in nd.correlator.log],
        trust_history=[r for nd in nodes.values() for r in nd.trust.history],
        detections=detections, attacks_injected=injector.log, events_total=len(events),
        rounds=total_rounds, wall_seconds=round(wall, 3), notes=notes)


def _inc(i: Incident) -> dict:
    return {"incident_id": i.incident_id, "kind": i.kind, "target_id": i.target_id,
            "event_type": i.event_type, "start": i.start, "end": i.end,
            "is_attack": i.is_attack, "observers": ",".join(i.observers)}


def run_simulation(cfg: SimConfig, progress: Optional[ProgressCb] = None) -> SimResult:
    """Synchronous wrapper (used by the CLI and Streamlit)."""
    return asyncio.run(run_simulation_async(cfg, progress))
