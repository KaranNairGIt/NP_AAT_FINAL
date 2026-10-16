"""Reproducible synthetic events with ground-truth labels.

Nothing here touches a real network: events are plain Python objects.
Each node only "sees" the events whose observer is that node, which gives
the partial visibility that makes collaboration meaningful.
"""
from __future__ import annotations

import itertools

import random

from .config import BENIGN_TYPES, SUSPICIOUS_TYPES, SimConfig
from .models import Event, Incident


def generate_events(cfg: SimConfig) -> tuple[list[Event], list[Incident]]:
    rng = random.Random(cfg.seed)
    nodes = cfg.node_ids()
    events: list[Event] = []
    incidents: list[Incident] = []
    ev_counter = itertools.count(1)
    tgt_counter = itertools.count(1)
    inc_counter = itertools.count(1)
    latest_start = max(3, cfg.duration - 12)

    def add(t: int, observer: str, src: str, target: str, etype: str, inc: str | None) -> None:
        events.append(Event(f"E{next(ev_counter):06d}", t, observer, src, target, etype, inc))

    def new_target() -> str:
        return f"10.0.1.{next(tgt_counter)}"

    def new_incident_id() -> str:
        return f"INC{next(inc_counter):03d}"

    def spread(count: int, start: int, span: int) -> list[int]:
        span = max(1, span)
        return [start + (i * span) // max(1, count) for i in range(count)]

    # 1. Concentrated high-rate attack: one node sees all of it.
    for _ in range(cfg.n_concentrated):
        inc, target, start = new_incident_id(), new_target(), rng.randint(3, latest_start)
        observer = rng.choice(nodes)
        src = f"203.0.113.{rng.randint(1, 254)}"
        n = cfg.strong_threshold + rng.randint(2, 5)
        for t in spread(n, start, 3):
            add(t, observer, src, target, "syn_flood", inc)
        incidents.append(Incident(inc, "concentrated", target, "syn_flood",
                                  start, start + 2, True, [observer]))

    # 2. Distributed attack: several nodes each see a part (below strong threshold).
    for _ in range(cfg.n_distributed):
        inc, target, start = new_incident_id(), new_target(), rng.randint(3, latest_start)
        observers = rng.sample(nodes, min(3, len(nodes)))
        hi = max(cfg.weak_threshold + 1, cfg.strong_threshold - 2)
        for obs in observers:
            src = f"198.51.100.{rng.randint(1, 254)}"
            n = rng.randint(cfg.weak_threshold + 1, hi)
            for t in spread(n, start, 5):
                add(t, obs, src, target, "port_scan", inc)
        incidents.append(Incident(inc, "distributed", target, "port_scan",
                                  start, start + 4, True, observers))

    # 3. Low-rate attack: every node sees just above the weak threshold.
    for _ in range(cfg.n_low_rate):
        inc, target, start = new_incident_id(), new_target(), rng.randint(3, latest_start)
        span = max(1, min(cfg.detection_window, cfg.correlation_window) - 1)
        src = f"192.0.2.{rng.randint(1, 254)}"
        for obs in nodes:
            for t in spread(cfg.weak_threshold + 1, start, span):
                add(t, obs, src, target, "brute_force", inc)
        incidents.append(Incident(inc, "low_rate", target, "brute_force",
                                  start, start + span, True, list(nodes)))

    # 4. Benign look-alike: e.g. a backup job or monitoring scan.
    for _ in range(cfg.n_benign_lookalike):
        inc, target, start = new_incident_id(), new_target(), rng.randint(3, latest_start)
        etype = rng.choice(SUSPICIOUS_TYPES)
        observers = rng.sample(nodes, min(2, len(nodes)))
        src = f"10.0.5.{rng.randint(1, 254)}"
        for obs in observers:
            n = rng.randint(cfg.weak_threshold, cfg.weak_threshold + 2)
            for t in spread(n, start, 5):
                add(t, obs, src, target, etype, inc)
        incidents.append(Incident(inc, "benign_lookalike", target, etype,
                                  start, start + 4, False, observers))

    # 5. Background benign traffic (plus rare isolated suspicious-looking events).
    whole = int(cfg.background_rate)
    frac = cfg.background_rate - whole
    for t in range(cfg.duration):
        for obs in nodes:
            n = whole + (1 if rng.random() < frac else 0)
            for _ in range(n):
                src = f"10.0.3.{rng.randint(1, 254)}"
                if rng.random() < 0.05:
                    add(t, obs, src, f"10.0.2.{rng.randint(1, 60)}",
                        rng.choice(SUSPICIOUS_TYPES), None)
                else:
                    add(t, obs, src, f"10.0.4.{rng.randint(1, 60)}",
                        rng.choice(BENIGN_TYPES), None)

    events.sort(key=lambda e: (e.time, e.event_id))
    return events, incidents


def events_by_round(events: list[Event]) -> dict[int, list[Event]]:
    out: dict[int, list[Event]] = {}
    for e in events:
        out.setdefault(e.time, []).append(e)
    return out


