"""Evaluation metrics. Zero denominators return None (shown as "n/a").

Evaluation unit: every correlation key (target_id, event_type) that appeared
in any suspicious event or any alert during the run. A key is an attack if it
belongs to a ground-truth attack incident, otherwise benign. An approach
"flags" a key if any honest, online node flagged it at any time. Ground truth
is used here only, never by the detectors.
"""
from __future__ import annotations

from statistics import mean
from typing import Optional

from .models import Incident

Key = tuple[str, str]


def safe_div(num: float, den: float) -> Optional[float]:
    return None if den == 0 else num / den


def classification_metrics(tp: int, fp: int, tn: int, fn: int) -> dict[str, Optional[float]]:
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    if precision is None or recall is None or precision + recall == 0:
        f1 = None if precision is None or recall is None else 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1,
            "fpr": safe_div(fp, fp + tn)}


def evaluate(units: set[Key], incidents: list[Incident],
             flagged: dict[Key, int]) -> dict:
    attacks = {i.key: i for i in incidents if i.is_attack}
    tp = fp = tn = fn = 0
    latencies: list[int] = []
    for key in units | set(flagged):
        is_attack = key in attacks
        hit = key in flagged
        if is_attack and hit:
            tp += 1
            latencies.append(max(0, flagged[key] - attacks[key].start))
        elif is_attack:
            fn += 1
        elif hit:
            fp += 1
        else:
            tn += 1
    out = {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
    out.update(classification_metrics(tp, fp, tn, fn))
    out["mean_latency_s"] = mean(latencies) if latencies else None
    return out
