"""Turns a SimResult into tables and export files (no UI code here)."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pandas as pd

from .simulation import APPROACH_LABELS, APPROACHES, SimResult


def metrics_frame(res: SimResult) -> pd.DataFrame:
    rows = [{"approach": APPROACH_LABELS[a], **res.metrics[a]} for a in APPROACHES]
    return pd.DataFrame(rows)


def frames(res: SimResult) -> dict[str, pd.DataFrame]:
    return {
        "metrics": metrics_frame(res),
        "incidents": pd.DataFrame(res.incidents),
        "alerts_sent": pd.DataFrame(res.sent_alerts),
        "messages_received": pd.DataFrame(res.received),
        "decisions": pd.DataFrame(res.decisions),
        "correlation_log": pd.DataFrame(res.correlation_log),
        "trust_history": pd.DataFrame(res.trust_history),
        "detections": pd.DataFrame(res.detections),
        "links": pd.DataFrame(res.links),
        "nodes": pd.DataFrame([{k: v for k, v in n.items() if k != "trust_given"} for n in res.nodes]),
        "attacks_injected": pd.DataFrame(res.attacks_injected),
    }


def result_json(res: SimResult) -> str:
    return json.dumps(asdict(res), indent=2, default=str)


def export_all(res: SimResult, out_dir: str | Path) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, df in frames(res).items():
        p = out / f"{name}.csv"
        df.to_csv(p, index=False)
        written.append(p)
    p = out / "run_log.json"
    p.write_text(result_json(res), encoding="utf-8")
    written.append(p)
    return written
