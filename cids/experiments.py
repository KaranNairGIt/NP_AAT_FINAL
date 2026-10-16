"""Named, repeatable experiments run over several seeds."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Callable, Optional

import pandas as pd

from .config import SimConfig
from .simulation import APPROACH_LABELS, APPROACHES, SimResult, run_simulation

# Each experiment is a list of (label, overrides). Scaling has several variants.
EXPERIMENTS: dict[str, list[tuple[str, dict]]] = {
    "1_benign_only": [("", dict(n_concentrated=0, n_distributed=0, n_low_rate=0,
                                n_benign_lookalike=3))],
    "2_localised_high_rate": [("", dict(n_concentrated=2, n_distributed=0, n_low_rate=0))],
    "3_distributed": [("", dict(n_concentrated=0, n_distributed=3, n_low_rate=0))],
    "4_low_rate_distributed": [("", dict(n_concentrated=0, n_distributed=0, n_low_rate=3))],
    "5_misleading_peer": [("", dict(malicious_nodes=["N4"]))],
    "6_peer_failure": [("", dict(offline_nodes=["N3"]))],
    "7_duplicate_and_replay": [("", dict(duplicate_factor=3, replay_attack=True,
                                         invalid_messages=True))],
    "8_node_scaling": [(f"{n} nodes", dict(num_nodes=n)) for n in (3, 4, 6, 8)],
    "9_network_delay": [(f"delay {d}s", dict(delay_rounds=d)) for d in (0, 2, 4, 6)],
    "10_reduced_availability": [(f"drop {p:.0%}", dict(drop_rate=p)) for p in (0.0, 0.2, 0.4)],
}

METRIC_COLS = ["precision", "recall", "f1", "fpr", "mean_latency_s"]


def result_rows(res: SimResult, experiment: str, variant: str) -> list[dict]:
    rows = []
    for a in APPROACHES:
        m = res.metrics[a]
        rows.append({
            "experiment": experiment, "variant": variant, "seed": res.config["seed"],
            "num_nodes": res.config["num_nodes"], "approach": APPROACH_LABELS[a],
            **{k: m[k] for k in ("tp", "fp", "tn", "fn")},
            **{k: m[k] for k in METRIC_COLS},
            "messages_sent": res.comm["messages_sent"], "bytes_sent": res.comm["bytes_sent"],
            "messages_rejected": res.comm["messages_rejected"],
            "peer_availability": res.comm["peer_availability"],
            "cpu_seconds": res.resources["cpu_seconds"],
            "timestamp": res.started_at, "config": json.dumps(res.config, sort_keys=True),
        })
    return rows


def run_experiments(base: SimConfig, names: list[str], seeds: list[int],
                    progress: Optional[Callable[[int, int, str], None]] = None) -> pd.DataFrame:
    jobs = []
    for name in names:
        for variant, overrides in EXPERIMENTS[name]:
            for s in seeds:
                cfg = base.replace(**overrides, seed=s)
                # Fault settings from the base config only apply if the experiment
                # does not set them and the node ids still exist.
                cfg.offline_nodes = [n for n in cfg.offline_nodes if n in cfg.node_ids()]
                cfg.malicious_nodes = [n for n in cfg.malicious_nodes if n in cfg.node_ids()]
                cfg.min_sources = min(cfg.min_sources, cfg.num_nodes)
                jobs.append((name, variant, cfg))
    rows: list[dict] = []
    for i, (name, variant, cfg) in enumerate(jobs, 1):
        rows += result_rows(run_simulation(cfg), name, variant)
        if progress:
            progress(i, len(jobs), f"{name} {variant} seed={cfg.seed}")
    return pd.DataFrame(rows)


def summarise(df: pd.DataFrame) -> pd.DataFrame:
    """Mean and standard deviation across seeds."""
    if df.empty:
        return df
    g = df.groupby(["experiment", "variant", "approach"], sort=False)[METRIC_COLS + ["messages_sent"]]
    out = g.agg(["mean", "std"])
    out.columns = [f"{a}_{b}" for a, b in out.columns]
    out["runs"] = g.size()
    return out.reset_index()


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
