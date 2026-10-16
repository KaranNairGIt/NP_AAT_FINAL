"""Command-line entry point (no dashboard needed).

Examples:
  python run_sim.py                          # one demo run, default settings
  python run_sim.py --nodes 6 --seed 7 --malicious N4 --replay --invalid
  python run_sim.py --experiments all --seeds 5
"""
from __future__ import annotations

import argparse
import json
import logging
import sys

import pandas as pd

from cids.config import SimConfig
from cids.experiments import EXPERIMENTS, run_experiments, stamp, summarise
from cids.reporting import export_all, metrics_frame
from cids.simulation import run_simulation


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Collaborative Intrusion Detection Between Socket Nodes")
    p.add_argument("--config", help="JSON file with SimConfig fields (overrides the flags below)")
    p.add_argument("--nodes", type=int, default=4)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--duration", type=int, default=60)
    p.add_argument("--correlation-window", type=int, default=12)
    p.add_argument("--quorum", type=float, default=0.9)
    p.add_argument("--min-sources", type=int, default=2)
    p.add_argument("--offline", nargs="*", default=[], help="node ids, e.g. N3")
    p.add_argument("--malicious", nargs="*", default=[], help="node ids, e.g. N4")
    p.add_argument("--duplicates", type=int, default=1)
    p.add_argument("--replay", action="store_true")
    p.add_argument("--invalid", action="store_true")
    p.add_argument("--delay", type=int, default=0)
    p.add_argument("--drop", type=float, default=0.0)
    p.add_argument("--experiments", nargs="*", help="experiment names or 'all'")
    p.add_argument("--seeds", type=int, default=5, help="number of seeds for experiments")
    p.add_argument("--out", default="results")
    p.add_argument("-v", "--verbose", action="store_true", help="show socket/validation logs")
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO if a.verbose else logging.WARNING,
                        format="%(asctime)s %(name)s %(message)s")
    try:
        cfg = SimConfig(num_nodes=a.nodes, seed=a.seed, duration=a.duration,
                        correlation_window=a.correlation_window, quorum_threshold=a.quorum,
                        min_sources=a.min_sources, offline_nodes=a.offline,
                        malicious_nodes=a.malicious, duplicate_factor=a.duplicates,
                        replay_attack=a.replay, invalid_messages=a.invalid,
                        delay_rounds=a.delay, drop_rate=a.drop)
        if a.config:
            with open(a.config, encoding="utf-8") as fh:
                cfg = cfg.replace(**json.load(fh))
        cfg.validate()
    except (ValueError, OSError, TypeError) as e:
        print(f"Invalid settings: {e}", file=sys.stderr)
        return 2
    pd.set_option("display.width", 160)
    pd.set_option("display.max_columns", 20)

    if a.experiments is not None:
        names = list(EXPERIMENTS) if not a.experiments or a.experiments == ["all"] else a.experiments
        unknown = [n for n in names if n not in EXPERIMENTS]
        if unknown:
            print(f"Unknown experiments {unknown}. Choose from: {list(EXPERIMENTS)}", file=sys.stderr)
            return 2
        seeds = list(range(a.seed, a.seed + a.seeds))
        df = run_experiments(cfg, names, seeds,
                             lambda i, n, label: print(f"[{i}/{n}] {label}", flush=True))
        s = summarise(df)
        tag = stamp()
        df.to_csv(f"{a.out}_experiments_raw_{tag}.csv", index=False)
        s.to_csv(f"{a.out}_experiments_summary_{tag}.csv", index=False)
        cols = ["experiment", "variant", "approach", "precision_mean", "recall_mean",
                "f1_mean", "f1_std", "fpr_mean", "mean_latency_s_mean", "runs"]
        print(s[cols].round(3).to_string(index=False))
        print(f"\nSaved {a.out}_experiments_raw_{tag}.csv and {a.out}_experiments_summary_{tag}.csv")
        return 0

    res = run_simulation(cfg)
    print(f"Ran {res.rounds} rounds, {res.events_total} events, {len(res.config['offline_nodes'])} "
          f"offline, {len(res.config['malicious_nodes'])} malicious, in {res.wall_seconds}s\n")
    print("Incidents (ground truth):")
    print(pd.DataFrame(res.incidents).to_string(index=False))
    print("\nDetection results:")
    print(metrics_frame(res).round(3).to_string(index=False))
    c = res.comm
    print(f"\nMessages sent {c['messages_sent']}, valid received {c['messages_received_valid']}, "
          f"rejected {c['messages_rejected']} {c['rejections_by_reason']}, dropped "
          f"{c['messages_dropped']}, failed sends {c['send_failures']}, bytes {c['bytes_sent']}")
    for n in res.notes:
        print("Note:", n)
    files = export_all(res, f"{a.out}/run_{stamp()}")
    print(f"\nExported {len(files)} files to {files[0].parent}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
