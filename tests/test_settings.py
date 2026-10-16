"""Every setting can be changed and the simulation still runs; key settings
change behaviour in the expected direction."""
import pytest

from cids.config import SimConfig
from cids.experiments import EXPERIMENTS, run_experiments, summarise
from cids.simulation import run_simulation

CHANGES = {
    "num_nodes": 6, "seed": 7, "duration": 40, "n_concentrated": 3, "n_distributed": 2,
    "n_low_rate": 2, "n_benign_lookalike": 4, "background_rate": 6.5, "detection_window": 6,
    "weak_threshold": 3, "strong_threshold": 10, "correlation_window": 8,
    "quorum_threshold": 1.4, "min_sources": 3, "initial_trust": 0.8, "trust_reward": 0.1,
    "trust_penalty": 0.2, "invalid_penalty": 0.3, "min_trust_to_count": 0.4,
    "max_message_age": 3, "max_frame_bytes": 1024, "offline_nodes": ["N2"], "offline_from": 20,
    "malicious_nodes": ["N3"], "duplicate_factor": 3, "replay_attack": True,
    "invalid_messages": True, "delay_rounds": 2, "drop_rate": 0.25,
}


def test_every_setting_is_covered():
    assert set(CHANGES) == set(SimConfig().to_dict())


@pytest.mark.parametrize("name", sorted(CHANGES))
def test_each_setting_runs(name):
    r = run_simulation(SimConfig().replace(**{name: CHANGES[name]}))
    assert r.config[name] == CHANGES[name]
    assert set(r.metrics) == {"local_only", "majority", "trust_aware"}


def test_all_settings_together():
    run_simulation(SimConfig().replace(**CHANGES))


def test_settings_have_effect():
    base = run_simulation(SimConfig())
    assert run_simulation(SimConfig(drop_rate=0.3)).comm["messages_dropped"] > 0
    assert run_simulation(SimConfig(num_nodes=6)).comm["messages_sent"] > base.comm["messages_sent"]
    strict = run_simulation(SimConfig(quorum_threshold=5.0, min_sources=4))
    assert strict.metrics["trust_aware"]["tp"] <= base.metrics["trust_aware"]["tp"]
    slow = run_simulation(SimConfig(delay_rounds=8))
    assert slow.comm["rejections_by_reason"].get("stale", 0) > 0
    assert run_simulation(SimConfig(seed=1)).incidents != base.incidents
    quiet = run_simulation(SimConfig(background_rate=0))
    assert quiet.events_total < base.events_total


@pytest.mark.parametrize("bad", [dict(num_nodes=1), dict(weak_threshold=9),
                                 dict(min_sources=9), dict(offline_nodes=["N9"]),
                                 dict(offline_nodes=["N1", "N2", "N3", "N4"]),
                                 dict(drop_rate=1.0), dict(malicious_nodes=["N1"], offline_nodes=["N1"])])
def test_invalid_settings_rejected(bad):
    with pytest.raises(ValueError):
        SimConfig().replace(**bad).validate()


def test_experiments_run_and_summarise():
    df = run_experiments(SimConfig(duration=30), list(EXPERIMENTS), [1])
    assert set(df["experiment"]) == set(EXPERIMENTS)
    s = summarise(df)
    assert "f1_mean" in s.columns and len(s) > 0
