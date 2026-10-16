"""Detector, correlation, trust, quorum and metric calculations."""
from cids.alert_correlator import Correlator
from cids.baselines import majority_decision
from cids.consensus_engine import trust_weighted_decision
from cids.local_detector import LocalDetector
from cids.metrics import classification_metrics, evaluate
from cids.models import Event, EvidenceRecord, Incident
from cids.trust_manager import TrustManager

K = ("10.0.1.1", "port_scan")


def ev(i, t, etype="port_scan"):
    return Event(f"E{i}", t, "N1", "1.2.3.4", "10.0.1.1", etype)


def test_detector_weak_strong_and_window():
    d = LocalDetector(window=10, weak=2, strong=4)
    d.observe(ev(1, 0)); d.observe(ev(2, 1)); d.observe(ev(9, 1, "dns_query"))
    [r] = d.evaluate(1)
    assert r.count == 2 and r.confidence == 0.5 and not r.strong
    d.observe(ev(3, 2)); d.observe(ev(4, 3))
    assert d.evaluate(3)[0].strong
    assert d.evaluate(10)[0].count == 3   # event at t=0 left the window
    assert d.evaluate(14) == []


def test_correlation_window_boundary_and_distinct_sources():
    c = Correlator("N1", window=5)
    c.add(K, "N2", "a1", 0.5, 10, 10)
    c.add(K, "N2", "a2", 0.6, 11, 11)          # same sender: still one source
    assert list(c.active(K, 11)) == ["N2"]
    assert c.active(K, 15)                       # 11 > 15-5
    assert not c.active(K, 16)                   # 11 <= 16-5 -> expired
    assert c.add(K, "N3", "a3", 0.5, 3, 10) == "rejected_stale_evidence"


def test_corroboration_flag():
    c = Correlator("N1", window=5)
    c.add(K, "N2", "a", 0.5, 1, 1)
    c.add(("x", "port_scan"), "N4", "b", 0.5, 1, 1)
    c.add(K, "N3", "c", 0.5, 2, 2)
    expired = {(e.key, e.record.sender_id): e.record.corroborated for e in c.expire(10)}
    assert expired[(K, "N2")] and expired[(K, "N3")]
    assert not expired[(("x", "port_scan"), "N4")]


def test_trust_bounds_and_history():
    t = TrustManager("N1", ["N1", "N2"], 0.5, 0.3, 0.4, 0.4)
    assert t.get("N1") == 1.0 and t.get("N2") == 0.5
    for _ in range(5):
        t.corroborated("N2", 1)
    assert t.get("N2") == 1.0
    for _ in range(5):
        t.uncorroborated("N2", 2)
    assert t.get("N2") == 0.0
    assert all(0 <= h["new"] <= 1 for h in t.history) and t.history[-1]["reason"]


def rec(s, c):
    return EvidenceRecord(s, "x", c, 0, 0)


def test_quorum_threshold_boundary():
    t = TrustManager("N1", ["N1", "N2", "N3"], 0.5, 0, 0, 0)
    ev2 = {"N1": rec("N1", 0.4), "N2": rec("N2", 1.0)}   # 0.4 + 0.5 = 0.9
    assert trust_weighted_decision(ev2, t, "N1", 0.9, 2, 0.2, 2).verdict
    assert not trust_weighted_decision(ev2, t, "N1", 0.91, 2, 0.2, 2).verdict
    assert not trust_weighted_decision(ev2, t, "N1", 0.9, 3, 0.2, 2).verdict  # too few sources


def test_low_trust_peer_ignored_and_local_override():
    t = TrustManager("N1", ["N1", "N2", "N3"], 0.1, 0, 0, 0)
    v = trust_weighted_decision({"N2": rec("N2", 1), "N3": rec("N3", 1)}, t, "N1", 0.1, 1, 0.2, 2)
    assert not v.verdict and "ignored" in v.explanation
    assert trust_weighted_decision({"N1": rec("N1", 1.0)}, t, "N1", 5, 3, 0.2, 2).verdict


def test_majority_rule():
    two = {"N1": rec("N1", .3), "N2": rec("N2", .3)}
    assert not majority_decision(two, 4)
    assert majority_decision({**two, "N3": rec("N3", .3)}, 4)
    assert majority_decision(two, 3)


def test_metrics_hand_computed():
    m = classification_metrics(tp=3, fp=1, tn=4, fn=2)
    assert m["precision"] == 0.75 and m["recall"] == 0.6
    assert abs(m["f1"] - 2 * 0.75 * 0.6 / 1.35) < 1e-12 and m["fpr"] == 0.2
    z = classification_metrics(0, 0, 0, 0)
    assert z["precision"] is None and z["fpr"] is None


def test_evaluate_counts_and_latency():
    inc = [Incident("I1", "d", "t1", "port_scan", 10, 12, True, []),
           Incident("I2", "d", "t2", "port_scan", 5, 6, True, [])]
    units = {("t1", "port_scan"), ("t2", "port_scan"), ("b", "syn_flood")}
    r = evaluate(units, inc, {("t1", "port_scan"): 13, ("fake", "syn_flood"): 3})
    assert (r["tp"], r["fp"], r["tn"], r["fn"]) == (1, 1, 1, 1)
    assert r["mean_latency_s"] == 3
