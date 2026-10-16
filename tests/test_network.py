"""Real TCP: disconnect/reconnect, shutdown/port cleanup, end-to-end runs."""
import asyncio
import random
import socket



from cids.config import SimConfig
from cids.message_security import node_secret
from cids.node import IDSNode
from cids.simulation import run_simulation
from cids.socket_transport import PeerLink, encode_frame


def test_disconnect_and_reconnect():
    async def go():
        cfg = SimConfig(num_nodes=2)
        secrets = {n: node_secret(n) for n in cfg.node_ids()}
        server = IDSNode("N2", cfg, secrets, random.Random(1))
        await server.start()
        port = server.port
        link = PeerLink("N2", "127.0.0.1", port, retry_after=1)
        f = encode_frame({"hello": 1}, 1024)
        assert await link.send(f, 0)
        await server.stop()
        await asyncio.sleep(0.05)
        assert not await link.send(f, 1)        # peer is down
        assert not await link.send(f, 1)        # back-off: no retry this round
        # restart a server on the same port
        srv2 = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", port)
        await asyncio.sleep(0.05)
        assert await link.send(f, 3)
        assert link.reconnects == 1 and link.failed == 2
        await link.close()
        srv2.close()
        await asyncio.wait_for(srv2.wait_closed(), 2)
    asyncio.run(go())


def test_graceful_shutdown_frees_port():
    async def go():
        cfg = SimConfig(num_nodes=2)
        n = IDSNode("N1", cfg, {i: node_secret(i) for i in cfg.node_ids()}, random.Random(1))
        await n.start()
        port = n.port
        await n.stop()
        return port
    port = asyncio.run(go())
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))   # would fail if the port were still held


def test_end_to_end_distributed_attack_needs_collaboration():
    cfg = SimConfig(n_concentrated=0, n_distributed=2, n_low_rate=1, n_benign_lookalike=0, seed=3)
    r = run_simulation(cfg)
    assert r.metrics["trust_aware"]["tp"] == 3
    assert r.metrics["local_only"]["tp"] == 0      # no single node sees enough
    assert r.comm["messages_sent"] == r.comm["messages_received_valid"] > 0


def test_end_to_end_offline_peer():
    r = run_simulation(SimConfig(offline_nodes=["N3"]))
    assert r.comm["send_failures"] > 0
    assert r.metrics["trust_aware"]["fp"] == 0
    assert any("offline" in n for n in r.notes)


def test_end_to_end_misleading_peer_loses_trust():
    r = run_simulation(SimConfig(malicious_nodes=["N4"], duration=90))
    for n in r.nodes:
        if n["node"] != "N4":
            assert n["trust_given"]["N4"] < 0.2
    assert r.metrics["trust_aware"]["fp"] == 0


def test_attacks_rejected_before_affecting_decisions():
    r = run_simulation(SimConfig(replay_attack=True, invalid_messages=True, duplicate_factor=2))
    rej = r.comm["rejections_by_reason"]
    for reason in ("duplicate", "replay", "bad_signature", "invalid_json", "schema",
                   "unknown_sender", "oversized", "truncated_frame"):
        assert rej.get(reason, 0) > 0, reason
    clean = run_simulation(SimConfig())
    assert r.metrics == clean.metrics   # rejected traffic changed nothing


def test_same_seed_is_reproducible():
    a, b = run_simulation(SimConfig(seed=9)), run_simulation(SimConfig(seed=9))
    assert a.metrics == b.metrics and a.incidents == b.incidents
