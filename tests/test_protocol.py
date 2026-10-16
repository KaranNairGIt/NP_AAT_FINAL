"""Framing, authentication, freshness, replay and duplicate handling."""
import asyncio

import pytest

from cids.message_security import MessageValidator, node_secret, sign_alert
from cids.models import Alert
from cids.socket_transport import HEADER, FrameError, decode_payload, encode_frame, read_frame

SECRETS = {n: node_secret(n) for n in ("N1", "N2", "N3")}


def make_alert(sender="N2", ts=10, aid="N2-000001", conf=0.5):
    return Alert(aid, "E1", sender, ts, "port_scan", "10.0.1.9", "medium", conf, "test")


def feed(chunks):
    """StreamReader fed in small pieces to imitate partial TCP reads."""
    async def go():
        r = asyncio.StreamReader()
        for c in chunks:
            r.feed_data(c)
        r.feed_eof()
        out = []
        while True:
            try:
                b = await read_frame(r, 1024)
            except FrameError as e:
                out.append(e.reason)
                break
            if b is None:
                break
            out.append(decode_payload(b))
        return out
    return asyncio.run(go())


def test_framing_survives_partial_reads():
    frames = encode_frame({"a": 1}, 1024) + encode_frame({"b": 2}, 1024)
    chunks = [frames[i:i + 3] for i in range(0, len(frames), 3)]
    assert feed(chunks) == [{"a": 1}, {"b": 2}]


def test_oversized_and_truncated_frames_rejected():
    assert feed([HEADER.pack(5000) + b"x"]) == ["oversized"]
    assert feed([HEADER.pack(50) + b"{}"]) == ["truncated_frame"]
    assert feed([b"\x00\x00"]) == ["truncated_frame"]
    with pytest.raises(FrameError):
        encode_frame({"x": "y" * 2000}, 1024)


def test_invalid_json_raises():
    with pytest.raises(FrameError) as e:
        decode_payload(b"{not json")
    assert e.value.reason == "invalid_json"


def test_valid_signature_accepted_and_tampering_rejected():
    v = MessageValidator("N1", SECRETS, max_age=5)
    msg = sign_alert(make_alert(), SECRETS["N2"])
    assert v.validate(msg, 10).reason == "ok"
    tampered = dict(sign_alert(make_alert(aid="N2-2"), SECRETS["N2"]), confidence=1.0)
    assert v.validate(tampered, 10).reason == "bad_signature"
    forged = sign_alert(make_alert(aid="N2-3"), SECRETS["N3"])  # signed with wrong key
    assert v.validate(forged, 10).reason == "bad_signature"


def test_schema_sender_and_content_checks():
    v = MessageValidator("N1", SECRETS, max_age=5)
    assert v.validate("hello", 10).reason == "malformed"
    m = sign_alert(make_alert(), SECRETS["N2"]); m.pop("confidence")
    assert v.validate(m, 10).reason == "schema"
    assert v.validate(sign_alert(make_alert(sender="EVIL"), b"k"), 10).reason == "unknown_sender"
    assert v.validate(sign_alert(make_alert(sender="N1"), SECRETS["N1"]), 10).reason == "unknown_sender"
    bad = v.validate(sign_alert(make_alert(conf=1.7), SECRETS["N2"]), 10)
    assert bad.reason == "invalid_content" and bad.authenticated


def test_freshness_boundaries():
    v = MessageValidator("N1", SECRETS, max_age=5, max_future=1)
    assert v.validate(sign_alert(make_alert(ts=5, aid="a"), SECRETS["N2"]), 10).reason == "ok"
    assert v.validate(sign_alert(make_alert(ts=4, aid="b"), SECRETS["N2"]), 10).reason == "stale"
    assert v.validate(sign_alert(make_alert(ts=11, aid="c"), SECRETS["N2"]), 10).reason == "ok"
    assert v.validate(sign_alert(make_alert(ts=12, aid="d"), SECRETS["N2"]), 10).reason == "future_timestamp"


def test_duplicate_and_replay_detection():
    v = MessageValidator("N1", SECRETS, max_age=5)
    msg = sign_alert(make_alert(ts=10), SECRETS["N2"])
    assert v.validate(msg, 10).reason == "ok"
    assert v.validate(dict(msg), 10).reason == "duplicate"   # same round
    assert v.validate(dict(msg), 12).reason == "replay"      # later round, still fresh
    assert v.validate(dict(msg), 20).reason == "stale"       # too old
