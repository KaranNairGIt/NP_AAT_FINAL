"""Length-prefixed JSON framing over asyncio TCP, plus a reconnecting peer link.

Frame = 4-byte big-endian length + UTF-8 JSON body. TCP is a byte stream,
so `readexactly` is used to survive partial reads.
"""
from __future__ import annotations

import asyncio
import json
import logging
import struct
from typing import Any, Optional

HEADER = struct.Struct("!I")
log = logging.getLogger("cids.transport")


class FrameError(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def encode_frame(payload: Any, max_bytes: int) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(body) > max_bytes:
        raise FrameError("oversized", f"{len(body)} > {max_bytes}")
    return HEADER.pack(len(body)) + body


async def read_frame(reader: asyncio.StreamReader, max_bytes: int) -> Optional[bytes]:
    """Return one frame body, None on clean EOF, or raise FrameError."""
    try:
        header = await reader.readexactly(HEADER.size)
    except asyncio.IncompleteReadError as e:
        if not e.partial:
            return None
        raise FrameError("truncated_frame", "partial header") from None
    (length,) = HEADER.unpack(header)
    if length == 0:
        raise FrameError("empty_frame")
    if length > max_bytes:
        raise FrameError("oversized", f"{length} > {max_bytes}")
    try:
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        raise FrameError("truncated_frame", "partial body") from None


def decode_payload(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise FrameError("invalid_json", str(e)) from None


class PeerLink:
    """Persistent client connection to one peer with timeout and back-off reconnect."""

    def __init__(self, peer_id: str, host: str, port: int,
                 timeout: float = 0.5, retry_after: int = 2) -> None:
        self.peer_id, self.host, self.port = peer_id, host, port
        self.timeout, self.retry_after = timeout, retry_after
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._next_retry = 0
        self.ever_connected = False
        self.up = False
        self.attempts = self.sent = self.failed = self.reconnects = self.bytes_sent = 0

    async def _connect(self, now: int) -> bool:
        if now < self._next_retry:
            return False
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), self.timeout)
        except (OSError, asyncio.TimeoutError):
            self._next_retry = now + self.retry_after
            self.up = False
            return False
        if self.ever_connected:
            self.reconnects += 1
            log.info("reconnected to %s", self.peer_id)
        self.ever_connected = True
        self.up = True
        return True

    async def send(self, frame: bytes, now: int) -> bool:
        self.attempts += 1
        # A peer that closed its side shows up as EOF on our reader.
        if self._writer is not None and (self._writer.is_closing()
                                         or (self._reader is not None and self._reader.at_eof())):
            await self.close()
        if self._writer is None and not await self._connect(now):
            self.failed += 1
            return False
        assert self._writer is not None
        try:
            self._writer.write(frame)
            await asyncio.wait_for(self._writer.drain(), self.timeout)
        except (OSError, ConnectionError, asyncio.TimeoutError):
            await self.close()
            self._next_retry = now + self.retry_after
            self.failed += 1
            return False
        self.sent += 1
        self.bytes_sent += len(frame)
        return True

    async def close(self) -> None:
        w, self._writer, self._reader = self._writer, None, None
        self.up = False
        if w is not None:
            w.close()
            try:
                await asyncio.wait_for(w.wait_closed(), 0.5)
            except (OSError, ConnectionError, asyncio.TimeoutError):
                pass
