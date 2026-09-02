"""Shared test helpers."""
from __future__ import annotations
import socket
from anyio import EndOfStream


class MockStream:
    """In-memory ByteStream for unit tests.

    ``receive()`` reads from a pre-filled buffer; ``send()`` appends to
    a write buffer.  Setting ``chunk_size`` forces partial reads so you
    can test that callers handle short reads (e.g. ``read_exact``).
    """

    def __init__(self, data: bytes = b"", chunk_size: int | None = None):
        self._read_buf = bytearray(data)
        self._write_buf = bytearray()
        self._chunk_size = chunk_size

    async def receive(self, max_bytes: int = 65536) -> bytes:
        if not self._read_buf:
            raise EndOfStream()
        n = len(self._read_buf) if self._chunk_size is None else self._chunk_size
        n = min(n, max_bytes, len(self._read_buf))
        chunk = bytes(self._read_buf[:n])
        del self._read_buf[:n]
        return chunk

    async def send(self, data: bytes) -> None:
        self._write_buf.extend(data)

    def feed(self, data: bytes) -> None:
        self._read_buf.extend(data)

    @property
    def written(self) -> bytes:
        return bytes(self._write_buf)


def free_port() -> int:
    """Return an OS-assigned free TCP port on localhost."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
