"""Tests for proxy/relay.py — async, run with anyio.run()."""
from __future__ import annotations
import anyio
from proxy.relay import relay_streams
from tests.conftest import MockStream


def run(coro):
    async def _wrap():
        return await coro
    return anyio.run(_wrap)


class TestRelayStreams:
    def test_data_flows_a_to_b(self):
        async def _():
            a = MockStream(b"hello")
            b = MockStream(b"")
            await relay_streams(a, b)
            assert b.written == b"hello"
        run(_())

    def test_data_flows_b_to_a(self):
        async def _():
            a = MockStream(b"")
            b = MockStream(b"world")
            await relay_streams(a, b)
            assert a.written == b"world"
        run(_())

    def test_bidirectional_simultaneous(self):
        async def _():
            a = MockStream(b"from-client")
            b = MockStream(b"from-server")
            await relay_streams(a, b)
            assert b.written == b"from-client"
            assert a.written == b"from-server"
        run(_())

    def test_empty_streams_return_immediately(self):
        async def _():
            a = MockStream(b"")
            b = MockStream(b"")
            await relay_streams(a, b)  # both hit EOF immediately — must return
            assert a.written == b""
            assert b.written == b""
        run(_())

    def test_upload_callback_called_with_byte_counts(self):
        async def _():
            a = MockStream(b"hello world")
            b = MockStream(b"")
            counts = []
            await relay_streams(a, b, on_upload=counts.append)
            assert sum(counts) == 11
        run(_())

    def test_download_callback_called_with_byte_counts(self):
        async def _():
            a = MockStream(b"")
            b = MockStream(b"hi there")
            counts = []
            await relay_streams(a, b, on_download=counts.append)
            assert sum(counts) == 8
        run(_())

    def test_chunk_size_limits_read(self):
        """chunk_size=3 should still forward all bytes; just in smaller pieces."""
        async def _():
            payload = b"abcdefghij"  # 10 bytes
            a = MockStream(payload)
            b = MockStream(b"")
            upload_calls = []
            await relay_streams(a, b, on_upload=upload_calls.append, chunk_size=3)
            assert b.written == payload
            # 10 bytes in chunks of 3 → at least 4 calls
            assert len(upload_calls) >= 4
            assert all(n <= 3 for n in upload_calls)
        run(_())

    def test_large_payload(self):
        async def _():
            data = bytes(range(256)) * 100  # 25 600 bytes
            a = MockStream(data)
            b = MockStream(b"")
            await relay_streams(a, b)
            assert b.written == data
        run(_())

    def test_eof_on_a_stops_relay(self):
        """After A is exhausted, relay must return even if B has no data."""
        async def _():
            a = MockStream(b"x")   # one byte, then EOF
            b = MockStream(b"")    # immediately EOF too
            await relay_streams(a, b)
            # If we get here, neither pipe hung
        run(_())
