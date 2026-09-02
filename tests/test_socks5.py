"""Tests for proxy/socks5.py — async, run with anyio.run()."""
from __future__ import annotations
import struct
import anyio
import pytest
from anyio import EndOfStream
from proxy.socks5 import (
    AddressType,
    AuthMethod,
    ConnectRequest,
    ReplyStatus,
    negotiate_auth,
    read_connect_request,
    read_exact,
    send_reply,
)
from tests.conftest import MockStream


def run(coro):
    """Run an async test body synchronously."""
    async def _wrap():
        return await coro
    return anyio.run(_wrap)


# ---------------------------------------------------------------------------
# read_exact
# ---------------------------------------------------------------------------

class TestReadExact:
    def test_reads_all_bytes(self):
        async def _():
            s = MockStream(b"hello")
            data = await read_exact(s, 5)
            assert data == b"hello"
        run(_())

    def test_reads_partial_chunks(self):
        """chunk_size=1 forces single-byte reads — read_exact must loop."""
        async def _():
            s = MockStream(b"abcde", chunk_size=1)
            data = await read_exact(s, 5)
            assert data == b"abcde"
        run(_())

    def test_reads_fewer_than_available(self):
        async def _():
            s = MockStream(b"hello world")
            data = await read_exact(s, 5)
            assert data == b"hello"
            rest = await read_exact(s, 6)
            assert rest == b" world"
        run(_())

    def test_eof_raises_end_of_stream(self):
        async def _():
            s = MockStream(b"hi")
            with pytest.raises(EndOfStream):
                await read_exact(s, 10)  # only 2 bytes available
        run(_())


# ---------------------------------------------------------------------------
# negotiate_auth
# ---------------------------------------------------------------------------

def _greeting(*methods: int) -> bytes:
    """Build a SOCKS5 greeting packet."""
    return struct.pack("!BB", 5, len(methods)) + bytes(methods)


class TestNegotiateAuth:
    def test_accepts_no_auth(self):
        async def _():
            s = MockStream(_greeting(AuthMethod.NO_AUTH))
            ok = await negotiate_auth(s)
            assert ok is True
            assert s.written == struct.pack("!BB", 5, AuthMethod.NO_AUTH)
        run(_())

    def test_no_auth_among_multiple_methods(self):
        async def _():
            s = MockStream(_greeting(AuthMethod.GSSAPI, AuthMethod.NO_AUTH,
                                     AuthMethod.USERNAME_PASSWORD))
            ok = await negotiate_auth(s)
            assert ok is True
        run(_())

    def test_rejects_when_no_auth_absent(self):
        async def _():
            s = MockStream(_greeting(AuthMethod.USERNAME_PASSWORD))
            ok = await negotiate_auth(s)
            assert ok is False
            assert s.written == struct.pack("!BB", 5, AuthMethod.NO_ACCEPTABLE)
        run(_())

    def test_rejects_wrong_version(self):
        async def _():
            s = MockStream(struct.pack("!BB", 4, 1) + bytes([0]))  # SOCKS4
            ok = await negotiate_auth(s)
            assert ok is False
        run(_())

    def test_partial_reads_handled(self):
        """chunk_size=1 proves the greeting is accumulated correctly."""
        async def _():
            s = MockStream(_greeting(AuthMethod.NO_AUTH), chunk_size=1)
            ok = await negotiate_auth(s)
            assert ok is True
        run(_())


# ---------------------------------------------------------------------------
# read_connect_request
# ---------------------------------------------------------------------------

def _connect_ipv4(ip: tuple[int, ...], port: int) -> bytes:
    return struct.pack("!BBBB", 5, 1, 0, AddressType.IPV4) + bytes(ip) + struct.pack("!H", port)

def _connect_domain(host: str, port: int) -> bytes:
    h = host.encode()
    return struct.pack("!BBBBB", 5, 1, 0, AddressType.DOMAIN, len(h)) + h + struct.pack("!H", port)

def _connect_ipv6(groups: tuple[int, ...], port: int) -> bytes:
    return struct.pack("!BBBB", 5, 1, 0, AddressType.IPV6) + struct.pack("!8H", *groups) + struct.pack("!H", port)


class TestReadConnectRequest:
    def test_ipv4(self):
        async def _():
            s = MockStream(_connect_ipv4((93, 184, 216, 34), 443))
            req = await read_connect_request(s)
            assert req is not None
            assert req.address_type == AddressType.IPV4
            assert req.host == "93.184.216.34"
            assert req.port == 443
        run(_())

    def test_domain(self):
        async def _():
            s = MockStream(_connect_domain("example.com", 80))
            req = await read_connect_request(s)
            assert req is not None
            assert req.address_type == AddressType.DOMAIN
            assert req.host == "example.com"
            assert req.port == 80
        run(_())

    def test_ipv6(self):
        async def _():
            groups = (0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
            s = MockStream(_connect_ipv6(groups, 8080))
            req = await read_connect_request(s)
            assert req is not None
            assert req.address_type == AddressType.IPV6
            assert req.host == "2001:db8::1"
            assert req.port == 8080
        run(_())

    def test_wrong_version_returns_none(self):
        async def _():
            s = MockStream(struct.pack("!BBBB", 4, 1, 0, 1) + bytes(4) + b"\x00\x50")
            req = await read_connect_request(s)
            assert req is None
        run(_())

    def test_unsupported_command_returns_none_and_replies(self):
        async def _():
            # CMD=2 (BIND) — not supported
            s = MockStream(struct.pack("!BBBB", 5, 2, 0, AddressType.IPV4)
                           + bytes(4) + b"\x00\x50")
            req = await read_connect_request(s)
            assert req is None
            # must have sent COMMAND_NOT_SUPPORTED reply
            assert s.written[1] == ReplyStatus.COMMAND_NOT_SUPPORTED
        run(_())

    def test_unknown_address_type_returns_none_and_replies(self):
        async def _():
            s = MockStream(struct.pack("!BBBB", 5, 1, 0, 0xFF))  # 0xFF = unknown atyp
            req = await read_connect_request(s)
            assert req is None
            assert s.written[1] == ReplyStatus.ADDRESS_TYPE_NOT_SUPPORTED
        run(_())

    def test_partial_reads_handled(self):
        async def _():
            s = MockStream(_connect_domain("example.com", 443), chunk_size=1)
            req = await read_connect_request(s)
            assert req is not None
            assert req.host == "example.com"
        run(_())

    def test_connect_request_is_frozen(self):
        req = ConnectRequest(AddressType.DOMAIN, "example.com", 443)
        with pytest.raises((AttributeError, TypeError)):
            req.host = "other.com"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# send_reply
# ---------------------------------------------------------------------------

class TestSendReply:
    def test_succeeded_reply_format(self):
        async def _():
            s = MockStream()
            await send_reply(s, ReplyStatus.SUCCEEDED)
            data = s.written
            assert data[0] == 5                          # version
            assert data[1] == ReplyStatus.SUCCEEDED      # status
            assert data[2] == 0                          # reserved
            assert data[3] == AddressType.IPV4           # bind addr type
            assert len(data) == 10                       # 4 header + 4 addr + 2 port
        run(_())

    def test_not_allowed_status(self):
        async def _():
            s = MockStream()
            await send_reply(s, ReplyStatus.NOT_ALLOWED)
            assert s.written[1] == ReplyStatus.NOT_ALLOWED
        run(_())

    def test_custom_bind_address(self):
        async def _():
            s = MockStream()
            await send_reply(s, ReplyStatus.SUCCEEDED, "1.2.3.4", 9999)
            data = s.written
            assert data[4:8] == bytes([1, 2, 3, 4])
            port = struct.unpack("!H", data[8:10])[0]
            assert port == 9999
        run(_())
