"""Integration tests for proxy/server.py — real TCP sockets, anyio.run()."""
from __future__ import annotations
import struct
import anyio
from anyio import EndOfStream, ClosedResourceError
from socklight.filters import FilterEngine, FilterMode, RuleKind
from socklight.server import ProxyServer
from socklight.tracker import ConnectionTracker
from socklight.socks5 import ReplyStatus
from tests.conftest import free_port


def run(coro):
    async def _wrap():
        return await coro
    return anyio.run(_wrap)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _echo_handler(stream):
    """Simple echo server: sends back whatever it receives."""
    async with stream:
        try:
            while True:
                data = await stream.receive(4096)
                await stream.send(data)
        except (EndOfStream, ClosedResourceError):
            pass


async def _socks5_connect(proxy_port: int, dest_ip: tuple[int, ...], dest_port: int):
    """
    Open a SOCKS5 connection through the proxy using an IPv4 address.
    Returns the connected client stream (caller owns it).
    """
    client = await anyio.connect_tcp("127.0.0.1", proxy_port)

    # Phase 1: greeting
    await client.send(struct.pack("!BBB", 5, 1, 0))  # SOCKS5, 1 method, NO_AUTH
    auth = await client.receive(2)
    assert auth == b"\x05\x00", f"Unexpected auth response: {auth.hex()}"

    # Phase 2: CONNECT (IPv4)
    await client.send(
        struct.pack("!BBBB", 5, 1, 0, 1)           # SOCKS5 CONNECT IPv4
        + bytes(dest_ip)                             # 4-byte IP
        + struct.pack("!H", dest_port)              # port
    )
    reply = await client.receive(10)
    return client, reply[1]  # (stream, status_byte)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestProxyServerIntegration:
    def test_full_data_relay(self):
        """Proxy connects to an echo server and relays data both ways."""
        async def _():
            echo_port = free_port()
            proxy_port = free_port()

            async with anyio.create_task_group() as tg:
                # Start echo server
                echo_listener = await anyio.create_tcp_listener(
                    local_host="127.0.0.1", local_port=echo_port
                )
                tg.start_soon(echo_listener.serve, _echo_handler)

                # Start proxy
                server = ProxyServer(
                    tracker=ConnectionTracker(),
                    filter_engine=FilterEngine(FilterMode.DENYLIST),
                    host="127.0.0.1",
                    port=proxy_port,
                    log=lambda _: None,
                )
                tg.start_soon(server.start)
                await anyio.sleep(0.05)

                client, status = await _socks5_connect(
                    proxy_port, (127, 0, 0, 1), echo_port
                )
                assert status == ReplyStatus.SUCCEEDED

                async with client:
                    await client.send(b"hello proxy")
                    data = await client.receive(64)
                    assert data == b"hello proxy"

                tg.cancel_scope.cancel()
        run(_())

    def test_filter_denies_connection(self):
        """A DENYLIST rule causes the proxy to send NOT_ALLOWED."""
        async def _():
            echo_port = free_port()
            proxy_port = free_port()

            engine = FilterEngine(FilterMode.DENYLIST)
            engine.add_rule("127.0.0.1", RuleKind.DENY)

            async with anyio.create_task_group() as tg:
                echo_listener = await anyio.create_tcp_listener(
                    local_host="127.0.0.1", local_port=echo_port
                )
                tg.start_soon(echo_listener.serve, _echo_handler)

                server = ProxyServer(
                    tracker=ConnectionTracker(),
                    filter_engine=engine,
                    host="127.0.0.1",
                    port=proxy_port,
                    log=lambda _: None,
                )
                tg.start_soon(server.start)
                await anyio.sleep(0.05)

                client, status = await _socks5_connect(
                    proxy_port, (127, 0, 0, 1), echo_port
                )
                async with client:
                    assert status == ReplyStatus.NOT_ALLOWED

                tg.cancel_scope.cancel()
        run(_())

    def test_tracker_records_connection(self):
        """Tracker total_connections increments after a successful relay."""
        async def _():
            echo_port = free_port()
            proxy_port = free_port()
            tracker = ConnectionTracker()

            async with anyio.create_task_group() as tg:
                echo_listener = await anyio.create_tcp_listener(
                    local_host="127.0.0.1", local_port=echo_port
                )
                tg.start_soon(echo_listener.serve, _echo_handler)

                server = ProxyServer(
                    tracker=tracker,
                    filter_engine=FilterEngine(FilterMode.DENYLIST),
                    host="127.0.0.1",
                    port=proxy_port,
                    log=lambda _: None,
                )
                tg.start_soon(server.start)
                await anyio.sleep(0.05)

                client, status = await _socks5_connect(
                    proxy_port, (127, 0, 0, 1), echo_port
                )
                assert status == ReplyStatus.SUCCEEDED
                async with client:
                    await client.send(b"x")
                    await client.receive(1)

                await anyio.sleep(0.05)  # let server record the close
                assert tracker.total_connections == 1

                tg.cancel_scope.cancel()
        run(_())

    def test_connection_refused_returns_error_reply(self):
        """Proxy returns CONNECTION_REFUSED when the target port is closed."""
        async def _():
            closed_port = free_port()   # nothing listening here
            proxy_port = free_port()

            async with anyio.create_task_group() as tg:
                server = ProxyServer(
                    tracker=ConnectionTracker(),
                    filter_engine=FilterEngine(FilterMode.DENYLIST),
                    host="127.0.0.1",
                    port=proxy_port,
                    log=lambda _: None,
                )
                tg.start_soon(server.start)
                await anyio.sleep(0.05)

                client, status = await _socks5_connect(
                    proxy_port, (127, 0, 0, 1), closed_port
                )
                async with client:
                    assert status == ReplyStatus.CONNECTION_REFUSED

                tg.cancel_scope.cancel()
        run(_())

    def test_stop_prevents_new_connections(self):
        """After stop(), the proxy rejects new connection attempts."""
        async def _():
            echo_port = free_port()
            proxy_port = free_port()

            async with anyio.create_task_group() as tg:
                echo_listener = await anyio.create_tcp_listener(
                    local_host="127.0.0.1", local_port=echo_port
                )
                tg.start_soon(echo_listener.serve, _echo_handler)

                server = ProxyServer(
                    tracker=ConnectionTracker(),
                    filter_engine=FilterEngine(FilterMode.DENYLIST),
                    host="127.0.0.1",
                    port=proxy_port,
                    log=lambda _: None,
                )
                tg.start_soon(server.start)
                await anyio.sleep(0.05)

                # First connection works fine.
                client1, status1 = await _socks5_connect(
                    proxy_port, (127, 0, 0, 1), echo_port
                )
                assert status1 == ReplyStatus.SUCCEEDED

                # Stop the proxy (closes listener).
                await server.stop()
                await anyio.sleep(0.05)

                # New connection attempt should fail (port closed).
                try:
                    await anyio.connect_tcp("127.0.0.1", proxy_port)
                    assert False, "Expected connection to be refused after stop()"
                except OSError:
                    pass  # expected

                async with client1:
                    pass  # close it

                tg.cancel_scope.cancel()
        run(_())

    def test_multiple_concurrent_connections(self):
        """Proxy handles several concurrent connections correctly."""
        async def _():
            echo_port = free_port()
            proxy_port = free_port()

            async with anyio.create_task_group() as tg:
                echo_listener = await anyio.create_tcp_listener(
                    local_host="127.0.0.1", local_port=echo_port
                )
                tg.start_soon(echo_listener.serve, _echo_handler)

                server = ProxyServer(
                    tracker=ConnectionTracker(),
                    filter_engine=FilterEngine(FilterMode.DENYLIST),
                    host="127.0.0.1",
                    port=proxy_port,
                    log=lambda _: None,
                )
                tg.start_soon(server.start)
                await anyio.sleep(0.05)

                async def one_roundtrip(payload: bytes):
                    client, status = await _socks5_connect(
                        proxy_port, (127, 0, 0, 1), echo_port
                    )
                    assert status == ReplyStatus.SUCCEEDED
                    async with client:
                        await client.send(payload)
                        data = await client.receive(len(payload))
                        assert data == payload

                async with anyio.create_task_group() as inner:
                    for i in range(5):
                        inner.start_soon(one_roundtrip, f"msg-{i}".encode())

                tg.cancel_scope.cancel()
        run(_())

    def test_client_disconnect_during_handshake_or_before_established(self):
        """Proxy should handle client disconnecting abruptly without crashing the server."""
        async def _():
            proxy_port = free_port()
            tracker = ConnectionTracker()

            async with anyio.create_task_group() as tg:
                server = ProxyServer(
                    tracker=tracker,
                    filter_engine=FilterEngine(FilterMode.DENYLIST),
                    host="127.0.0.1",
                    port=proxy_port,
                    log=lambda _: None,
                )
                tg.start_soon(server.start)
                await anyio.sleep(0.05)

                # Connect to proxy but close immediately
                client = await anyio.connect_tcp("127.0.0.1", proxy_port)
                await client.aclose()

                # Also test disconnecting after greeting
                client2 = await anyio.connect_tcp("127.0.0.1", proxy_port)
                await client2.send(struct.pack("!BBB", 5, 1, 0))  # greeting
                # Receive auth response
                auth = await client2.receive(2)
                assert auth == b"\x05\x00"
                # Close immediately without sending connect request
                await client2.aclose()

                # Verify server is still running and can handle new connections
                closed_port = free_port()
                client3, status = await _socks5_connect(
                    proxy_port, (127, 0, 0, 1), closed_port
                )
                async with client3:
                    assert status == ReplyStatus.CONNECTION_REFUSED

                tg.cancel_scope.cancel()
        run(_())
