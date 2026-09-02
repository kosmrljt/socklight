"""
Proxy Server — the orchestration layer
========================================

This module wires together all the pieces:

    socks5.py  → parse the client's request
    filters.py → decide if the connection is allowed
    relay.py   → shovel bytes in both directions
    tracker.py → record what happened

AnyIO concepts covered here
----------------------------
- ``create_tcp_listener()`` — creates a socket that accepts
  incoming connections.

- ``listener.serve(handler)`` — runs an infinite accept loop,
  spawning a new task for each client via an internal task group.
  This is the highest-level server API in AnyIO — one line and
  you have a concurrent TCP server.

- ``connect_tcp(host, port)`` — opens an outbound connection.
  Returns a ``SocketStream`` you can read/write on.

- ``move_on_after(seconds)`` — a *cancel scope* with a timeout.
  If the body hasn't finished within *seconds*, AnyIO cancels it.
  This is how you implement connect timeouts without threading.

Architecture
------------
The main entry point is ``ProxyServer.start()``.  It binds a TCP
listener and calls ``serve()`` which runs forever.  For each
incoming client, AnyIO spawns ``_handle_client()`` in a new task.

    ┌───────────┐
    │  Podman   │──── TCP ────▶ listener.serve()
    │ Container │              spawns _handle_client() per connection
    └───────────┘                │
                                 ├─ negotiate_auth()    [socks5.py]
                                 ├─ read_connect_request()
                                 ├─ filter_engine.is_allowed()
                                 ├─ connect_tcp()       [AnyIO]
                                 └─ relay_streams()     [relay.py]
"""

from __future__ import annotations

import logging
import socket
import time
from typing import Callable

import anyio
from anyio import BrokenResourceError, ClosedResourceError, EndOfStream
from anyio.abc import SocketStream

from proxy.socks5 import (
    negotiate_auth,
    read_connect_request,
    send_reply,
    ReplyStatus,
)
from proxy.relay import relay_streams
from proxy.classifier import Classifier
from proxy.filters import FilterEngine
from proxy.throttle import ThrottleEngine, ThrottleState
from proxy.tracker import ConnectionTracker, ConnectionStatus

logger = logging.getLogger("proxy.server")

# Type for the log callback the TUI can provide
LogCallback = Callable[[str], None]

# DNS cache — two-generation eviction.
#
# Writes go only to the ACTIVE table.  When active reaches _DNS_GEN_LIMIT,
# backup is cleared and the two tables swap: the old active becomes the new
# backup (still searchable), and the freshly cleared table becomes active.
# Lookups check active first, then backup — so up to 2× _DNS_GEN_LIMIT
# entries are reachable at any time without unbounded growth.
_DNS_A: dict[str, tuple[str, float]] = {}
_DNS_B: dict[str, tuple[str, float]] = {}
_DNS_ACTIVE = _DNS_A
_DNS_BACKUP = _DNS_B
_DNS_TTL       = 60.0   # seconds — conservative; real TTL requires raw DNS query
_DNS_GEN_LIMIT = 512    # rotate when active reaches this size


async def _resolve(host: str) -> str:
    """Resolve *host* to an IP string, using a two-generation in-process cache.

    DNS resolution is a blocking syscall.  AnyIO runs it in a thread-pool
    worker so it never blocks the event loop.  With the cache, repeat
    connections to the same host skip the thread dispatch entirely.
    """
    global _DNS_ACTIVE, _DNS_BACKUP

    # If host is already an IP address, return it immediately — no DNS needed.
    try:
        socket.inet_pton(socket.AF_INET, host)
        return host
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except OSError:
        pass

    now = time.monotonic()
    for table in (_DNS_ACTIVE, _DNS_BACKUP):
        entry = table.get(host)
        if entry is not None and now < entry[1]:
            return entry[0]

    infos = await anyio.to_thread.run_sync(
        lambda: socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    )
    ip = infos[0][4][0]
    _DNS_ACTIVE[host] = (ip, now + _DNS_TTL)

    if len(_DNS_ACTIVE) >= _DNS_GEN_LIMIT:
        _DNS_BACKUP.clear()
        _DNS_ACTIVE, _DNS_BACKUP = _DNS_BACKUP, _DNS_ACTIVE

    return ip


def _default_log(msg: str) -> None:
    """Fallback logger when no TUI is attached."""
    logger.info(msg)


class ProxyServer:
    """SOCKS5 proxy server built on AnyIO.

    Parameters
    ----------
    tracker :
        Connection tracker for observability.
    filter_engine :
        Filter engine for access control.
    host :
        Address to bind the listener on.  "0.0.0.0" accepts
        connections from any interface (needed for Podman).
    port :
        Port to listen on.  1080 is the conventional SOCKS port.
    connect_timeout :
        Seconds to wait when connecting to the target host.
    log :
        Optional callback for log messages (the TUI passes one).
    """

    def __init__(
        self,
        tracker: ConnectionTracker,
        filter_engine: FilterEngine,
        classifier: Classifier | None = None,
        throttle_engine: ThrottleEngine | None = None,
        host: str = "0.0.0.0",
        port: int = 1080,
        connect_timeout: float = 10.0,
        max_connections: int | None = None,
        log: LogCallback = _default_log,
    ) -> None:
        self.tracker = tracker
        self.filter_engine = filter_engine
        self.classifier = classifier if classifier is not None else Classifier()
        self.throttle_engine = throttle_engine
        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self.log = log
        self._listener = None
        self._cancel_scopes: dict[int, anyio.CancelScope] = {}
        # Per-connection throttle state — shared with the relay task so that
        # live updates from the TUI (T key) propagate without restarting.
        self._conn_throttle: dict[int, ThrottleState] = {}
        # Incremented whenever throttle limits change so the TUI fingerprint
        # can detect updates with a single integer comparison.
        self.throttle_version: int = 0
        # Optional cap on concurrent connections (prevents FD exhaustion).
        self._semaphore = anyio.Semaphore(max_connections) if max_connections else None

    def get_conn_throttle(self, conn_id: int) -> ThrottleState | None:
        """Return the live ThrottleState for *conn_id*, or None."""
        return self._conn_throttle.get(conn_id)

    def set_conn_throttle(
        self,
        conn_id: int,
        download_bps: int | None,
        upload_bps: int | None,
    ) -> bool:
        """Update bandwidth limits for a running connection.

        Returns True if the connection was found.  The relay reads
        these values on the next chunk — no restart required.
        """
        state = self._conn_throttle.get(conn_id)
        if state is None:
            return False
        state.download_bps = download_bps
        state.upload_bps = upload_bps
        self.throttle_version += 1
        return True

    async def start(self) -> None:
        """Bind the listener and serve forever.

        AnyIO concept — ``create_tcp_listener()``
        -------------------------------------------
        This creates a TCP socket, binds it to (host, port), and
        calls listen().  It returns a ``Listener`` object.

        AnyIO concept — ``listener.serve(handler)``
        ---------------------------------------------
        This is the high-level server loop.  It:
          1. Calls ``await listener.accept()`` in a loop
          2. For each new connection, spawns ``handler(stream)``
             as a new task in a task group
          3. Runs forever (until cancelled)

        The handler receives an ``anyio.abc.SocketStream`` — the
        same stream type we use in socks5.py.  AnyIO closes the
        stream automatically when the handler returns or raises.
        """
        self._listener = await anyio.create_tcp_listener(
            local_host=self.host,
            local_port=self.port,
        )
        self.log(f"SOCKS5 proxy listening on {self.host}:{self.port}")

        # serve() accepts forever, spawning _handle_client per connection.
        # When stop() closes the listener, AnyIO's accept() raises
        # ClosedResourceError, which bubbles up through nested task groups
        # as ExceptionGroups.  except* unwraps them recursively (Python 3.11+).
        try:
            await self._listener.serve(self._handle_client)
        except ClosedResourceError:
            pass  # stop() was called — graceful shutdown, not an error
        except Exception as exc:
            # Handle ClosedResourceError wrapped in ExceptionGroups without using except* (for Python 3.10 compatibility)
            def is_closed_resource_error(e: BaseException) -> bool:
                if isinstance(e, ClosedResourceError):
                    return True
                if hasattr(e, "exceptions"):
                    return all(is_closed_resource_error(child) for child in e.exceptions)
                return False

            if is_closed_resource_error(exc):
                pass
            else:
                raise
        finally:
            if self._listener is not None:
                try:
                    await self._listener.aclose()
                except Exception:
                    pass
            self._listener = None

    def cancel_connection(self, conn_id: int) -> bool:
        """Forcibly close an active relay by tracker connection ID.

        AnyIO concept — ``CancelScope.cancel()``
        ------------------------------------------
        Calling ``cancel()`` on a scope from *outside* the task that owns it
        is safe: AnyIO sets a flag, and at the next await point inside the
        scope the cancellation unwinds naturally (streams are closed, finally
        blocks run).  The scope catches the cancellation so it doesn't
        propagate to the parent task group.

        Returns True if a matching relay was found and cancelled.
        """
        scope = self._cancel_scopes.get(conn_id)
        if scope is not None:
            scope.cancel()
            return True
        return False

    async def stop(self) -> None:
        """Close the listener so no new connections are accepted.

        ``serve()`` will then wait for all active connection handlers to
        finish before returning.  Call this instead of cancelling the
        start() task to get graceful (non-RST) connection teardown.
        """
        if self._listener is not None:
            await self._listener.aclose()

    async def _handle_client(self, client_stream: SocketStream) -> None:
        """Handle one SOCKS5 client from handshake to relay.

        If ``max_connections`` was set, waits for a semaphore slot before
        proceeding — this caps concurrency and prevents FD exhaustion.

        This method orchestrates the full connection lifecycle:
          1. Parse the SOCKS5 greeting and CONNECT request
          2. Check the filter rules
          3. Open a connection to the target
          4. Relay data until either side closes
          5. Record everything in the tracker

        The ``async with client_stream:`` ensures the client socket
        is always closed when we're done, even if an error occurs.
        This is AnyIO's resource management pattern — always use
        ``async with`` for streams and listeners.
        """
        # Outer try/except: catch any unexpected exception so a bug in one
        # connection handler cannot propagate into AnyIO's listener task group
        # and crash the entire server.
        if self._semaphore is not None:
            async with self._semaphore:
                await self._handle_client_body(client_stream)
        else:
            await self._handle_client_body(client_stream)

    async def _handle_client_body(self, client_stream: SocketStream) -> None:
        client_host, client_port = "unknown", 0
        try:
            async with client_stream:
                try:
                    # remote_address is a (host, port[, flow, scope]) tuple — unpack first two
                    client_host, client_port, *_ = client_stream.extra(
                        anyio.abc.SocketAttribute.remote_address
                    )
                except Exception:
                    pass

                # ---- Phase 1: SOCKS5 handshake (with timeout) ----
                # ``fail_after(5)`` prevents Slowloris-style DoS: a client that
                # connects but never sends the greeting would otherwise hold a
                # handler task open indefinitely.
                try:
                    with anyio.fail_after(5.0):
                        if not await negotiate_auth(client_stream):
                            self.log(f"AUTH FAIL from {client_host}:{client_port}")
                            return

                        request = await read_connect_request(client_stream)
                        if request is None:
                            self.log(f"BAD REQUEST from {client_host}:{client_port}")
                            return
                except ValueError as exc:
                    # Malformed request (e.g. non-ASCII hostname bytes → UnicodeDecodeError)
                    self.log(f"BAD REQUEST from {client_host}:{client_port}: {exc}")
                    try:
                        await send_reply(client_stream, ReplyStatus.GENERAL_FAILURE)
                    except (EndOfStream, ClosedResourceError, BrokenResourceError, ConnectionError):
                        pass
                    return
                except TimeoutError:
                    self.log(f"TIMEOUT handshake from {client_host}:{client_port}")
                    return
                except (EndOfStream, ClosedResourceError, BrokenResourceError, ConnectionError):
                    # Client disconnected during handshake — nothing to do
                    return

                target = f"{request.host}:{request.port}"

                # ---- Classify connection ----
                cat = self.classifier.classify(request.host)
                cat_tag = f" [{cat.name}]" if cat.name != "unknown" else ""

                # ---- Register in tracker (before any deny so it's visible in TUI) ----
                conn = self.tracker.open_connection(
                    client_host=client_host,
                    client_port=client_port,
                    target_host=request.host,
                    target_port=request.port,
                    category=cat.name,
                )

                # ---- Phase 2 + 3: Filter rules → category → mode default ----
                #
                # Priority (highest first):
                #   1. Explicit URL DENY rule          → block, no further checks
                #   2. Explicit URL ALLOW rule         → pass, bypass category + mode
                #   3. Category deny (@cat / TOML block=true) → block
                #   4. Category allow (@cat override)  → pass, bypass mode default
                #   5. Mode default                    → DENYLIST=pass, ALLOWLIST=block
                allowed, rule = self.filter_engine.check_verbose(
                    request.host, request.port
                )

                if rule is not None:
                    # Explicit URL rule matched — it is the final decision.
                    if not allowed:
                        self.log(f"DENIED  {target}{cat_tag} (rule: {rule.original})")
                        try:
                            await send_reply(client_stream, ReplyStatus.NOT_ALLOWED)
                        except (EndOfStream, ClosedResourceError, BrokenResourceError, ConnectionError):
                            pass
                        self.tracker.deny(conn)
                        return
                    # URL ALLOW rule → fall through to connect (bypasses category + mode)
                else:
                    # No explicit URL rule → category decides, then mode default.
                    if self.classifier.is_category_blocked(cat.name):
                        # deny @cat or TOML block=true
                        self.log(f"BLOCKED {target}{cat_tag}")
                        try:
                            await send_reply(client_stream, ReplyStatus.NOT_ALLOWED)
                        except (EndOfStream, ClosedResourceError, BrokenResourceError, ConnectionError):
                            pass
                        self.tracker.deny(conn)
                        return

                    cat_override = self.classifier.get_cat_override(cat.name)
                    if cat_override is None and not allowed:
                        # No category override + ALLOWLIST mode → block by default.
                        self.log(f"DENIED  {target}{cat_tag} (allowlist: no rule)")
                        try:
                            await send_reply(client_stream, ReplyStatus.NOT_ALLOWED)
                        except (EndOfStream, ClosedResourceError, BrokenResourceError, ConnectionError):
                            pass
                        self.tracker.deny(conn)
                        return
                    # allow @cat override OR DENYLIST default → fall through to connect

                # ---- Throttle lookup ----
                # Must happen after filter/category check (connection already allowed).
                # Pattern rules set the initial rate; the TUI can override it live.
                throttle_rule = (
                    self.throttle_engine.match(request.host, cat.name)
                    if self.throttle_engine is not None
                    else None
                )
                throttle_state = ThrottleState(
                    download_bps=throttle_rule.download_bps if throttle_rule else None,
                    upload_bps=throttle_rule.upload_bps if throttle_rule else None,
                )
                delay_ms = throttle_rule.delay_ms if throttle_rule else 0

                if throttle_rule:
                    extra = throttle_state.summary()
                    if delay_ms:
                        extra += f" delay:{delay_ms}ms"
                    self.log(f"THROTTLE {target} {extra}")

                # ---- Phase 3: Connect to target ----
                try:
                    # AnyIO concept — ``fail_after()``
                    # ----------------------------------
                    # A cancel scope with a hard deadline.  If the body
                    # hasn't finished within *connect_timeout* seconds,
                    # AnyIO cancels it and raises ``TimeoutError``.
                    # We catch that below to send HOST_UNREACHABLE.
                    #
                    # (``move_on_after`` is the softer sibling — it
                    # suppresses the timeout and lets you check
                    # ``scope.cancelled_caught`` instead of catching.)
                    with anyio.fail_after(self.connect_timeout):
                        resolved = await _resolve(request.host)
                        target_stream = await anyio.connect_tcp(
                            resolved, request.port
                        )
                except TimeoutError:
                    self.log(f"TIMEOUT {target}")
                    try:
                        await send_reply(client_stream, ReplyStatus.HOST_UNREACHABLE)
                    except (EndOfStream, ClosedResourceError, BrokenResourceError, ConnectionError):
                        pass
                    self.tracker.close(conn, failed=True)
                    return
                except OSError as exc:
                    self.log(f"FAILED  {target} ({exc})")
                    try:
                        await send_reply(client_stream, ReplyStatus.CONNECTION_REFUSED)
                    except (EndOfStream, ClosedResourceError, BrokenResourceError, ConnectionError):
                        pass
                    self.tracker.close(conn, failed=True)
                    return

                # ---- Phase 4 + 5: Reply, then relay ----
                # async with guarantees target_stream is closed even if the
                # client disconnects before we finish the SUCCEEDED reply (H1).
                async with target_stream:
                    try:
                        await send_reply(client_stream, ReplyStatus.SUCCEEDED)
                    except (EndOfStream, ClosedResourceError, BrokenResourceError, ConnectionError):
                        self.log(f"ERROR   {target}: client disconnected before tunnel established")
                        self.tracker.close(conn, failed=True)
                        return
                    self.tracker.activate(conn)
                    self.log(f"CONNECT {target}{cat_tag}")

                    # Wrap in a CancelScope so cancel_connection() can stop this relay
                    # without touching any other task.
                    relay_scope: anyio.CancelScope
                    with anyio.CancelScope() as relay_scope:
                        self._cancel_scopes[conn.id] = relay_scope
                        self._conn_throttle[conn.id] = throttle_state
                        try:
                            await relay_streams(
                                stream_a=client_stream,
                                stream_b=target_stream,
                                on_upload=self.tracker.make_upload_counter(conn),
                                on_download=self.tracker.make_download_counter(conn),
                                throttle=throttle_state,
                                delay_ms=delay_ms,
                            )
                        except Exception as exc:
                            # ExceptionGroup from relay TaskGroup — unwrap and check
                            # if all sub-exceptions are normal TCP-close errors.
                            # If so, treat as a clean close instead of logging ERROR.
                            subs = getattr(exc, "exceptions", None)
                            if subs is not None:
                                _normal = (BrokenResourceError, ClosedResourceError,
                                           EndOfStream, ConnectionResetError, OSError)
                                if all(isinstance(e, _normal) for e in subs):
                                    self.tracker.close(conn)
                                    return
                            self.log(f"ERROR   {target}: {exc}")
                            self.tracker.close(conn, failed=True)
                            return
                        finally:
                            self._cancel_scopes.pop(conn.id, None)
                            self._conn_throttle.pop(conn.id, None)

                    if relay_scope.cancelled_caught:
                        # cancel_connection() was called — treat as an intentional kill.
                        self.log(f"KILLED  {target}{cat_tag}")
                        self.tracker.close(conn, failed=True)
                        return

                    # ---- Phase 6: Clean close ----
                    self.tracker.close(conn)
                    self.log(f"CLOSED  {target}{cat_tag} ({conn.bytes_sent + conn.bytes_recv} bytes)")

        except Exception as exc:
            # Catch-all: unexpected bugs (UnicodeDecodeError, AttributeError, …)
            # must not escape into listener.serve's task group or the server crashes.
            self.log(f"ERROR   unexpected in handler for {client_host}:{client_port}: {type(exc).__name__}: {exc}")
