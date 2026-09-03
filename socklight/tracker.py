"""
Connection Tracker
==================

Keeps a live registry of every connection the proxy has handled.
The TUI reads this to display the connection table and stats.

This module is pure data management — no networking, no AnyIO.

Design decisions
-----------------
- ``ConnectionRecord`` is a *mutable* dataclass (unlike our protocol
  types which are frozen).  We update ``bytes_sent``, ``bytes_recv``,
  ``status``, and ``ended_at`` as the connection progresses.

- The tracker assigns sequential IDs so the TUI can show a stable
  order.  We keep both active and recent closed connections so you
  can see what just happened.

- Callbacks: the tracker supports an ``on_change`` callback so the
  TUI can be notified immediately when something changes.  This is
  a simple observer pattern — no message queues, no framework.
"""

from __future__ import annotations

import enum
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger("proxy.tracker")


class ConnectionStatus(enum.Enum):
    """Lifecycle states of a proxied connection."""

    CONNECTING = "CONNECTING"  # Handshake in progress
    ACTIVE = "ACTIVE"  # Relay running
    CLOSED = "CLOSED"  # Finished normally
    DENIED = "DENIED"  # Blocked by filter
    FAILED = "FAILED"  # Target unreachable / error


# Signature for change callbacks.
# Called with (event_name, connection_record).
ChangeCallback = Callable[[str, "ConnectionRecord"], None]


@dataclass(slots=True)
class ConnectionRecord:
    """Mutable record for one proxied connection.

    We don't use ``frozen=True`` here because we need to update
    byte counts and status as the connection lives.

    ``slots=True`` is still used for performance — we may create
    many of these over a long proxy session.
    """

    id: int
    client_host: str
    client_port: int
    target_host: str
    target_port: int
    status: ConnectionStatus = ConnectionStatus.CONNECTING
    started_at: float = field(default_factory=time.monotonic)
    ended_at: float | None = None
    bytes_sent: int = 0  # client → target (upload)
    bytes_recv: int = 0  # target → client (download)
    category: str = ""  # classifier category name ("unknown" or e.g. "analytics")

    @property
    def duration(self) -> float:
        """Elapsed seconds (still ticking if active)."""
        end = self.ended_at or time.monotonic()
        return end - self.started_at

    @property
    def target(self) -> str:
        """Formatted target as 'host:port' (IPv6 addresses get brackets)."""
        if ":" in self.target_host:
            return f"[{self.target_host}]:{self.target_port}"
        return f"{self.target_host}:{self.target_port}"

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_recv


def format_bytes(n: int) -> str:
    """Human-friendly byte count: 1234 → '1.2 KB'."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    else:
        return f"{n / 1024 / 1024 / 1024:.1f} GB"


class ConnectionTracker:
    """Thread-safe-ish registry of all connections.

    (In asyncio, "thread-safe" is trivially satisfied because
    only one coroutine runs at a time.  But we still keep the
    interface clean for potential Trio use.)
    """

    def __init__(self, max_history: int = 200) -> None:
        self._next_id = 1
        self._active: dict[int, ConnectionRecord] = {}
        self._history: deque[ConnectionRecord] = deque(maxlen=max_history)
        self._callbacks: list[ChangeCallback] = []

        # Incremented on every structural change (open/activate/deny/close).
        # The TUI compares this integer instead of building tuple fingerprints.
        self.structure_version: int = 0

        # Aggregate stats
        self.total_connections = 0
        self.total_denied = 0
        self.total_bytes = 0
        self.total_bytes_sent = 0  # upload (client → target), closed connections only
        self.total_bytes_recv = 0  # download (target → client), closed connections only

    # -- Observer pattern --

    def on_change(self, callback: ChangeCallback) -> None:
        """Register a callback for connection events."""
        self._callbacks.append(callback)

    def _notify(self, event: str, conn: ConnectionRecord) -> None:
        """Invoke all registered callbacks."""
        for cb in self._callbacks:
            try:
                cb(event, conn)
            except Exception as exc:
                logger.debug("tracker callback %r raised: %s", cb, exc)

    # -- Lifecycle methods --

    def open_connection(
        self,
        client_host: str,
        client_port: int,
        target_host: str,
        target_port: int,
        category: str = "",
    ) -> ConnectionRecord:
        """Register a new connection.  Returns the record."""
        conn = ConnectionRecord(
            id=self._next_id,
            client_host=client_host,
            client_port=client_port,
            target_host=target_host,
            target_port=target_port,
            category=category,
        )
        self._next_id += 1
        self._active[conn.id] = conn
        self.total_connections += 1
        self.structure_version += 1
        self._notify("opened", conn)
        return conn

    def activate(self, conn: ConnectionRecord) -> None:
        """Mark a connection as actively relaying data."""
        conn.status = ConnectionStatus.ACTIVE
        self.structure_version += 1
        self._notify("activated", conn)

    def deny(self, conn: ConnectionRecord) -> None:
        """Mark a connection as denied by filter."""
        conn.status = ConnectionStatus.DENIED
        conn.ended_at = time.monotonic()
        self._active.pop(conn.id, None)
        self._add_to_history(conn)
        self.total_denied += 1
        self.structure_version += 1
        self._notify("denied", conn)

    def close(self, conn: ConnectionRecord, failed: bool = False) -> None:
        """Mark a connection as finished."""
        conn.status = ConnectionStatus.FAILED if failed else ConnectionStatus.CLOSED
        conn.ended_at = time.monotonic()
        self.total_bytes += conn.total_bytes
        self.total_bytes_sent += conn.bytes_sent
        self.total_bytes_recv += conn.bytes_recv
        self._active.pop(conn.id, None)
        self._add_to_history(conn)
        self.structure_version += 1
        self._notify("closed", conn)

    # -- Byte counting helpers --
    # These return closures that the relay module can call without
    # knowing about the tracker.  This keeps relay.py decoupled.

    def make_upload_counter(self, conn: ConnectionRecord) -> Callable[[int], None]:
        """Return a callback that increments bytes_sent."""
        def count(n: int) -> None:
            conn.bytes_sent += n
        return count

    def make_download_counter(self, conn: ConnectionRecord) -> Callable[[int], None]:
        """Return a callback that increments bytes_recv."""
        def count(n: int) -> None:
            conn.bytes_recv += n
        return count

    # -- Query methods --

    def get_connection(self, conn_id: int) -> ConnectionRecord | None:
        """Look up a connection by ID — O(1) active check, then history scan."""
        conn = self._active.get(conn_id)
        if conn is not None:
            return conn
        for c in reversed(self._history):
            if c.id == conn_id:
                return c
        return None

    @property
    def active_connections(self) -> list[ConnectionRecord]:
        """Snapshot of currently active connections."""
        return list(self._active.values())

    @property
    def recent_history(self) -> list[ConnectionRecord]:
        """Most recently closed connections (newest first) — full copy."""
        return list(reversed(self._history))

    def get_recent_history(self, limit: int | None = None) -> list[ConnectionRecord]:
        """Like ``recent_history`` but avoids copying the entire deque.

        Uses an O(1) reverse iterator and ``islice`` so only *limit* items
        are materialised — useful when the TUI only needs the last 20 or 50.
        """
        import itertools
        it = reversed(self._history)
        if limit is not None:
            it = itertools.islice(it, limit)
        return list(it)

    # -- Internal --

    def _add_to_history(self, conn: ConnectionRecord) -> None:
        """Move a connection to the history buffer."""
        self._history.append(conn)  # deque evicts oldest automatically via maxlen
