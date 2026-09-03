"""
Bidirectional Data Relay — AnyIO task groups in action
=======================================================

After the SOCKS5 handshake, the proxy has TWO open TCP connections:

    Client  ⟵──stream_a──⟶  Proxy  ⟵──stream_b──⟶  Target

We need to copy bytes in *both* directions simultaneously:

    Client → Target   (upload  / outbound)
    Target → Client   (download / inbound)

This is where AnyIO's **structured concurrency** shines.

Structured concurrency — the big idea
---------------------------------------
In traditional async code (e.g. raw asyncio), you might do:

    asyncio.create_task(pipe_upload())
    asyncio.create_task(pipe_download())

But those tasks are "fire-and-forget".  If one crashes, the other
keeps running and nobody notices.  You have to manually wire up
cancellation, error propagation, and cleanup.

AnyIO (inspired by Trio) offers **task groups** instead:

    async with anyio.create_task_group() as tg:
        tg.start_soon(pipe_upload)
        tg.start_soon(pipe_download)

A task group is a *scope* for concurrent tasks.  It guarantees:

  1. The ``async with`` block does NOT exit until every task in the
     group has finished (or been cancelled).

  2. If ANY task raises an unhandled exception, ALL other tasks in
     the group are cancelled, and the exception propagates out of
     the ``async with`` block.

For our relay, this is perfect: when one direction hits EOF (the
remote side closed), we want the other direction to stop too.  The
task group handles that automatically — we raise ``EndOfStream`` in
one pipe, the task group cancels the other, and the ``async with``
block exits cleanly.

Cancellation — how it works
-----------------------------
When a task group cancels a task, AnyIO injects a ``Cancelled``
exception into whatever ``await`` the task is currently sitting on.
The task's ``finally`` blocks run (so cleanup works), and then the
task exits.  You don't need to check a "should I stop?" flag — it's
cooperative but automatic.

This is why you should always use ``async with`` for streams and
listeners — AnyIO can close them in ``__aexit__`` even if
cancellation happens.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Callable

import anyio
from anyio import BrokenResourceError, ClosedResourceError, EndOfStream
from anyio.abc import ByteStream

if TYPE_CHECKING:
    from socklight.throttle import ThrottleState


# Type alias for a callback that receives a byte count.
# The tracker will pass us one of these so it can count bytes
# without the relay knowing anything about the tracker.
ByteCountCallback = Callable[[int], None]


def _noop(_n: int) -> None:
    """Default callback that does nothing — used when no tracker."""
    pass


async def relay_streams(
    stream_a: ByteStream,
    stream_b: ByteStream,
    on_upload: ByteCountCallback = _noop,
    on_download: ByteCountCallback = _noop,
    chunk_size: int = 65_536,
    throttle: "ThrottleState | None" = None,
    delay_ms: int = 0,
) -> None:
    """Copy data between two streams in both directions.

    This function returns when either side closes the connection
    (or an error occurs).  Both streams are left open — the caller
    is responsible for closing them (usually via ``async with``).

    Parameters
    ----------
    stream_a :
        The "client" side (SOCKS5 client in the container).
    stream_b :
        The "target" side (the upstream server we connected to).
    on_upload :
        Called with the byte count each time data flows a → b.
    on_download :
        Called with the byte count each time data flows b → a.
    chunk_size :
        Max bytes to read in a single ``receive()`` call.
        65 KB is a good default — large enough to be efficient,
        small enough to keep memory bounded.
    throttle :
        Optional ``ThrottleState`` with per-direction bandwidth limits.
        The relay checks ``throttle.download_bps`` / ``upload_bps``
        on *every chunk*, so live updates from the TUI take effect
        without restarting the connection.
    delay_ms :
        Extra latency injected once at the start of the relay,
        simulating a slow/distant server.  Applied before any data
        flows in either direction.

    AnyIO concept — ``create_task_group()``
    ----------------------------------------
    We start two concurrent tasks (upload pipe + download pipe)
    inside a task group.  When one pipe ends (EOF or error), the
    task group auto-cancels the other.  Beautiful cleanup.
    """

    # Simulate connection latency (e.g. a geographically distant server).
    # This happens ONCE, before any data flows.
    if delay_ms > 0:
        await anyio.sleep(delay_ms / 1000.0)

    async def _pipe(
        source: ByteStream,
        dest: ByteStream,
        on_data: ByteCountCallback,
        label: str,
        is_download: bool,
    ) -> None:
        """Copy bytes from *source* to *dest* until EOF.

        Normal exits (silently return, task group cancels sibling):
          EndOfStream        — remote closed cleanly (FIN)
          BrokenResourceError — connection reset (RST) or broken mid-stream
          ClosedResourceError — stream already closed (e.g. by cancel)

        Unexpected errors are re-raised with a direction label so the
        caller (server.py) can log something useful instead of a bare
        ExceptionGroup message.

        Throttle — token bucket
        ------------------------
        We track (window_start, window_bytes) within the current rate
        window.  After sending each chunk we check whether we are ahead
        of the desired throughput and sleep the surplus.  When the caller
        changes ``throttle.download_bps`` / ``upload_bps`` at runtime
        (T key in the TUI) we detect the change and reset the window so
        the new rate takes effect immediately without overshoot.
        """
        last_bps: int | None = -1  # sentinel: forces first-run window reset
        window_start = 0.0
        window_bytes = 0

        try:
            while True:
                data = await source.receive(chunk_size)
                await dest.send(data)
                on_data(len(data))

                if throttle is None:
                    continue

                bps = throttle.download_bps if is_download else throttle.upload_bps

                if bps != last_bps:
                    # Rate changed (or first chunk) — start a fresh window.
                    last_bps = bps
                    window_start = time.monotonic()
                    window_bytes = 0

                if bps is None or bps <= 0:
                    continue

                window_bytes += len(data)
                expected_elapsed = window_bytes / bps
                actual_elapsed = time.monotonic() - window_start

                # If the connection was idle or slow for a long time, the
                # window accumulates a large time credit.  When data resumes
                # the client could burst at full speed until the credit drains.
                # Reset the window whenever we are more than 1 s behind
                # schedule to keep the burst bounded.
                if actual_elapsed > expected_elapsed + 1.0:
                    window_start = time.monotonic()
                    window_bytes = len(data)
                    expected_elapsed = window_bytes / bps
                    actual_elapsed = 0.0

                surplus = expected_elapsed - actual_elapsed
                if surplus > 0.001:  # skip sub-millisecond sleeps
                    await anyio.sleep(surplus)

        except (EndOfStream, BrokenResourceError, ClosedResourceError,
                ConnectionResetError, ConnectionAbortedError, OSError):
            return
        except Exception as exc:
            raise RuntimeError(f"{label}: {type(exc).__name__}: {exc}") from exc

    # ---- Start both pipes concurrently ----
    #
    # ``create_task_group()`` returns a context manager.  Inside
    # the ``async with``, we use ``tg.start_soon(coro_func, args)``
    # to launch concurrent tasks.
    #
    # Note: ``start_soon`` takes a *callable* and its *arguments*
    # separately — NOT an already-created coroutine.  This is
    # different from asyncio's ``create_task(coro())``.
    #
    #   ✅  tg.start_soon(_pipe, stream_a, stream_b, on_upload, "upload", False)
    #   ❌  tg.start_soon(_pipe(stream_a, stream_b, on_upload, "upload", False))
    #
    # The task group calls the callable for you, which lets it
    # set up proper cancellation scopes before the coroutine starts.

    async with anyio.create_task_group() as tg:
        async def _pipe_and_cancel(source, dest, on_data, label, is_download):
            # When either direction finishes (EOF or error), cancel the other.
            # Without this, closing the browser leaves the server-side pipe
            # waiting forever for data that will never arrive.
            try:
                await _pipe(source, dest, on_data, label, is_download)
            finally:
                tg.cancel_scope.cancel()

        tg.start_soon(_pipe_and_cancel, stream_a, stream_b, on_upload,   "upload",   False)
        tg.start_soon(_pipe_and_cancel, stream_b, stream_a, on_download, "download", True)

    # When we reach this line, BOTH pipes have stopped.
    # Either one hit EOF (and the other was cancelled),
    # or both finished naturally.  No leaked tasks!
