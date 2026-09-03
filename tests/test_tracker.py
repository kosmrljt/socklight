"""Tests for proxy/tracker.py — all synchronous."""
import time
from socklight.tracker import ConnectionRecord, ConnectionStatus, ConnectionTracker, format_bytes


class TestFormatBytes:
    def test_zero(self):
        assert format_bytes(0) == "0 B"

    def test_sub_kilobyte(self):
        assert format_bytes(512) == "512 B"
        assert format_bytes(1023) == "1023 B"

    def test_kilobytes(self):
        assert format_bytes(1024) == "1.0 KB"
        assert format_bytes(2048) == "2.0 KB"

    def test_megabytes(self):
        assert format_bytes(1024 * 1024) == "1.0 MB"
        assert format_bytes(int(1.5 * 1024 * 1024)) == "1.5 MB"

    def test_gigabytes(self):
        assert format_bytes(1024 ** 3) == "1.0 GB"


class TestConnectionRecord:
    def _make(self, **kw):
        defaults = dict(id=1, client_host="127.0.0.1", client_port=0,
                        target_host="example.com", target_port=443)
        return ConnectionRecord(**{**defaults, **kw})

    def test_target_property(self):
        c = self._make(target_host="api.example.com", target_port=8443)
        assert c.target == "api.example.com:8443"

    def test_total_bytes(self):
        c = self._make()
        c.bytes_sent = 100
        c.bytes_recv = 250
        assert c.total_bytes == 350

    def test_duration_still_running(self):
        c = self._make()
        time.sleep(0.05)
        assert c.duration >= 0.04

    def test_duration_after_close(self):
        c = self._make()
        c.ended_at = c.started_at + 2.5
        assert abs(c.duration - 2.5) < 0.01

    def test_default_status(self):
        c = self._make()
        assert c.status == ConnectionStatus.CONNECTING


class TestConnectionTracker:
    def _tracker(self, **kw):
        return ConnectionTracker(**kw)

    def _open(self, t, i=1):
        return t.open_connection("127.0.0.1", i, "example.com", 443)

    # ---- lifecycle ----

    def test_open_assigns_id_and_counts(self):
        t = self._tracker()
        c = self._open(t)
        assert c.id == 1
        assert c.status == ConnectionStatus.CONNECTING
        assert t.total_connections == 1

    def test_ids_increment(self):
        t = self._tracker()
        c1 = self._open(t, 1)
        c2 = self._open(t, 2)
        assert c1.id == 1
        assert c2.id == 2

    def test_activate(self):
        t = self._tracker()
        c = self._open(t)
        t.activate(c)
        assert c.status == ConnectionStatus.ACTIVE
        assert c in t.active_connections

    def test_close_normal(self):
        t = self._tracker()
        c = self._open(t)
        t.activate(c)
        t.close(c)
        assert c.status == ConnectionStatus.CLOSED
        assert c.ended_at is not None
        assert c not in t.active_connections
        assert c in t.recent_history

    def test_close_failed(self):
        t = self._tracker()
        c = self._open(t)
        t.close(c, failed=True)
        assert c.status == ConnectionStatus.FAILED

    def test_deny(self):
        t = self._tracker()
        c = self._open(t)
        t.deny(c)
        assert c.status == ConnectionStatus.DENIED
        assert c.ended_at is not None
        assert t.total_denied == 1
        assert c not in t.active_connections
        assert c in t.recent_history

    # ---- aggregate stats ----

    def test_total_bytes_accumulated_on_close(self):
        t = self._tracker()
        c = self._open(t)
        c.bytes_sent = 100
        c.bytes_recv = 200
        t.close(c)
        assert t.total_bytes == 300

    def test_total_bytes_not_counted_on_deny(self):
        t = self._tracker()
        c = self._open(t)
        c.bytes_sent = 999
        t.deny(c)
        assert t.total_bytes == 0  # deny doesn't count bytes

    def test_multiple_closes_accumulate(self):
        t = self._tracker()
        for i in range(3):
            c = self._open(t, i)
            c.bytes_sent = 100
            t.close(c)
        assert t.total_bytes == 300

    # ---- byte counter closures ----

    def test_upload_counter(self):
        t = self._tracker()
        c = self._open(t)
        up = t.make_upload_counter(c)
        up(100)
        up(50)
        assert c.bytes_sent == 150
        assert c.bytes_recv == 0

    def test_download_counter(self):
        t = self._tracker()
        c = self._open(t)
        dn = t.make_download_counter(c)
        dn(200)
        assert c.bytes_recv == 200
        assert c.bytes_sent == 0

    def test_counters_independent(self):
        t = self._tracker()
        c = self._open(t)
        t.make_upload_counter(c)(10)
        t.make_download_counter(c)(20)
        assert c.bytes_sent == 10
        assert c.bytes_recv == 20

    # ---- history ----

    def test_recent_history_newest_first(self):
        t = self._tracker()
        c1 = self._open(t, 1)
        c2 = self._open(t, 2)
        t.close(c1)
        t.close(c2)
        h = t.recent_history
        assert h[0] is c2
        assert h[1] is c1

    def test_max_history_evicts_oldest(self):
        t = self._tracker(max_history=3)
        conns = [self._open(t, i) for i in range(5)]
        for c in conns:
            t.close(c)
        assert len(t.recent_history) == 3
        # oldest (id=1,2) evicted; newest (id=3,4,5) kept
        ids = {c.id for c in t.recent_history}
        assert ids == {3, 4, 5}

    def test_recent_history_is_snapshot(self):
        t = self._tracker()
        c = self._open(t)
        t.close(c)
        snapshot = t.recent_history
        snapshot.clear()
        assert len(t.recent_history) == 1  # original unaffected

    # ---- active_connections ----

    def test_active_connections_tracks_open(self):
        t = self._tracker()
        c1 = self._open(t, 1)
        c2 = self._open(t, 2)
        assert len(t.active_connections) == 2
        t.close(c1)
        assert len(t.active_connections) == 1
        assert t.active_connections[0] is c2

    # ---- observer callbacks ----

    def test_on_change_fired_for_lifecycle_events(self):
        t = self._tracker()
        events = []
        t.on_change(lambda ev, c: events.append(ev))

        c = self._open(t)
        t.activate(c)
        t.close(c)

        assert events == ["opened", "activated", "closed"]

    def test_on_change_fired_for_deny(self):
        t = self._tracker()
        events = []
        t.on_change(lambda ev, c: events.append(ev))
        c = self._open(t)
        t.deny(c)
        assert "denied" in events

    def test_bad_callback_does_not_crash_proxy(self):
        t = self._tracker()
        t.on_change(lambda ev, c: 1 / 0)
        c = self._open(t)  # should not raise
        t.close(c)         # should not raise

    def test_multiple_callbacks(self):
        t = self._tracker()
        a, b = [], []
        t.on_change(lambda ev, c: a.append(ev))
        t.on_change(lambda ev, c: b.append(ev))
        self._open(t)
        assert a == b == ["opened"]
