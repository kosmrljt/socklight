"""
Terminal UI — built with Textual
=================================

This is the interactive dashboard for the proxy.  It shows:
  • Active + recent connections (live-updating table)
  • Active filter rules with DENY / ALLOW indicators
  • A command input for managing rules and log level
  • A colour-coded activity log

TUI commands
------------
  deny <pattern>            Add a DENY rule
  allow <pattern>           Add an ALLOW rule
  remove <pattern>          Remove a rule (by host pattern)
  mode denylist|allowlist   Set the default policy
  reload                    Re-read the rules file (if one was loaded)
  loglevel all|connections|denied|errors|none
                            Change what the log shows
  block/unblock <cat>       Block or unblock a connection category
  cats                      List all categories
  dump [path]               Save connections + log to a file (snapshot)
  clear                     Clear all rules
  quit / exit               Shut down

LogLevel — what gets shown
--------------------------
  all          every message (default)
  connections  CONNECT and CLOSED only
  denied       DENIED only
  errors       FAILED, TIMEOUT, ERROR
  none         silence the log completely
"""

from __future__ import annotations

import enum
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from collections import deque
from pathlib import Path
from typing import IO

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]

import anyio
from rich.markup import escape as markup_escape
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.suggester import SuggestFromList
from textual.widgets import (
    DataTable,
    Footer,
    Input,
    Label,
    RichLog,
    Static,
)
from textual.widget import Widget

from proxy.classifier import Classifier
from proxy.filters import FilterEngine, FilterMode, RuleKind
from proxy.server import ProxyServer
from proxy.throttle import ThrottleEngine, format_speed, parse_throttle_args
from proxy.tracker import ConnectionTracker, ConnectionStatus, format_bytes


# ---------------------------------------------------------------------------
# Theme config persistence
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path.home() / ".config" / "socks5proxy" / "config.toml"


def _load_theme_config() -> str | None:
    """Read the saved UI theme from the config file. Returns None if not set."""
    try:
        with open(_CONFIG_PATH, "rb") as fh:
            data = tomllib.load(fh)
        return data.get("ui", {}).get("theme")
    except (OSError, Exception):
        return None


def _save_theme_config(theme: str) -> None:
    """Write the chosen theme to the config file, preserving other keys."""
    try:
        _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(_CONFIG_PATH, "rb") as fh:
                data: dict = tomllib.load(fh)
        except (OSError, Exception):
            data = {}
        data.setdefault("ui", {})["theme"] = theme
        # Serialise back with a simple hand-rolled TOML writer (no tomli_w needed).
        parts: list[str] = []
        for section, values in data.items():
            parts.append(f"[{section}]")
            for k, v in values.items():
                parts.append(f'{k} = "{v}"' if isinstance(v, str) else f"{k} = {v}")
            parts.append("")
        _CONFIG_PATH.write_text("\n".join(parts), encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Log-level filtering
# ---------------------------------------------------------------------------

class LogLevel(enum.Enum):
    """Controls which proxy messages are shown in the activity log."""

    ALL = "all"
    CONNECTIONS = "connections"   # CONNECT + CLOSED
    DENIED = "denied"            # blocked connections
    ERRORS = "errors"            # FAILED / TIMEOUT / ERROR
    NONE = "none"


# Keywords used to classify a log message — matched against the FIRST word only
# to avoid false positives on hostnames (e.g. "reconnect.example.com").
_CONNECT_KW  = {"CONNECT", "CLOSED", "LISTEN"}
_DENIED_KW   = {"DENIED", "BLOCKED"}
# "AUTH FAIL" and "BAD REQUEST" are two-word prefixes; match on first word only.
_ERROR_KW    = {"FAILED", "TIMEOUT", "ERROR", "AUTH", "BAD"}


def _passes_level(message: str, level: LogLevel) -> bool:
    """Return True if *message* should be shown at *level*."""
    if level == LogLevel.ALL:
        return True
    if level == LogLevel.NONE:
        return False
    first = message.split(None, 1)[0].upper() if message else ""
    if level == LogLevel.CONNECTIONS:
        return first in _CONNECT_KW
    if level == LogLevel.DENIED:
        return first in _DENIED_KW
    if level == LogLevel.ERRORS:
        return first in _ERROR_KW
    return True


# ---------------------------------------------------------------------------
# _NoSelectStatic — Static that disables mouse text-selection
# ---------------------------------------------------------------------------

class _NoSelectStatic(Static):
    """Static widget used for read-only panels where mouse selection is unwanted."""
    ALLOW_SELECT = False


# ---------------------------------------------------------------------------
# SplitHandle — draggable separator between two vertically stacked widgets
# ---------------------------------------------------------------------------

class SplitHandle(Widget):
    """Thin bar between two widgets; drag or use ↑↓ keys to resize them."""

    DEFAULT_CSS = """
    SplitHandle {
        height: 1;
        background: $primary-background;
        color: $text;
        text-style: bold;
        padding: 0 0 0 1;
    }
    SplitHandle:hover {
        background: $primary 20%;
    }
    SplitHandle:focus {
        background: $primary 30%;
    }
    """

    def __init__(self, top_id: str, bottom_id: str, label: str = "", **kwargs) -> None:
        super().__init__(**kwargs)
        self._top_id = top_id
        self._bottom_id = bottom_id
        self._label = label
        self._dragging = False
        self._drag_start_y = 0
        self._top_start_height = 0

    def render(self) -> str:
        return self._label

    def on_mouse_down(self, event: events.MouseDown) -> None:
        self._dragging = True
        self._drag_start_y = event.screen_y
        self._top_start_height = self.app.query_one(f"#{self._top_id}").size.height
        self.capture_mouse()
        event.stop()

    def on_mouse_move(self, event: events.MouseMove) -> None:
        if not self._dragging:
            return
        top = self.app.query_one(f"#{self._top_id}")
        bottom = self.app.query_one(f"#{self._bottom_id}")
        total = top.size.height + bottom.size.height
        new_top = max(3, self._top_start_height + (event.screen_y - self._drag_start_y))
        new_top = min(new_top, total - 3)
        top.styles.height = new_top
        bottom.styles.height = total - new_top
        event.stop()

    def on_mouse_up(self, event: events.MouseUp) -> None:
        self._dragging = False
        self.release_mouse()
        event.stop()


# ---------------------------------------------------------------------------
# DataTable with header-hover disabled
# ---------------------------------------------------------------------------

class _ConnectionsTable(DataTable):
    """DataTable that suppresses the mouse-hover highlight on the header row."""

    def _on_mouse_move(self, event: events.MouseMove) -> None:
        meta = event.style.meta
        if meta and meta.get("row") == -1:   # header row → no hover effect
            self._set_hover_cursor(False)
            return
        super()._on_mouse_move(event)


# ---------------------------------------------------------------------------
# Autocomplete suggestions for the command input
# ---------------------------------------------------------------------------

_CMD_SUGGESTIONS = SuggestFromList(
    [
        "deny ", "deny @", "allow ", "allow @", "remove ", "remove @",
        "block ", "unblock ", "cats",
        "mode denylist", "mode allowlist",
        "loglevel all", "loglevel connections", "loglevel denied",
        "loglevel errors", "loglevel none",
        "throttle ", "throttles", "throttles clear",
        "reload", "clear", "clear deny", "clear allow", "dump",
        "save ", "save pac ", "save privoxy ", "kill ", "help", "quit",
    ],
    case_sensitive=False,
)

# ---------------------------------------------------------------------------
# Help modal
# ---------------------------------------------------------------------------

_HELP_MARKUP = """\
[bold]Key bindings[/]

  [dim]Connection actions[/]
  [cyan]I[/]            info: DNS + GeoIP lookup for selected row
  [cyan]K[/]            kill selected connection  [dim](force-close relay)[/]
  [cyan]D[/]            [red]✗[/] deny selected host  [dim](prepend deny rule + kill)[/]
  [cyan]A[/]            [green]✓[/] allow selected host  [dim](bypasses category block)[/]
  [cyan]R[/]            remove deny/allow rule for selected host
  [cyan]M[/]            mark for review  [dim](appended to marks.log)[/]
  [cyan]Y[/]            copy hostname to clipboard
  [cyan]T[/]            fill command input with throttle rule for this host

  [dim]View[/]
  [cyan]H[/]            toggle history  [dim](show / hide closed rows)[/]
  [cyan]C[/]            clear activity log
  [cyan]?[/]            show this help  [dim](also: F1)[/]
  [cyan]F2[/]           show categories reference
  [cyan]Q[/]            quit  [dim](also: Ctrl+Q)[/]

  [dim]Navigation[/]
  [cyan]Tab[/]          move focus between panels
  [cyan]Escape[/]       clear command input / return focus to table
  [cyan]End[/]          resume log auto-scroll
  [cyan]Shift+↑ ↓[/]    scroll filter list          [cyan]Ctrl+↑ ↓[/]  scroll categories

  [dim]In command input[/]
  [cyan]↑ ↓[/]          browse command history
  [cyan]→[/]            accept autocomplete suggestion

[bold]Commands[/]

  [dim]Filter rules[/]
  [cyan]deny[/] [dim]<host>[/]              [red]✗[/] add deny rule  [dim](wildcards: *.ads.com  *.evil.*)[/]
  [cyan]allow[/] [dim]<host>[/]             [green]✓[/] add allow rule  [dim](bypasses category block)[/]
  [cyan]remove[/] [dim]<host>[/]            remove a specific rule
  [cyan]mode[/] [dim]denylist|allowlist[/]  set default policy
  [cyan]clear[/]                    remove all rules
  [cyan]clear deny[/]               remove all deny rules
  [cyan]clear allow[/]              remove all allow rules
  [cyan]reload[/]                   re-read rules file from disk  [dim](requires --rules-file)[/]
  [cyan]save[/] [dim]<path>[/]              write current rules to file
  [cyan]save pac[/] [dim]<path>[/]          export PAC file for browser  [dim](deny+categories→blocked, allow→DIRECT)[/]
  [cyan]save privoxy[/] [dim]<path>[/]      export Privoxy action + config snippet  [dim](same rules, HTTP/S→SOCKS5)[/]

  [dim]Category overrides[/]  [dim](use @name or @ABBREV)[/]
  [cyan]deny[/] [dim]@<name|abbrev>[/]      [red]⊘[/] block category  [dim](e.g. deny @ADV)[/]
  [cyan]allow[/] [dim]@<name|abbrev>[/]     [green]✓[/] explicitly allow category  [dim](overrides TOML default block)[/]
  [cyan]remove[/] [dim]@<name|abbrev>[/]    reset category to TOML default  [dim](no validation)[/]
  [cyan]block[/] [dim]<name|abbrev>[/]      alias for deny @  [dim](legacy)[/]
  [cyan]unblock[/] [dim]<name|abbrev>[/]    alias for allow @  [dim](legacy)[/]
  [cyan]cats[/]                     list all categories with status

  [dim]Utility[/]
  [cyan]kill[/] [dim]<id>[/]                force-close a relay
  [cyan]dump[/] [dim]<path>[/]              save snapshot to file  [dim](connections + log)[/]
  [cyan]loglevel[/] [dim]<level>[/]         filter the activity log
                           [dim]all  connections  denied  errors  none[/]

[bold]Throttling[/]  [dim](filter checked first; applies to allowed connections only)[/]

  [dim]Host rules[/]
  [cyan]throttle[/] [dim]<host> <speed>[/]                     both directions
  [cyan]throttle[/] [dim]<host> down:<speed> up:<speed>[/]     per-direction (asymmetric)
  [cyan]throttle[/] [dim]<host> delay:<n>ms[/]                 latency only
  [cyan]throttle[/] [dim]<host> <speed> delay:<n>ms[/]         bandwidth + latency combined
  [cyan]throttle[/] [dim]<host> off[/]                         remove host rule

  [dim]Category rules[/]  [dim](host rule takes priority if both match)[/]
  [cyan]throttle[/] [dim]@<name|abbrev> <speed>[/]             throttle entire category
  [cyan]throttle[/] [dim]@<name|abbrev> off[/]                 remove category rule

  [dim]Live override[/]
  [cyan]throttle[/] [dim]#<id> <speed>[/]                      override one connection  [dim](not saved)[/]

  [cyan]throttles[/]                                   list all throttle rules
  [cyan]throttles clear[/]                             remove all throttle rules

  [dim]Examples[/]
  [dim]  throttle *.slow.com 200k[/]
  [dim]  throttle *.cdn.com down:500k up:2m[/]
  [dim]  throttle @analytics 100k[/]
  [dim]  throttle @ADV down:50k[/]
  [dim]  throttle api.remote.com delay:300ms[/]

  [dim]Speed units:  200k = 200 KB/s  ·  1m = 1 MB/s  ·  500 = 500 B/s[/]
"""


class HelpScreen(ModalScreen):
    """Modal overlay showing key bindings and commands."""

    BINDINGS = [
        Binding("escape",        "dismiss", "Close"),
        Binding("question_mark", "dismiss", "Close", show=False),
        Binding("f1",            "dismiss", "Close", show=False),
        Binding("q",             "dismiss", "Close", show=False),
    ]

    DEFAULT_CSS = """
    HelpScreen { align: center middle; }
    HelpScreen > VerticalScroll {
        background: $surface;
        border: solid $primary;
        width: 120;
        max-width: 95%;
        height: auto;
        max-height: 90%;
        padding: 1 2;
    }
    """

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(_HELP_MARKUP, markup=True)


_CATS_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}
_EMA_ALPHA     = 0.3   # smoothing factor for per-connection speed display
_SPEED_MIN_BPS = 1000  # below 1 KB/s hide speed
_CATS_SEV_LABEL = {
    "high":   "── high ──",
    "medium": "── medium ──",
    "low":    "── low ──",
    "info":   "── info ──",
}


def _build_cats_markup(cats: list) -> str:
    sorted_cats = sorted(
        cats, key=lambda c: (_CATS_SEVERITY_RANK.get(c.severity, 4), c.name)
    )
    lines = ["[bold]Categories[/]", ""]
    prev_sev = None
    for cat in sorted_cats:
        sev = cat.severity or "info"
        if sev != prev_sev:
            if prev_sev is not None:
                lines.append("")
            lines.append(f"[dim]{_CATS_SEV_LABEL.get(sev, f'── {sev} ──')}[/]")
            lines.append("")
            prev_sev = sev
        col = cat.color or "white"
        abbrev_text = f"{markup_escape(cat.abbrev):<5}"
        name_text = markup_escape(f"{cat.name:<24}")
        # geo_hint as dim plain text — avoid [XX] being parsed as Rich markup tag
        geo = f" [dim]{markup_escape(cat.geo_hint)}[/]" if cat.geo_hint else ""
        blk = " [red]● blocked[/]" if cat.block else ""
        desc = f" [dim]{markup_escape(cat.description)}[/]" if cat.description else ""
        lines.append(f"  [{col}]{abbrev_text}[/]  [bold]{name_text}[/]{geo}{blk}{desc}")
    return "\n".join(lines)


class CatsScreen(ModalScreen):
    """Modal overlay showing all loaded categories, sorted by severity."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("f2",     "dismiss", "Close", show=False),
        Binding("q",      "dismiss", "Close", show=False),
    ]

    DEFAULT_CSS = """
    CatsScreen { align: center middle; }
    CatsScreen > VerticalScroll {
        background: $surface;
        border: solid $primary;
        width: 140;
        max-width: 95%;
        height: auto;
        max-height: 90%;
        padding: 1 2;
    }
    """

    def __init__(self, markup: str) -> None:
        super().__init__()
        self._markup = markup

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(self._markup, markup=True)


# ---------------------------------------------------------------------------
# ProxyApp
# ---------------------------------------------------------------------------

class ProxyApp(App):
    """SOCKS5 dev proxy TUI.

    Parameters
    ----------
    proxy_host, proxy_port :
        Address the proxy listens on.
    log_level :
        Initial log verbosity (can be changed at runtime with ``loglevel``).
    log_file :
        Optional path.  Every log line is also written here as plain
        text (no ANSI codes), one line per entry.
    rules_file :
        Optional path to a rules file loaded at startup (and on
        ``reload``).
    """

    TITLE = "sockLight — SOCKS5 Dev Proxy"

    # Keep the command input and status bar visible when a widget is maximized
    # so that T (throttle), D (deny), etc. can still prepopulate the input.
    ALLOW_IN_MAXIMIZED_VIEW = "Footer, #command-input, #status-bar"

    BINDINGS = [
        Binding("q", "graceful_quit", "Quit"),
        Binding("ctrl+q", "graceful_quit", "Quit", show=False),
        Binding("i", "info_selected", "Info"),
        Binding("k", "kill_selected", "Kill conn"),
        Binding("d", "deny_selected",  "Deny host"),
        Binding("a", "allow_selected", "Allow host"),
        Binding("r", "remove_rule_selected", "Remove rule"),
        Binding("m", "mark_selected", "Mark"),
        Binding("t", "throttle_selected", "Throttle"),
        Binding("h", "toggle_history", "History"),
        Binding("c", "clear_log", "Clear Log"),
        Binding("tab", "focus_next", "Next Widget", show=False),
        Binding("shift+up",   "filter_scroll_up",   "Filter ↑", show=False),
        Binding("shift+down", "filter_scroll_down", "Filter ↓", show=False),
        Binding("ctrl+up",    "cat_scroll_up",      "Cat ↑",    show=False),
        Binding("ctrl+down",  "cat_scroll_down",    "Cat ↓",    show=False),
        Binding("end",           "log_resume",   "Log end", show=False),
        Binding("escape",        "escape_input", show=False),
        Binding("question_mark", "show_help",    "Help"),
        Binding("f1",            "show_help",    "Help", show=False),
        Binding("f2",            "show_cats",    "Cats", show=False),
        Binding("y",             "copy_target",  "Copy URL", show=False),
    ]

    CSS = """
    #stats-bar {
        height: 1;
        padding: 0 1;
        background: $primary-background;
    }
    #stat-title {
        color: $text;
        text-style: bold;
        padding: 0 3 0 0;
        width: auto;
    }
    #stats-bar Label {
        padding: 0 2;
        width: auto;
        color: $text-muted;
    }
    #main-area { height: 1fr; }
    #left-panel { width: 3fr; }
    #right-panel {
        width: 1fr;
        min-width: 32;
        border-left: solid $primary;
        padding: 0 1;
    }
    #connections-table { height: 2fr; }
    #connections-table > .datatable--cursor {
        background: $primary 25%;
    }
    DataTable > .datatable--hover {
        background: transparent;
    }
    DataTable > .datatable--header-hover {
        background: $panel;
    }
    Static:hover {
        background: transparent;
    }
    Label:hover {
        background: transparent;
    }
    .section-title:hover {
        background: $primary-background;
    }
    #activity-log      { height: 1fr; }
    #filter-list        { height: 1fr; }
    #categories-list    { height: auto; max-height: 50%; }
    #categories-content { height: auto; }
    #command-input     { dock: bottom; }
    #status-bar {
        dock: bottom;
        height: 1;
        padding: 0 1;
        color: $text-muted;
        background: $surface-darken-1;
    }
    .section-title {
        text-style: bold;
        padding: 0 0 0 1;
        color: $text;
        background: $primary-background;
    }
    """

    def __init__(
        self,
        proxy_host: str = "0.0.0.0",
        proxy_port: int = 1080,
        log_level: LogLevel = LogLevel.ALL,
        log_file: str | None = None,
        rules_file: str | None = None,
        categories_file: str | None = None,
        theme_name: str | None = None,
        max_connections: int | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.log_level = log_level
        self.log_file = Path(log_file) if log_file else None
        self.rules_file = Path(rules_file) if rules_file else None
        self.categories_file = Path(categories_file) if categories_file else None
        self._initial_theme = theme_name  # from --theme flag; falls back to saved config
        self._startup_done = False  # guard: don't save theme during startup
        self._max_connections = max_connections

        self.tracker = ConnectionTracker()
        self.filter_engine = FilterEngine(mode=FilterMode.DENYLIST)
        self.classifier = Classifier()
        self.throttle_engine = ThrottleEngine()

        self._server: ProxyServer | None = None
        self._log_fh: IO[str] | None = None
        self._wl_copy_proc: subprocess.Popen | None = None

        # Stable-table state — connections stay in their row; no rebuild on close.
        self._display_order: list[int] = []        # conn IDs in insertion order
        self._display_set: set[int] = set()        # same, O(1) lookup
        self._in_table: set[int] = set()           # IDs currently rendered in DataTable
        self._last_statuses: dict[int, ConnectionStatus] = {}
        self._last_throttle_v: int = 0
        self._last_show_history: bool = True
        # Cache of last displayed cell text per conn id → (sent, recv, dur).
        # update_cell is only called when the formatted string actually changes.
        self._cell_display: dict[int, tuple[str, str, str]] = {}
        # EMA speed tracking: prev sample (time, bytes_sent, bytes_recv) and smoothed rates.
        self._speed_prev: dict[int, tuple[float, int, int]] = {}
        self._speed_ema: dict[int, tuple[float, float]] = {}
        self._speed_display: dict[int, tuple[str, str]] = {}

        self._stats_fingerprint: tuple = ()
        self._filters_fingerprint: int = 0
        self._categories_fingerprint: tuple = ()
        self._log_buffer: deque[str] = deque(maxlen=2000)  # plain text, no markup
        self._show_history: bool = True  # H key toggles closed/denied/failed rows
        self._log_paused: bool = False
        self._log_skip_pause: int = 0  # skip re-pause checks after explicit resume
        self._cmd_history: deque[str] = deque(maxlen=100)
        self._cmd_history_idx: int = -1   # -1 = not browsing
        self._cmd_current: str = ""       # saved draft when browsing history

        # Widget cache — populated in on_mount, avoids query_one() on every tick.
        self._w_table: _ConnectionsTable
        self._w_log: RichLog
        self._w_status: Label
        self._w_total: Label
        self._w_active: Label
        self._w_denied: Label
        self._w_traffic: Label
        self._w_loglevel: Label
        self._w_filter_mode: Label
        self._w_filter_rules: _NoSelectStatic
        self._w_categories: _NoSelectStatic
        self._cat_tick: int = 0

    # ---- widget tree ----

    def compose(self) -> ComposeResult:
        with Horizontal(id="stats-bar"):
            yield Label("SOCKS5 Proxy", id="stat-title")
            yield Label("Connections: 0", id="stat-total")
            yield Label("Active: 0", id="stat-active")
            yield Label("Denied: 0", id="stat-denied")
            yield Label("Traffic: 0 B", id="stat-traffic")
            yield Label(f"⚡ {self.proxy_host}:{self.proxy_port}", id="stat-listen")
            yield Label("Log: all", id="stat-loglevel")

        with Horizontal(id="main-area"):
            with Vertical(id="left-panel"):
                yield Static(" Connections", classes="section-title")
                yield _ConnectionsTable(id="connections-table", cursor_type="row")
                yield SplitHandle("connections-table", "activity-log", label="Activity Log")
                yield RichLog(id="activity-log", highlight=True, markup=True, max_lines=200)

            with Vertical(id="right-panel"):
                yield Static(" Filters", classes="section-title")
                yield Label("Mode: DENYLIST", id="filter-mode")
                yield VerticalScroll(
                    _NoSelectStatic("(no rules)", id="filter-rules-content"),
                    id="filter-list",
                    can_focus=False,
                )
                yield Static(" Categories", classes="section-title")
                with VerticalScroll(id="categories-list", can_focus=False):
                    yield _NoSelectStatic("(use --categories-file to load)", id="categories-content")

        yield Input(
            placeholder="command  (? for help, ↑↓ history, → autocomplete)",
            id="command-input",
            suggester=_CMD_SUGGESTIONS,
            select_on_focus=False,
        )
        yield Label("", id="status-bar")
        yield Footer()

    # ---- lifecycle ----

    def on_mount(self) -> None:
        # Open the log file handle once; keep it open until on_unmount.
        if self.log_file:
            try:
                self._log_fh = self.log_file.open("a", buffering=1)  # line-buffered
            except OSError as exc:
                self._log_fh = None
                # Can't log to file, but the TUI still works.
                self.notify(f"Cannot open log file: {exc}", severity="warning")

        # Cache widget references — avoids query_one() traversal on every tick/log.
        self._w_table    = self.query_one("#connections-table", _ConnectionsTable)
        self._w_log      = self.query_one("#activity-log", RichLog)
        self._w_status   = self.query_one("#status-bar", Label)
        self._w_total    = self.query_one("#stat-total",    Label)
        self._w_active   = self.query_one("#stat-active",   Label)
        self._w_denied   = self.query_one("#stat-denied",   Label)
        self._w_traffic  = self.query_one("#stat-traffic",  Label)
        self._w_loglevel = self.query_one("#stat-loglevel", Label)
        self._w_filter_mode    = self.query_one("#filter-mode", Label)
        self._w_filter_rules   = self.query_one("#filter-rules-content", _NoSelectStatic)
        self._w_categories      = self.query_one("#categories-content", _NoSelectStatic)

        self._w_table.add_column("ID",       key="id")
        self._w_table.add_column("Status",   key="status")
        self._w_table.add_column("Cat",      key="cat")
        self._w_table.add_column("Target",   key="target")
        self._w_table.add_column("Throttle", key="throttle")
        self._w_table.add_column("↑KB/s",    key="up", width=6)
        self._w_table.add_column("↓KB/s",    key="dn", width=6)
        self._w_table.add_column("Sent",     key="sent")
        self._w_table.add_column("Recv",     key="recv")
        self._w_table.add_column("Duration", key="dur")

        self._cat_tick = 0  # throttle _refresh_categories to every 3 ticks

        # Load rules and categories before the proxy starts.
        if self.rules_file:
            self._load_rules_file()
            self._refresh_filters()
        if self.categories_file:
            try:
                n = self.classifier.load_file(self.categories_file)
                self._proxy_log(
                    f"CATEGORIES loaded {n} from {self.categories_file.name}",
                    force=True,
                )
            except OSError as exc:
                self._proxy_log(f"CATEGORIES error: {exc}", force=True)
        self._refresh_categories([])  # show immediately, don't wait for first tick
        self._cat_tick = 0

        self.run_worker(self._run_proxy(), exclusive=True, thread=False)
        self.set_interval(1.0, self._refresh_ui)

        # Apply theme: CLI flag wins; else use saved config.
        theme_to_apply = self._initial_theme or _load_theme_config()
        if theme_to_apply:
            try:
                self.theme = theme_to_apply
            except Exception:
                pass  # unknown theme name — ignore
        self._startup_done = True  # now watch_theme may persist changes

    def watch_theme(self, theme: str) -> None:
        """Called by Textual whenever the active theme changes — persist it."""
        if self._startup_done:
            _save_theme_config(theme)

    def on_unmount(self) -> None:
        """Close the log file handle and clipboard process cleanly when the app exits."""
        if self._log_fh is not None:
            self._log_fh.close()
            self._log_fh = None
        if self._wl_copy_proc is not None and self._wl_copy_proc.poll() is None:
            self._wl_copy_proc.terminate()

    async def _run_proxy(self) -> None:
        self._server = ProxyServer(
            tracker=self.tracker,
            filter_engine=self.filter_engine,
            classifier=self.classifier,
            throttle_engine=self.throttle_engine,
            host=self.proxy_host,
            port=self.proxy_port,
            max_connections=self._max_connections,
            log=self._proxy_log,
        )
        try:
            await self._server.start()
        except OSError as exc:
            import errno
            if exc.errno == errno.EADDRINUSE:
                self.notify(
                    f"Port {self.proxy_port} is already in use.\n"
                    f"Kill the existing process or use --port to choose another.",
                    title="Cannot start proxy",
                    severity="error",
                    timeout=0,
                )
            else:
                self.notify(str(exc), title="Proxy error", severity="error", timeout=0)
            self._proxy_log(
                f"ERROR   cannot bind {self.proxy_host}:{self.proxy_port} — {exc}",
                force=True,
            )

    # ---- command history (Up/Down in Input) ----

    def on_key(self, event: events.Key) -> None:
        inp = self.query_one("#command-input", Input)
        if not inp.has_focus:
            return
        if event.key == "up":
            if not self._cmd_history:
                return
            if self._cmd_history_idx == -1:
                self._cmd_current = inp.value
                self._cmd_history_idx = 0
            elif self._cmd_history_idx < len(self._cmd_history) - 1:
                self._cmd_history_idx += 1
            else:
                return
            inp.value = self._cmd_history[self._cmd_history_idx]
            inp.cursor_position = len(inp.value)
            event.stop()
        elif event.key == "down":
            if self._cmd_history_idx == -1:
                return
            if self._cmd_history_idx == 0:
                self._cmd_history_idx = -1
                inp.value = self._cmd_current
            else:
                self._cmd_history_idx -= 1
                inp.value = self._cmd_history[self._cmd_history_idx]
            inp.cursor_position = len(inp.value)
            event.stop()

    # ---- logging ----

    def _proxy_log(self, message: str, force: bool = False, markup: bool = False) -> None:
        """Receive a log line from the proxy, filter it, show it, save it.

        Set markup=True only for pre-formatted Rich strings (e.g. help text);
        plain proxy messages are escaped so IPv6 brackets won't be parsed as tags.
        """
        if not force and not _passes_level(message, self.log_level):
            return

        timestamp = time.strftime("%H:%M:%S")
        full = f"{timestamp} {message}"
        self._log_buffer.append(full)

        # Auto-pause if user has scrolled up; keep their position.
        # -3 tolerance: layout updates lag one frame so max_scroll_y may be
        # slightly ahead of scroll_y right after a programmatic scroll_end().
        log_widget = self._w_log
        at_bottom = log_widget.scroll_y >= log_widget.max_scroll_y - 3
        if self._log_skip_pause > 0:
            self._log_skip_pause -= 1
        elif self._log_paused:
            # If user pressed End (or scrolled down) while paused, auto-resume.
            if at_bottom:
                self._log_paused = False
                log_widget.auto_scroll = True
                self._log_skip_pause = 3
                self._update_log_pause_indicator()
        else:
            if not at_bottom:
                self._log_paused = True
                log_widget.auto_scroll = False
                self._update_log_pause_indicator()

        # Write to the TUI log with colour markup.
        if markup:
            log_widget.write(f"{timestamp} {message}")
        else:
            safe = markup_escape(full)
            if "DENIED" in message or "BLOCKED" in message:
                log_widget.write(f"[red]{safe}[/]")
            elif any(k in message for k in ("FAILED", "ERROR", "TIMEOUT", "AUTH FAIL", "BAD REQUEST")):
                log_widget.write(f"[yellow]{safe}[/]")
            elif "CONNECT" in message:
                log_widget.write(f"[green]{safe}[/]")
            elif "CLOSED" in message:
                log_widget.write(f"[dim]{safe}[/]")
            else:
                log_widget.write(safe)

        # Write plain text to the persistent file handle (line-buffered).
        if self._log_fh is not None:
            try:
                self._log_fh.write(full + "\n")
            except OSError:
                pass  # disk full etc. — don't crash the proxy

    # ---- UI refresh (efficient) ----

    def _refresh_ui(self) -> None:
        # Build connection lists once; reuse across all sub-refreshes.
        active  = self.tracker.active_connections
        history = self.tracker.get_recent_history(200)  # always; _refresh_table filters by H
        with self.batch_update():
            self._refresh_table(active, history)
            self._refresh_stats(active)
            self._refresh_filters()
        # Categories count connections — expensive; refresh every 3 ticks (~3 s).
        self._cat_tick += 1
        if self._cat_tick >= 3:
            self._cat_tick = 0
            self._refresh_categories(active)

    # ── Table row helpers ──────────────────────────────────────────────────

    @staticmethod
    def _trunc(s: str, n: int = 45) -> str:
        return s if len(s) <= n else s[: n - 1] + "…"

    def _table_row_cells(self, conn, throttle_v: int, server) -> tuple:
        """Return (status, cat, target, throttle, sent, recv, dur) markup for one row."""
        is_live = conn.status in (ConnectionStatus.ACTIVE, ConnectionStatus.CONNECTING)
        status = {
            ConnectionStatus.CONNECTING: "[yellow]CONNECTING[/]",
            ConnectionStatus.ACTIVE:     "[green]ACTIVE[/]",
            ConnectionStatus.CLOSED:     "[dim]CLOSED[/]",
            ConnectionStatus.DENIED:     "[red]DENIED[/]",
            ConnectionStatus.FAILED:     "[yellow]FAILED[/]",
        }.get(conn.status, conn.status.value)
        if is_live:
            ts = server.get_conn_throttle(conn.id) if server else None
            throttle_cell = f"[yellow]{ts.summary()}[/]" if ts and ts.active else ""
            return (
                status,
                self._cat_markup(conn.category),
                markup_escape(self._trunc(conn.target)),
                throttle_cell,
                format_bytes(conn.bytes_sent),
                format_bytes(conn.bytes_recv),
                f"{conn.duration:.1f}s",
            )
        else:
            return (
                status,
                f"[dim]{self._cat_abbrev(conn.category)}[/]",
                f"[dim]{markup_escape(self._trunc(conn.target))}[/]",
                "",
                f"[dim]{format_bytes(conn.bytes_sent)}[/]",
                f"[dim]{format_bytes(conn.bytes_recv)}[/]",
                f"[dim]{conn.duration:.1f}s[/]",
            )

    def _table_add_row(self, table, conn, throttle_v: int, server) -> None:
        key = str(conn.id)
        st, cat, tgt, thr, sent, recv, dur = self._table_row_cells(conn, throttle_v, server)
        table.add_row(key, st, cat, tgt, thr, "", "", sent, recv, dur, key=key)

    def _table_update_row_style(self, table, conn, throttle_v: int, server) -> None:
        key = str(conn.id)
        st, cat, tgt, thr, sent, recv, dur = self._table_row_cells(conn, throttle_v, server)
        is_live = conn.status in (ConnectionStatus.ACTIVE, ConnectionStatus.CONNECTING)
        try:
            table.update_cell(key, "status",   st,  update_width=False)
            table.update_cell(key, "cat",      cat, update_width=False)
            table.update_cell(key, "target",   tgt, update_width=False)
            table.update_cell(key, "throttle", thr, update_width=bool(thr))
            table.update_cell(key, "sent",     sent, update_width=False)
            table.update_cell(key, "recv",     recv, update_width=False)
            table.update_cell(key, "dur",      dur,  update_width=False)
            if not is_live and self._speed_display.get(conn.id) != ("", ""):
                table.update_cell(key, "up", "", update_width=False)
                table.update_cell(key, "dn", "", update_width=False)
                self._speed_display[conn.id] = ("", "")
        except Exception:
            pass

    def _table_restore_cursor(self, table, saved_id: int | None, saved_scroll: float) -> None:
        if table.row_count == 0:
            return

        target_row = None
        if saved_id is not None:
            try:
                target_row = table.get_row_index(str(saved_id))  # O(1) dict lookup
            except Exception:
                for i in range(table.row_count):               # O(N) fallback
                    try:
                        if int(str(table.get_row_at(i)[0])) == saved_id:
                            target_row = i
                            break
                    except Exception:
                        pass

        if target_row is None:
            target_row = max(0, min(table.cursor_row, table.row_count - 1))

        if table.cursor_row != target_row:
            table.move_cursor(row=target_row, animate=False, scroll=False)

        if abs(table.scroll_y - saved_scroll) > 0.1:
            table.scroll_to(y=saved_scroll, animate=False)

    def _refresh_table(self, active: list, history: list) -> None:
        """Stable-order table refresh — rows never move, status/colour updates in place.

        New connections append to the bottom. When a connection closes (H=True) its
        row stays in position and just dims. When H=False, closed rows are removed from
        the table but kept in _display_order so they come back in the right place if
        H is toggled on again.
        """
        table = self._w_table
        server = self._server
        throttle_v = server.throttle_version if server else 0

        active_set  = {c.id for c in active}
        history_set = {c.id for c in history}
        all_known   = active_set | history_set
        visible_set = active_set | (history_set if self._show_history else set())

        # Merged lookup for all currently known connections.
        all_conns: dict[int, object] = {c.id: c for c in active}
        for c in history:
            if c.id not in all_conns:
                all_conns[c.id] = c

        # ── 1. Register new connections ───────────────────────────────────
        for cid in sorted(all_known - self._display_set):
            self._display_order.append(cid)
            self._display_set.add(cid)
            self._last_statuses[cid] = all_conns[cid].status

        # ── 2. H toggle → full rebuild ────────────────────────────────────
        if self._show_history != self._last_show_history:
            self._last_show_history = self._show_history
            self._last_throttle_v   = throttle_v
            saved_id     = self._selected_conn_id()
            saved_scroll = table.scroll_y
            table.clear()
            self._in_table.clear()
            self._speed_display.clear()
            new_order = []
            for cid in self._display_order:
                if cid not in all_known:
                    continue  # prune during rebuild
                new_order.append(cid)
                if cid in visible_set:
                    self._table_add_row(table, all_conns[cid], throttle_v, server)
                    self._in_table.add(cid)
                self._last_statuses[cid] = all_conns[cid].status
            self._display_order = new_order
            self._display_set   = set(new_order)
            self._table_restore_cursor(table, saved_id, saved_scroll)
            return

        # ── 3. Prune connections that fell off the history deque ──────────
        gone = [cid for cid in self._display_order if cid not in all_known]
        struct_changed = bool(gone)
        saved_id     = self._selected_conn_id() if struct_changed else None
        saved_scroll = table.scroll_y            if struct_changed else 0.0
        if gone:
            gone_set = set(gone)
            for cid in gone:
                if cid in self._in_table:
                    try:
                        table.remove_row(str(cid))
                    except Exception:
                        pass
                    self._in_table.discard(cid)
                self._display_set.discard(cid)
                self._last_statuses.pop(cid, None)
                self._cell_display.pop(cid, None)
                self._speed_prev.pop(cid, None)
                self._speed_ema.pop(cid, None)
                self._speed_display.pop(cid, None)
            # Rebuild in one O(N) pass instead of N × list.remove() = O(N²).
            self._display_order = [cid for cid in self._display_order if cid not in gone_set]

        # ── 4. Sync table visibility and update cells ─────────────────────
        for cid in self._display_order:
            conn = all_conns.get(cid)
            if conn is None:
                continue
            should_show = cid in visible_set
            is_shown    = cid in self._in_table

            if should_show and not is_shown:
                # Became visible (e.g., connection re-appeared — rare edge case)
                if not struct_changed:
                    saved_id     = self._selected_conn_id()
                    saved_scroll = table.scroll_y
                    struct_changed = True
                self._table_add_row(table, conn, throttle_v, server)
                self._in_table.add(cid)
                self._last_statuses[cid] = conn.status
            elif not should_show and is_shown:
                # No longer visible (H=False and connection closed)
                if not struct_changed:
                    saved_id     = self._selected_conn_id()
                    saved_scroll = table.scroll_y
                    struct_changed = True
                try:
                    table.remove_row(str(cid))
                except Exception:
                    pass
                self._in_table.discard(cid)
            elif should_show and is_shown:
                last_st = self._last_statuses.get(cid)
                if last_st is not None and last_st != conn.status:
                    self._last_statuses[cid] = conn.status
                    self._table_update_row_style(table, conn, throttle_v, server)

        # Restore cursor after any structural change so it stays on the same connection.
        if struct_changed:
            self._table_restore_cursor(table, saved_id, saved_scroll)

        # ── 5. Throttle column update ─────────────────────────────────────
        if throttle_v != self._last_throttle_v:
            self._last_throttle_v = throttle_v
            for conn in active:
                if conn.id not in self._in_table:
                    continue
                ts = server.get_conn_throttle(conn.id) if server else None
                thr = f"[yellow]{ts.summary()}[/]" if ts and ts.active else ""
                try:
                    table.update_cell(str(conn.id), "throttle", thr, update_width=bool(thr))
                except Exception:
                    pass

        # ── 6. Incremental bytes / duration / EMA speed ───────────────────
        now = time.monotonic()
        for conn in active:
            if conn.id not in self._in_table:
                continue
            sent = format_bytes(conn.bytes_sent)
            recv = format_bytes(conn.bytes_recv)
            dur  = f"{conn.duration:.1f}s"
            prev = self._cell_display.get(conn.id)
            if prev != (sent, recv, dur):
                self._cell_display[conn.id] = (sent, recv, dur)
                try:
                    if prev is None or prev[0] != sent:
                        table.update_cell(str(conn.id), "sent", sent, update_width=False)
                    if prev is None or prev[1] != recv:
                        table.update_cell(str(conn.id), "recv", recv, update_width=False)
                    if prev is None or prev[2] != dur:
                        table.update_cell(str(conn.id), "dur",  dur,  update_width=False)
                except Exception:
                    pass

            prev_s = self._speed_prev.get(conn.id)
            if prev_s is not None:
                t0, s0, r0 = prev_s
                elapsed = now - t0
                if elapsed > 0:
                    raw_up = (conn.bytes_sent - s0) / elapsed
                    raw_dn = (conn.bytes_recv - r0) / elapsed
                    pe = self._speed_ema.get(conn.id, (0.0, 0.0))
                    ema_up = _EMA_ALPHA * raw_up + (1 - _EMA_ALPHA) * pe[0]
                    ema_dn = _EMA_ALPHA * raw_dn + (1 - _EMA_ALPHA) * pe[1]
                    self._speed_ema[conn.id] = (ema_up, ema_dn)
                    up_str = f"[dim]{int(ema_up / 1000)}[/]" if ema_up >= _SPEED_MIN_BPS else ""
                    dn_str = f"[dim]{int(ema_dn / 1000)}[/]" if ema_dn >= _SPEED_MIN_BPS else ""
                    if self._speed_display.get(conn.id) != (up_str, dn_str):
                        self._speed_display[conn.id] = (up_str, dn_str)
                        try:
                            table.update_cell(str(conn.id), "up", up_str, update_width=False)
                            table.update_cell(str(conn.id), "dn", dn_str, update_width=False)
                        except Exception:
                            pass
            self._speed_prev[conn.id] = (now, conn.bytes_sent, conn.bytes_recv)

    def _resolve_category(self, arg: str):
        """Resolve a category by full name or abbreviation (case-insensitive)."""
        a = arg.strip().lower()
        for cat in self.classifier.categories:
            if cat.name.lower() == a or cat.abbrev.lower() == a:
                return cat
        return None

    def _cat_markup(self, category: str) -> str:
        """Rich markup for a category name — coloured abbreviation for active rows."""
        if not category or category == "unknown":
            return ""
        cat = self.classifier.get_by_name(category)
        if cat is None:
            return f"[dim]{category[:3].upper()}[/]"
        blocked_marker = "[red bold]![/]" if self.classifier.is_category_blocked(cat.name) else ""
        return f"[{cat.color}]{cat.abbrev}[/]{blocked_marker}"

    def _cat_abbrev(self, category: str) -> str:
        """Plain abbreviation string (no colour) for dim history rows."""
        if not category or category == "unknown":
            return ""
        cat = self.classifier.get_by_name(category)
        return cat.abbrev if cat else category[:3].upper()

    _SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}

    def _refresh_categories(self, active: list) -> None:
        """Rebuild the Categories panel when block state or counts change."""
        cats = sorted(
            self.classifier.categories,
            key=lambda c: (self._SEVERITY_RANK.get(c.severity, 4), c.name),
        )
        if not cats:
            return

        # Count connections per category — use pre-fetched active list + bounded history.
        counts: dict[str, int] = {}
        for conn in active:
            if conn.category:
                counts[conn.category] = counts.get(conn.category, 0) + 1
        for conn in self.tracker.get_recent_history(50):
            if conn.category:
                counts[conn.category] = counts.get(conn.category, 0) + 1

        new_fp = tuple(
            (c.name, self.classifier.is_category_blocked(c.name),
             self.classifier.get_cat_override(c.name), counts.get(c.name, 0))
            for c in cats
        )
        if new_fp == self._categories_fingerprint:
            return
        self._categories_fingerprint = new_fp

        _SEV_LABEL = {"high": "── high ──", "medium": "── medium ──", "low": "── low ──", "info": "── info ──"}
        lines = []
        prev_sev = None
        for cat in cats:
            sev = cat.severity or "info"
            if sev != prev_sev:
                if prev_sev is not None:
                    lines.append("")
                lines.append(f"[dim]{_SEV_LABEL.get(sev, f'── {sev} ──')}[/]")
                prev_sev = sev
            n = counts.get(cat.name, 0)
            blocked = self.classifier.is_category_blocked(cat.name)
            override = self.classifier.get_cat_override(cat.name)
            geo = f"[dim]{cat.geo_hint}[/] " if cat.geo_hint else ""
            count_str = f"  [dim]{n}[/]" if n > 0 else ""
            if blocked:
                lines.append(
                    f"  [{cat.color}]{cat.abbrev}[/] [red]✗ {geo}{cat.name}[/]{count_str}"
                )
            elif override is False:
                lines.append(
                    f"  [{cat.color}]{cat.abbrev}[/] [green]✓ {geo}{cat.name}[/]{count_str}"
                )
            else:
                lines.append(
                    f"  [{cat.color}]{cat.abbrev}[/]   {geo}{cat.name}{count_str}"
                )

        content = "\n".join(lines)
        self._w_categories.update(content)
        self._w_categories.styles.height = len(lines)

    def _refresh_stats(self, active: list) -> None:
        n_active = len(active)
        total_sent = self.tracker.total_bytes_sent + sum(c.bytes_sent for c in active)
        total_recv = self.tracker.total_bytes_recv + sum(c.bytes_recv for c in active)
        new_fp = (
            self.tracker.total_connections,
            n_active,
            self.tracker.total_denied,
            total_sent,
            total_recv,
            self.log_level,
        )
        if new_fp == self._stats_fingerprint:
            return
        self._stats_fingerprint = new_fp

        self._w_total.update(f"Connections: {self.tracker.total_connections}")
        self._w_active.update(f"Active: {n_active}")
        self._w_denied.update(f"Denied: {self.tracker.total_denied}")
        self._w_traffic.update(f"↑ {format_bytes(total_sent)}  ↓ {format_bytes(total_recv)}")
        self._update_log_pause_indicator()

    def _refresh_filters(self) -> None:
        new_fp = self.filter_engine.version
        if new_fp == self._filters_fingerprint:
            return
        self._filters_fingerprint = new_fp

        if self.filter_engine.mode == FilterMode.DENYLIST:
            self._w_filter_mode.update("[bold]Default:[/] [green]allow[/] (DENY rules block)")
        else:
            self._w_filter_mode.update("[bold]Default:[/] [red]deny[/] (ALLOW rules permit)")

        rules = self.filter_engine.rules
        content = self._w_filter_rules
        if not rules:
            content.update("[dim](no rules)[/]")
        else:
            lines = []
            for rule in rules:
                orig = markup_escape(rule.original)
                if rule.kind == RuleKind.DENY:
                    lines.append(f"  [red]✗ {orig}[/]")
                else:
                    lines.append(f"  [green]✓ {orig}[/]")
            content.update("\n".join(lines))

    # ---- command handling ----

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        command = event.value.strip()
        event.input.clear()
        if not command:
            return

        # Save to history (skip duplicates at top)
        if not self._cmd_history or self._cmd_history[0] != command:
            self._cmd_history.appendleft(command)
        self._cmd_history_idx = -1
        self._cmd_current = ""

        parts = command.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("quit", "exit"):
            await self.action_graceful_quit()

        elif cmd == "deny":
            if not arg:
                self.notify("Usage: deny <pattern>  or  deny @<name|abbrev>", severity="warning")
                return
            if arg.startswith("@"):
                cat = self._resolve_category(arg[1:])
                if cat is None:
                    self.notify(f"Unknown category '{arg[1:]}'. Type 'cats' to list.", severity="warning")
                    return
                self.classifier.set_cat_override(cat.name, True)
                self.filter_engine.block_category(cat.name)
                self._proxy_log(f"CATEGORY {cat.abbrev} {cat.name} → BLOCKED", force=True)
                self.notify(f"⊘ {cat.abbrev} {cat.name} blocked")
                self._save_rules()
                self._cat_tick = 3
            else:
                rule = self.filter_engine.add_rule(arg, RuleKind.DENY)
                self._proxy_log(f"RULE + deny {rule.original}", force=True)
                self.notify(f"✗ deny {rule.original}")
                self._save_rules()

        elif cmd == "allow":
            if not arg:
                self.notify("Usage: allow <pattern>  or  allow @<name|abbrev>", severity="warning")
                return
            if arg.startswith("@"):
                cat = self._resolve_category(arg[1:])
                if cat is None:
                    self.notify(f"Unknown category '{arg[1:]}'. Type 'cats' to list.", severity="warning")
                    return
                self.classifier.set_cat_override(cat.name, False)
                self.filter_engine.unblock_category(cat.name)
                self._proxy_log(f"CATEGORY {cat.abbrev} {cat.name} → explicitly allowed", force=True)
                self.notify(f"✓ {cat.abbrev} {cat.name} allowed")
                self._save_rules()
                self._cat_tick = 3
            else:
                rule = self.filter_engine.add_rule(arg, RuleKind.ALLOW)
                self._proxy_log(f"RULE + allow {rule.original}", force=True)
                self.notify(f"✓ allow {rule.original}")
                self._save_rules()

        elif cmd == "remove":
            if not arg:
                self.notify("Usage: remove <pattern>  or  remove @<name|abbrev>", severity="warning")
                return
            if arg.startswith("@"):
                cat_name = arg[1:].strip().lower()
                self.classifier.set_cat_override(cat_name, None)
                self.filter_engine.reset_category(cat_name)
                self._proxy_log(f"CATEGORY {cat_name} → reset to TOML default", force=True)
                self.notify(f"↺ {cat_name} reset to default")
                self._save_rules()
                self._cat_tick = 3
            else:
                if self.filter_engine.remove_rule(arg):
                    self._proxy_log(f"RULE - removed {arg}", force=True)
                    self.notify(f"− removed {arg}")
                    self._save_rules()
                else:
                    self.notify(f"No rule matching '{arg}'", severity="warning")

        elif cmd == "mode":
            if arg.lower() == "denylist":
                self.filter_engine.set_mode(FilterMode.DENYLIST)
                self._proxy_log("MODE → DENYLIST (default: allow)", force=True)
                self.notify("Mode → DENYLIST")
                self._save_rules()
            elif arg.lower() == "allowlist":
                self.filter_engine.set_mode(FilterMode.ALLOWLIST)
                self._proxy_log("MODE → ALLOWLIST (default: deny)", force=True)
                self.notify("Mode → ALLOWLIST")
                self._save_rules()
            else:
                self.notify("Usage: mode denylist|allowlist", severity="warning")

        elif cmd == "loglevel":
            try:
                self.log_level = LogLevel(arg.lower())
                self._proxy_log(f"LOG level → {self.log_level.value}", force=True)
            except ValueError:
                self.notify("Usage: loglevel all|connections|denied|errors|none", severity="warning")

        elif cmd == "reload":
            if self.rules_file:
                self._load_rules_file()
            else:
                self._proxy_log("No rules file loaded (use --rules-file at startup)", force=True)

        elif cmd == "save":
            sub, _, rest = arg.partition(" ")
            if sub.strip().lower() == "pac":
                pac_path = Path(rest.strip()) if rest.strip() else Path("proxy.pac")
                try:
                    self._generate_pac(pac_path)
                    self._proxy_log(f"PAC saved → {pac_path}", force=True)
                    self.notify(f"PAC saved: {pac_path}")
                except OSError as exc:
                    self.notify(f"PAC save failed: {exc}", severity="error")
            elif sub.strip().lower() == "privoxy":
                base = Path(rest.strip()) if rest.strip() else Path("proxy-privoxy")
                try:
                    action_path, conf_path = self._generate_privoxy(base)
                    self._proxy_log(f"Privoxy saved → {action_path}  {conf_path}", force=True)
                    self.notify(f"Privoxy: {action_path.name}  {conf_path.name}")
                except OSError as exc:
                    self.notify(f"Privoxy save failed: {exc}", severity="error")
            else:
                if arg:
                    self.rules_file = Path(arg)
                if self.rules_file:
                    self._save_rules(report=True)
                else:
                    self.notify("Usage: save <path>  (or use --rules-file at startup)", severity="warning")

        elif cmd == "kill":
            if not arg:
                self.notify("Usage: kill <id>  (ID from connections table)", severity="warning")
                return
            try:
                self._do_kill(int(arg))
            except ValueError:
                self.notify(f"kill: '{arg}' is not a number", severity="warning")

        elif cmd == "dump":
            path = arg if arg else f"proxy-dump-{time.strftime('%Y%m%d-%H%M%S')}.txt"
            self._dump_to_file(path)

        elif cmd == "clear":
            sub = arg.strip().lower()
            if sub in ("deny", "allow"):
                kind = RuleKind.DENY if sub == "deny" else RuleKind.ALLOW
                victims = [r for r in self.filter_engine.rules if r.kind == kind]
                if not victims:
                    self.notify(f"No {sub} rules to clear.", severity="warning")
                    return
                for r in victims:
                    self.filter_engine.remove_rule(r.original)
                self._proxy_log(f"RULES cleared {len(victims)} {sub} rule(s)", force=True)
                self.notify(f"Cleared {len(victims)} {sub} rule(s)")
                self._save_rules()
            else:
                self.filter_engine.clear_rules()
                self._proxy_log("RULES cleared", force=True)
                self.notify("Rules cleared")
                self._save_rules()

        elif cmd == "block":
            if not arg:
                self.notify("Usage: block <name|abbrev>  (alias for: deny @<name>)", severity="warning")
                return
            cat = self._resolve_category(arg)
            if cat is None:
                self.notify(f"Unknown category '{arg}'. Type 'cats' to list.", severity="warning")
                return
            self.classifier.set_cat_override(cat.name, True)
            self.filter_engine.block_category(cat.name)
            self._proxy_log(f"CATEGORY {cat.abbrev} {cat.name} → BLOCKED", force=True)
            self.notify(f"⊘ {cat.abbrev} {cat.name} blocked")
            self._save_rules()
            self._cat_tick = 3

        elif cmd == "unblock":
            if not arg:
                self.notify("Usage: unblock <name|abbrev>  (alias for: allow @<name>)", severity="warning")
                return
            cat = self._resolve_category(arg)
            if cat is None:
                self.notify(f"Unknown category '{arg}'. Type 'cats' to list.", severity="warning")
                return
            self.classifier.set_cat_override(cat.name, False)
            self.filter_engine.unblock_category(cat.name)
            self._proxy_log(f"CATEGORY {cat.abbrev} {cat.name} → explicitly allowed", force=True)
            self.notify(f"✓ {cat.abbrev} {cat.name} allowed")
            self._save_rules()
            self._cat_tick = 3

        elif cmd == "cats":
            cats = sorted(
                self.classifier.categories,
                key=lambda c: (self._SEVERITY_RANK.get(c.severity, 4), c.name),
            )
            if not cats:
                self._proxy_log(
                    "No categories loaded. Start with --categories-file categories.toml",
                    force=True,
                )
                return
            lines = ["Categories:"]
            for cat in cats:
                is_blocked = self.classifier.is_category_blocked(cat.name)
                override   = self.classifier.get_cat_override(cat.name)
                if is_blocked:
                    state = "BLOCK"
                elif override is False:
                    state = "ALLOW"   # explicit override of TOML default
                else:
                    state = "——"      # TOML default (allowed)
                geo = f" {cat.geo_hint}" if cat.geo_hint else ""
                lines.append(f"  {cat.abbrev}{geo} {cat.name} [{state}] — {cat.description}")
            self._proxy_log("\n".join(lines), force=True)

        elif cmd == "throttle":
            await self._cmd_throttle(arg)

        elif cmd == "throttles":
            if arg.strip().lower() == "clear":
                n = len(self.throttle_engine.rules) + len(self.throttle_engine.cat_rules)
                if n == 0:
                    self.notify("No throttle rules to clear.", severity="warning")
                    return
                self.throttle_engine.reset()
                updated = 0
                if self._server:
                    for conn in self.tracker.active_connections:
                        if self._server.set_conn_throttle(conn.id, None, None):
                            updated += 1
                self._proxy_log(f"THROTTLE cleared {n} rule(s)", force=True)
                msg = f"cleared {n} throttle rule(s)"
                if updated:
                    msg += f" ({updated} active connection(s) unthrottled)"
                self.notify(msg)
                self._save_rules()
            else:
                host_rules = self.throttle_engine.rules
                cat_rules = self.throttle_engine.cat_rules
                if not host_rules and not cat_rules:
                    self._proxy_log("No throttle rules. Use: throttle <pattern> <speed>  or  throttle @<category> <speed>", force=True)
                    return
                lines = ["Throttle rules:"]
                for r in host_rules:
                    lines.append(f"  {r.pattern}  {r.summary()}")
                for cat_name, r in sorted(cat_rules.items()):
                    lines.append(f"  @{cat_name}  {r.summary()}")
                self._proxy_log("\n".join(lines), force=True)

        elif cmd in ("help", "?"):
            self.push_screen(HelpScreen())

        else:
            self.notify(f"Unknown command: '{cmd}'.  Press ? for help.", severity="warning")

    # ---- actions (key bindings) ----

    def _resize_split(self, delta: int) -> None:
        """Adjust the connections/log split by *delta* rows."""
        table = self.query_one("#connections-table")
        log   = self.query_one("#activity-log")
        total = table.size.height + log.size.height
        if total <= 6:
            return
        new_table = max(3, min(total - 3, table.size.height + delta))
        table.styles.height = new_table
        log.styles.height   = total - new_table

    def action_split_up(self)   -> None: self._resize_split(-1)
    def action_split_down(self) -> None: self._resize_split(1)

    def action_filter_scroll_up(self)   -> None:
        self.query_one("#filter-list", VerticalScroll).scroll_up()

    def action_filter_scroll_down(self) -> None:
        self.query_one("#filter-list", VerticalScroll).scroll_down()

    def action_cat_scroll_up(self)   -> None:
        self.query_one("#categories-list", VerticalScroll).scroll_up()

    def action_cat_scroll_down(self) -> None:
        self.query_one("#categories-list", VerticalScroll).scroll_down()

    def _update_log_pause_indicator(self) -> None:
        level = self.log_level.value
        if self._log_paused:
            self._w_loglevel.update(f"Log: {level} [yellow]⏸[/]")
        else:
            self._w_loglevel.update(f"Log: {level}")

    def action_log_resume(self) -> None:
        self._log_paused = False
        self._log_skip_pause = 5  # absorb layout-lag false positives after scroll_end
        self._w_log.auto_scroll = True
        self._w_log.scroll_end(animate=False)
        self._update_log_pause_indicator()

    def action_escape_input(self) -> None:
        inp = self.query_one("#command-input", Input)
        if inp.has_focus:
            if inp.value:
                inp.clear()
                self._cmd_history_idx = -1
            else:
                self.query_one("#connections-table", DataTable).focus()
        else:
            inp.focus()

    def action_show_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_show_cats(self) -> None:
        self.push_screen(CatsScreen(_build_cats_markup(self.classifier.categories)))

    async def action_graceful_quit(self) -> None:
        """Stop accepting connections, drain active relays (up to 3 s), then exit."""
        cmd_input = self.query_one("#command-input", Input)
        cmd_input.disabled = True
        self.query_one(Footer).display = False

        if self._server is not None:
            n = len(self.tracker.active_connections)
            if n:
                self._set_status(f"Shutting down — waiting for {n} connection(s) to close...")
                self._proxy_log(f"Shutting down — waiting for {n} active connection(s)...", force=True)
            else:
                self._set_status("Shutting down...")
            # Yield so Textual renders the status bar before we block.
            await anyio.sleep(0.05)
            await self._server.stop()
            # Wait for active handlers to finish naturally (up to 3 s).
            with anyio.move_on_after(3.0):
                while self.tracker.active_connections:
                    remaining = len(self.tracker.active_connections)
                    self._set_status(f"Shutting down — {remaining} connection(s) remaining...")
                    await anyio.sleep(0.1)
        self.exit()

    def _selected_conn_id(self) -> int | None:
        """Return the connection ID of the currently selected table row, or None."""
        table = self.query_one("#connections-table", DataTable)
        if table.row_count == 0 or table.cursor_row < 0 or table.cursor_row >= table.row_count:
            return None
        try:
            return int(str(table.get_row_at(table.cursor_row)[0]))
        except Exception:
            return None

    def _find_connection(self, conn_id: int):
        """Look up a connection record by ID — delegates to tracker's O(1) lookup."""
        return self.tracker.get_connection(conn_id)

    def action_info_selected(self) -> None:
        """Fetch DNS + GeoIP info for the selected connection and show in log."""
        conn_id = self._selected_conn_id()
        if conn_id is None:
            self._proxy_log("INFO    — select a row in the connections table first", force=True)
            return
        conn = self._find_connection(conn_id)
        if conn is None:
            self._proxy_log(f"INFO    #{conn_id} — not found", force=True)
            return
        self._proxy_log(f"INFO    #{conn_id} {conn.target} — looking up...", force=True)
        self.run_worker(self._fetch_conn_info(conn.id, conn.target_host, conn.target_port, conn.category))

    def action_kill_selected(self) -> None:
        """Kill the relay for the currently selected connection row."""
        conn_id = self._selected_conn_id()
        if conn_id is None:
            return
        self._do_kill(conn_id)

    def action_deny_selected(self) -> None:
        """Prepend a deny rule for the selected host (removes allow if present), then kill."""
        conn_id = self._selected_conn_id()
        if conn_id is None:
            self._proxy_log("DENY    — select a row first", force=True)
            return
        conn = self._find_connection(conn_id)
        if conn is None:
            self._proxy_log(f"DENY    #{conn_id} — not found", force=True)
            return
        host = conn.target_host
        existing = self.filter_engine.find_rule(host)
        if existing and existing.kind == RuleKind.DENY:
            self._proxy_log(f"DENY    #{conn_id} {host} — already denied", force=True)
            return
        if existing and existing.kind == RuleKind.ALLOW:
            self.filter_engine.remove_rule(host)
        self.filter_engine.prepend_rule(host, RuleKind.DENY)
        self._proxy_log(f"DENY    #{conn_id} {host} — deny rule added", force=True)
        self.notify(f"✗ deny {host}")
        self._save_rules()
        self._do_kill(conn_id)

    def action_allow_selected(self) -> None:
        """Prepend an allow rule for the selected host (removes deny if present)."""
        conn_id = self._selected_conn_id()
        if conn_id is None:
            self._proxy_log("ALLOW   — select a row first", force=True)
            return
        conn = self._find_connection(conn_id)
        if conn is None:
            self._proxy_log(f"ALLOW   #{conn_id} — not found", force=True)
            return
        host = conn.target_host
        existing = self.filter_engine.find_rule(host)
        if existing and existing.kind == RuleKind.ALLOW:
            self._proxy_log(f"ALLOW   #{conn_id} {host} — already allowed", force=True)
            return
        if existing and existing.kind == RuleKind.DENY:
            self.filter_engine.remove_rule(host)
        self.filter_engine.prepend_rule(host, RuleKind.ALLOW)
        self._proxy_log(f"ALLOW   #{conn_id} {host} — allow rule added", force=True)
        self.notify(f"✓ allow {host}")
        self._save_rules()

    def action_remove_rule_selected(self) -> None:
        """Remove the deny/allow rule for the selected host, if one exists."""
        conn_id = self._selected_conn_id()
        if conn_id is None:
            self._proxy_log("REMOVE  — select a row first", force=True)
            return
        conn = self._find_connection(conn_id)
        if conn is None:
            self._proxy_log(f"REMOVE  #{conn_id} — not found", force=True)
            return
        host = conn.target_host
        existing = self.filter_engine.find_rule(host)
        if existing is None:
            self._proxy_log(f"REMOVE  {host} — no rule", force=True)
            self.notify(f"No rule for {host}", severity="warning")
            return
        self.filter_engine.remove_rule(host)
        kind_label = existing.kind.value  # "deny" or "allow"
        self._proxy_log(f"REMOVE  {host} — {kind_label} rule removed", force=True)
        self.notify(f"Removed {kind_label} rule: {host}")
        self._save_rules()

    def action_mark_selected(self) -> None:
        """Flag the selected connection for later review and write to marks.log."""
        conn_id = self._selected_conn_id()
        if conn_id is None:
            self._proxy_log("MARK    — select a row first", force=True)
            return
        conn = self._find_connection(conn_id)
        if conn is None:
            self._proxy_log(f"MARK    #{conn_id} — not found", force=True)
            return
        target = conn.target
        cat = f" [{conn.category}]" if conn.category and conn.category != "unknown" else ""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = f"{timestamp}  #{conn_id}  {target}{cat}\n"
        marks_path = (self.rules_file.parent if self.rules_file else _CONFIG_PATH.parent) / "marks.log"
        try:
            marks_path.parent.mkdir(parents=True, exist_ok=True)
            with open(marks_path, "a") as fh:
                fh.write(entry)
        except OSError as exc:
            self._proxy_log(f"MARK    warning: could not write marks.log: {exc}", force=True)
            return
        self._proxy_log(f"[magenta]★ MARKED  #{conn_id} {target}{cat}[/]", force=True, markup=True)

    def _clipboard_copy(self, text: str) -> bool:
        """Copy text to system clipboard. Returns True on success."""
        env = os.environ.copy()
        try:
            if shutil.which("wl-copy"):
                # Terminate previous wl-copy before starting a new one —
                # prevents process accumulation on repeated Y presses.
                if self._wl_copy_proc is not None:
                    if self._wl_copy_proc.poll() is None:
                        self._wl_copy_proc.terminate()
                    self._wl_copy_proc.wait()
                proc = subprocess.Popen(
                    ["wl-copy"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                )
                if proc.stdin:
                    proc.stdin.write(text.encode())
                    proc.stdin.close()
                self._wl_copy_proc = proc
                return True
            if shutil.which("xclip"):
                subprocess.run(["xclip", "-selection", "clipboard"],
                               input=text.encode(), check=False, timeout=2, env=env)
                return True
            if shutil.which("xsel"):
                subprocess.run(["xsel", "--clipboard", "--input"],
                               input=text.encode(), check=False, timeout=2, env=env)
                return True
        except Exception as exc:
            self._proxy_log(f"[yellow]✂ COPY    — clipboard error: {exc}[/]", force=True, markup=True)
        return False

    def action_copy_target(self) -> None:
        """Copy the hostname of the selected connection to the system clipboard."""
        conn_id = self._selected_conn_id()
        if conn_id is None:
            self._proxy_log("[yellow]✂ COPY    — select a row first[/]", force=True, markup=True)
            return
        conn = self._find_connection(conn_id)
        if conn is None:
            self._proxy_log(f"[yellow]✂ COPY    #{conn_id} — not found[/]", force=True, markup=True)
            return
        host = conn.target_host
        if self._clipboard_copy(host):
            self._proxy_log(f"[cyan]✂ COPY    {host} → clipboard[/]", force=True, markup=True)
        else:
            self._proxy_log("[yellow]✂ COPY    — no clipboard tool found (wl-copy / xclip / xsel)[/]", force=True, markup=True)

    def action_throttle_selected(self) -> None:
        """Prepopulate the command input with 'throttle <host> ' for the selected row.

        Uses the hostname so the command creates a persistent pattern rule that
        is saved to the rules file and reloaded on next startup — unlike a
        per-connection #<id> override which is temporary and not persisted.
        """
        conn_id = self._selected_conn_id()
        if conn_id is None:
            self._proxy_log("THROTTLE — select a row in the connections table first", force=True)
            return
        conn = self._find_connection(conn_id)
        if conn is None:
            self._proxy_log(f"THROTTLE #{conn_id} — not found", force=True)
            return
        inp = self.query_one("#command-input", Input)
        host = conn.target_host
        existing = self.throttle_engine.match(host, conn.category)
        inp.value = f"throttle {host} {existing.summary()}" if existing else f"throttle {host} "
        inp.cursor_position = len(inp.value)
        inp.focus()

    async def _cmd_throttle(self, arg: str) -> None:
        """Handle the 'throttle' command — pattern rules or per-connection override."""
        parts = arg.split(None, 1)
        if not parts:
            self.notify(
                "Usage: throttle <pattern> <speed>  or  throttle #<id> <speed>",
                severity="warning",
            )
            return

        target = parts[0]
        speed_arg = parts[1].strip() if len(parts) > 1 else ""

        if target.startswith("@"):
            # ── Category throttle rule ────────────────────────────────────
            cat = self._resolve_category(target[1:])
            if cat is None:
                self.notify(
                    f"Unknown category '{target[1:]}'. Type 'cats' to list.",
                    severity="warning",
                )
                return
            category_name = cat.name  # canonical name, even if abbrev was typed

            if speed_arg.lower() == "off":
                if self.throttle_engine.remove_cat_rule(category_name):
                    updated = self._apply_cat_throttle(category_name, removed=True)
                    self._proxy_log(f"THROTTLE removed category rule @{category_name}", force=True)
                    msg = f"@{category_name} throttle removed"
                    if updated:
                        msg += f" ({updated} active connection(s) unthrottled)"
                    self.notify(msg)
                    self._save_rules()
                else:
                    self.notify(f"No throttle rule for '@{category_name}'", severity="warning")
                return

            if not speed_arg:
                self.notify(
                    "Usage: throttle @<category> <speed|off>  (e.g. throttle @analytics 100k)",
                    severity="warning",
                )
                return

            try:
                rule = self.throttle_engine.add_cat_rule(category_name, speed_arg)
            except ValueError as exc:
                self.notify(f"Bad throttle args: {exc}", severity="warning")
                return

            updated = self._apply_cat_throttle(category_name)
            self._proxy_log(f"THROTTLE category rule + {rule.original}", force=True)
            msg = f"[{cat.color}]{cat.abbrev}[/] @{category_name} {rule.summary()}"
            if updated:
                msg += f" ({updated} active)"
            self.notify(msg)
            self._save_rules()

        elif target.startswith("#"):
            # ── Per-connection live override ──────────────────────────────
            try:
                conn_id = int(target[1:])
            except ValueError:
                self.notify(f"Bad connection ID: {target!r}", severity="warning")
                return

            if speed_arg.lower() == "off":
                if self._server and self._server.set_conn_throttle(conn_id, None, None):
                    self._proxy_log(f"THROTTLE #{conn_id} removed", force=True)
                    self.notify(f"⏱ #{conn_id} throttle removed")
                else:
                    self.notify(f"#{conn_id} — not active", severity="warning")
                return

            try:
                down, up, _delay = parse_throttle_args(speed_arg)
            except ValueError as exc:
                self.notify(f"Bad speed: {exc}", severity="warning")
                return

            if self._server and self._server.set_conn_throttle(conn_id, down, up):
                parts_desc = []
                if down is not None:
                    parts_desc.append(f"↓{format_speed(down)}")
                if up is not None:
                    parts_desc.append(f"↑{format_speed(up)}")
                summary = " ".join(parts_desc) or "none"
                self._proxy_log(f"THROTTLE #{conn_id} → {summary} (live)", force=True)
                self.notify(f"⏱ #{conn_id} {summary}")
            else:
                self.notify(f"#{conn_id} — not active (try pattern rule instead)", severity="warning")

        else:
            # ── Pattern rule ──────────────────────────────────────────────
            if speed_arg.lower() == "off":
                if self.throttle_engine.remove_rule(target):
                    # Clear throttle on active connections that no longer match any rule.
                    updated = self._apply_throttle_to_active(target, removed=True)
                    self._proxy_log(f"THROTTLE removed rule for {target}", force=True)
                    msg = f"⏱ rule removed: {target}"
                    if updated:
                        msg += f" ({updated} active connection(s) unthrottled)"
                    self.notify(msg)
                    self._save_rules()
                else:
                    self.notify(f"No throttle rule for '{target}'", severity="warning")
                return

            if not speed_arg:
                self.notify(
                    "Usage: throttle <pattern> <speed|off>  (e.g. throttle *.cdn.com 200k)",
                    severity="warning",
                )
                return

            try:
                rule = self.throttle_engine.add_rule(target, speed_arg)
            except ValueError as exc:
                self.notify(f"Bad throttle args: {exc}", severity="warning")
                return

            # Apply immediately to already-running connections that match.
            updated = self._apply_throttle_to_active(rule.pattern)
            self._proxy_log(f"THROTTLE rule + {rule.original}", force=True)
            msg = f"⏱ {rule.pattern} {rule.summary()}"
            if updated:
                msg += f" ({updated} active)"
            self.notify(msg)
            self._save_rules()

    def _apply_throttle_to_active(self, pattern: str, removed: bool = False) -> int:
        """Apply or clear throttle on running connections whose host matches *pattern*.

        Called after adding or removing a pattern rule so that active connections
        are updated immediately without needing to reconnect.

        Returns the number of connections updated.
        """
        if self._server is None:
            return 0
        updated = 0
        for conn in self.tracker.active_connections:
            if removed:
                # Re-evaluate effective throttle now that the rule is gone.
                # A category rule may now apply as fallback.
                effective = self.throttle_engine.match(conn.target_host, conn.category)
                if effective is None:
                    self._server.set_conn_throttle(conn.id, None, None)
                else:
                    self._server.set_conn_throttle(conn.id, effective.download_bps, effective.upload_bps)
                updated += 1
            else:
                # Rule was added/updated — apply if this connection's host matches it.
                matched = self.throttle_engine.match(conn.target_host)
                if matched is not None and matched.pattern == pattern:
                    self._server.set_conn_throttle(conn.id, matched.download_bps, matched.upload_bps)
                    updated += 1
        return updated

    def _apply_cat_throttle(self, category: str, removed: bool = False) -> int:
        """Apply or clear throttle on active connections that belong to *category*.

        Host pattern rules take priority — connections already covered by a
        host rule are left untouched.
        """
        if self._server is None:
            return 0
        updated = 0
        cat_rule = None if removed else self.throttle_engine.match_cat(category)
        for conn in self.tracker.active_connections:
            if conn.category != category:
                continue
            # Host rule takes priority — skip this connection.
            if self.throttle_engine.match(conn.target_host) is not None:
                continue
            if cat_rule is None:
                self._server.set_conn_throttle(conn.id, None, None)
            else:
                self._server.set_conn_throttle(conn.id, cat_rule.download_bps, cat_rule.upload_bps)
            updated += 1
        return updated

    def action_toggle_history(self) -> None:
        """Toggle whether closed/denied/failed connections are shown in the table."""
        self._show_history = not self._show_history
        state = "ON" if self._show_history else "OFF"
        self._proxy_log(f"History {state} — {'showing' if self._show_history else 'hiding'} closed connections", force=True)

    def action_clear_log(self) -> None:
        self.query_one("#activity-log", RichLog).clear()

    # ---- helpers ----

    async def _fetch_conn_info(
        self, conn_id: int, host: str, port: int, category: str
    ) -> None:
        """Async worker: resolve DNS + fetch GeoIP, write results to activity log.

        AnyIO concept — ``anyio.to_thread.run_sync``
        -----------------------------------------------
        DNS lookups and HTTP requests are blocking system calls.  Running
        them on the event loop would freeze the TUI.  ``to_thread.run_sync``
        offloads them to a thread-pool thread and awaits the result without
        blocking the async loop.
        """
        def _flag(code: str) -> str:
            """Two-letter country code → flag emoji (🇸🇮, 🇺🇸, …)."""
            try:
                return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())
            except Exception:
                return ""

        tag = f"#{conn_id} {host}:{port}"
        lines: list[str] = []

        # ---- Step 1: Resolve hostname → IP address ----
        try:
            with anyio.fail_after(8):
                infos = await anyio.to_thread.run_sync(
                    lambda: socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                )
            ips = list(dict.fromkeys(info[4][0] for info in infos))  # deduplicated, order kept
        except TimeoutError:
            self._proxy_log(f"INFO    {tag} — DNS timeout", force=True)
            return
        except OSError as exc:
            self._proxy_log(f"INFO    {tag} — DNS failed: {exc}", force=True)
            return

        lines.append(f"  IP:      {', '.join(ips[:4])}")

        # ---- Step 2: Reverse DNS (PTR record) ----
        if ips:
            try:
                with anyio.fail_after(5):
                    ptr_host, *_ = await anyio.to_thread.run_sync(
                        lambda: socket.gethostbyaddr(ips[0])
                    )
                if ptr_host.rstrip(".") != host:
                    lines.append(f"  rDNS:    {ptr_host}")
            except (socket.herror, OSError, TimeoutError):
                pass

        # ---- Step 3: GeoIP via ip-api.com (free, no key needed) ----
        if ips:
            try:
                import ipaddress as _ipaddress
                _addr = _ipaddress.ip_address(ips[0])
                if _addr.is_private or _addr.is_loopback or _addr.is_link_local:
                    lines.append("  GeoIP:   private/local address, skipped")
                    ips = []  # skip the lookup below
            except ValueError:
                pass
        if ips:
            try:
                url = (
                    f"http://ip-api.com/json/{ips[0]}"
                    "?fields=status,country,countryCode,regionName,city,isp,org,as,query"
                )
                def _fetch_geo() -> dict:
                    with urllib.request.urlopen(url, timeout=6) as resp:
                        return json.loads(resp.read())
                geo = await anyio.to_thread.run_sync(_fetch_geo)

                if geo.get("status") == "success":
                    flag = _flag(geo.get("countryCode", ""))
                    country = geo.get("country", "?")
                    city = geo.get("city", "")
                    region = geo.get("regionName", "")
                    location = ", ".join(p for p in [city, region, country] if p)
                    lines.append(f"  Country: {flag} {location}")
                    isp = geo.get("isp", "")
                    org = geo.get("org", "")
                    if org and org != isp:
                        lines.append(f"  ISP:     {isp}")
                        lines.append(f"  Org:     {org}")
                    elif isp:
                        lines.append(f"  ISP/Org: {isp}")
                    asn = geo.get("as", "")
                    if asn:
                        lines.append(f"  ASN:     {asn}")
            except Exception as exc:
                lines.append(f"  GeoIP:   unavailable ({exc})")

        # ---- Emit to log ----
        cat_tag = f" [{category}]" if category and category != "unknown" else ""
        self._proxy_log(f"INFO    {tag}{cat_tag}", force=True)
        for line in lines:
            self._proxy_log(line, force=True)
        self._w_log.scroll_end(animate=False)

    def _set_status(self, msg: str) -> None:
        """Write a short status message to the status bar below the command input."""
        try:
            self._w_status.update(msg)
        except Exception:
            pass

    def _do_kill(self, conn_id: int) -> None:
        """Cancel the relay for connection *conn_id* and log the result."""
        if self._server is None:
            return
        if self._server.cancel_connection(conn_id):
            self._proxy_log(f"KILL    #{conn_id} — relay cancelled", force=True)
            self.notify(f"✕ #{conn_id} killed")
        else:
            self.notify(f"#{conn_id} — not active (already closed?)", severity="warning")

    def _dump_to_file(self, path: str) -> None:
        """Write a snapshot of connections + activity log to *path*."""
        try:
            with open(path, "w", encoding="utf-8") as fh:
                now = time.strftime("%Y-%m-%d %H:%M:%S")
                fh.write(f"# SOCKS5 Proxy snapshot — {now}\n")
                fh.write(f"# Listening on {self.proxy_host}:{self.proxy_port}\n")
                fh.write(f"# Total connections: {self.tracker.total_connections}"
                         f"  Denied: {self.tracker.total_denied}"
                         f"  ↑ {format_bytes(self.tracker.total_bytes_sent)}"
                         f"  ↓ {format_bytes(self.tracker.total_bytes_recv)}\n\n")

                # Active connections
                active = self.tracker.active_connections
                fh.write(f"## Active connections ({len(active)})\n")
                fh.write(f"{'ID':<5} {'Status':<12} {'Category':<18} {'Target':<45}"
                         f" {'Sent':<10} {'Recv':<10} Duration\n")
                fh.write("-" * 115 + "\n")
                for c in active:
                    fh.write(
                        f"{c.id:<5} {c.status.value:<12} {c.category or 'unknown':<18}"
                        f" {c.target:<45} {format_bytes(c.bytes_sent):<10}"
                        f" {format_bytes(c.bytes_recv):<10} {c.duration:.1f}s\n"
                    )

                # Recent history
                history = self.tracker.recent_history
                fh.write(f"\n## Recent connections ({len(history)})\n")
                fh.write(f"{'ID':<5} {'Status':<12} {'Category':<18} {'Target':<45}"
                         f" {'Sent':<10} {'Recv':<10} Duration\n")
                fh.write("-" * 115 + "\n")
                for c in history:
                    fh.write(
                        f"{c.id:<5} {c.status.value:<12} {c.category or 'unknown':<18}"
                        f" {c.target:<45} {format_bytes(c.bytes_sent):<10}"
                        f" {format_bytes(c.bytes_recv):<10} {c.duration:.1f}s\n"
                    )

                # Activity log
                fh.write(f"\n## Activity log ({len(self._log_buffer)} entries)\n")
                fh.write("-" * 80 + "\n")
                for line in self._log_buffer:
                    fh.write(line + "\n")

            self._proxy_log(f"DUMP → {path}", force=True)
        except OSError as exc:
            self._proxy_log(f"DUMP error: {exc}", force=True)

    def _generate_pac(self, path: Path) -> None:
        """Write a PAC file reflecting current filter rules and blocked categories."""
        import datetime
        proxy = f"{self.proxy_host}:{self.proxy_port}"
        deny_rules  = [r for r in self.filter_engine.rules if r.kind == RuleKind.DENY]
        allow_rules = [r for r in self.filter_engine.rules if r.kind == RuleKind.ALLOW]
        blocked_cats = [
            c for c in self.classifier.categories
            if self.classifier.is_category_blocked(c.name)
        ]

        out: list[str] = [
            f"// Generated by sockLight — SOCKS5 Dev Proxy — {datetime.date.today()}",
            f"// Proxy: SOCKS5 {proxy}  |  Mode: {self.filter_engine.mode.value}",
            "//",
            "// Usage:",
            f"//   chromium --proxy-pac-url=\"file://{path.resolve()}\"",
            f"//   firefox  --proxy-server=\"pac+file://{path.resolve()}\"",
            "",
            "function FindProxyForURL(url, host) {",
            "    host = host.toLowerCase();",
            "",
        ]

        def _pat(rule) -> str:
            if rule.port:
                return (
                    f'shExpMatch(host, "{rule.pattern}") && '
                    f'url.indexOf(":{rule.port}") !== -1'
                )
            return f'shExpMatch(host, "{rule.pattern}")'

        if deny_rules:
            out.append("    // Deny rules")
            for r in deny_rules:
                out.append(f'    if ({_pat(r)}) return "PROXY 127.0.0.1:1";')
            out.append("")

        if blocked_cats:
            out.append("    // Blocked categories")
            for cat in blocked_cats:
                out.append(f"    // {cat.abbrev}  {cat.name} — {cat.description}")
                for pat in cat.patterns:
                    out.append(f'    if (shExpMatch(host, "{pat}")) return "PROXY 127.0.0.1:1";')
            out.append("")

        if allow_rules:
            out.append("    // Allow rules — bypass proxy")
            for r in allow_rules:
                out.append(f'    if ({_pat(r)}) return "DIRECT";')
            out.append("")

        out.append("    // Default policy")
        if self.filter_engine.mode == FilterMode.DENYLIST:
            out.append(f'    return "SOCKS5 {proxy}";')
        else:
            out.append(f'    return "PROXY 127.0.0.1:1";  // ALLOWLIST — block by default')
        out.append("}")

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(out) + "\n")

    def _generate_privoxy(self, base: Path) -> tuple[Path, Path]:
        """Write a Privoxy user.action file and a config snippet.

        Returns (action_path, conf_path).

        Pattern translation:
          *.example.com  →  .example.com   (Privoxy dot-prefix = domain + all subdomains)
          sub.example.com → sub.example.com (exact host, unchanged)
          *.google.com.* and *.amazon.*    →  cannot translate (wildcard TLD); written as comments
        """
        import datetime

        def _to_privoxy(pat: str) -> str | None:
            """Convert one fnmatch pattern to Privoxy format.  None = not translatable."""
            p = pat.strip().lower()
            # Multi-TLD wildcard (e.g. *.google.com.* or *.amazon.*) — not supported
            if p.count("*") >= 2:
                return None
            if p.startswith("*."):
                return "." + p[2:]   # *.example.com → .example.com
            return p                  # exact or sub.example.com unchanged

        deny_rules   = [r for r in self.filter_engine.rules if r.kind == RuleKind.DENY]
        allow_rules  = [r for r in self.filter_engine.rules if r.kind == RuleKind.ALLOW]
        blocked_cats = [
            c for c in self.classifier.categories
            if self.classifier.is_category_blocked(c.name)
        ]
        proxy        = f"{self.proxy_host}:{self.proxy_port}"
        today        = datetime.date.today()

        # ── user.action ────────────────────────────────────────────────────
        act: list[str] = [
            f"# Privoxy user.action — generated by sockLight — SOCKS5 Dev Proxy {today}",
            f"# SOCKS5 proxy: {proxy}  |  mode: {self.filter_engine.mode.value}",
            "#",
            "# Load this file in Privoxy config:",
            "#   actionsfile user.action",
            "#",
            "# To forward all traffic to the SOCKS5 proxy add to Privoxy config:",
            f"#   forward-socks5t   /   {proxy}   .",
            "",
        ]

        # Default policy based on filter mode
        if self.filter_engine.mode == FilterMode.ALLOWLIST:
            act += [
                "# ALLOWLIST mode — block everything by default, then allow exceptions",
                "{ +block{default: allowlist mode} }",
                "/",
                "",
            ]

        # Deny rules → block
        if deny_rules:
            act.append("# ── Deny rules ──────────────────────────────────────────────────────")
            act.append("{ +block{deny rule} }")
            for r in deny_rules:
                pv = _to_privoxy(r.pattern)
                if pv:
                    suffix = f":{r.port}" if r.port else ""
                    act.append(f"{pv}{suffix}")
                else:
                    act.append(f"# UNSUPPORTED (multi-wildcard TLD): {r.pattern}")
            act.append("")

        # Blocked categories → block sections
        if blocked_cats:
            act.append("# ── Blocked categories ──────────────────────────────────────────────")
            for cat in blocked_cats:
                act.append(f"# {cat.abbrev}  {cat.name} — {cat.description}")
                act.append(f"{{ +block{{{cat.name}: {cat.abbrev}}} }}")
                for pat in cat.patterns:
                    pv = _to_privoxy(pat)
                    if pv:
                        act.append(pv)
                    else:
                        act.append(f"# UNSUPPORTED (multi-wildcard TLD): {pat}")
                act.append("")

        # Allow rules → -block (override blocks above)
        if allow_rules:
            act.append("# ── Allow rules (override blocks) ───────────────────────────────────")
            act.append("{ -block }")
            for r in allow_rules:
                pv = _to_privoxy(r.pattern)
                if pv:
                    suffix = f":{r.port}" if r.port else ""
                    act.append(f"{pv}{suffix}")
                else:
                    act.append(f"# UNSUPPORTED (multi-wildcard TLD): {r.pattern}")
            act.append("")

        # ── config snippet ─────────────────────────────────────────────────
        conf: list[str] = [
            f"# Privoxy config snippet — generated by sockLight — SOCKS5 Dev Proxy {today}",
            "#",
            "# Add these lines to your Privoxy config file (usually /etc/privoxy/config",
            "# or ~/.privoxy/config), then reload Privoxy.",
            "",
            "# Forward all traffic to SOCKS5 dev proxy",
            f"forward-socks5t   /   {proxy}   .",
            "",
            "# Load the exported action rules",
            f"actionsfile {base.stem}.action",
        ]

        action_path = base.with_suffix(".action")
        conf_path   = base.with_suffix(".conf.snippet")

        base.parent.mkdir(parents=True, exist_ok=True)
        action_path.write_text("\n".join(act) + "\n")
        conf_path.write_text("\n".join(conf) + "\n")
        return action_path, conf_path

    def _save_rules(self, report: bool = False) -> None:
        """Write current rules back to rules_file (if one is set)."""
        if self.rules_file is None:
            self._proxy_log("RULES   changes not persisted — start with --rules-file to save", force=True)
            return
        try:
            self.filter_engine.save_rules_file(
                self.rules_file,
                throttle_engine=self.throttle_engine,
            )
            if report:
                self._proxy_log(f"RULES saved to {self.rules_file}", force=True)
        except OSError as exc:
            self._proxy_log(f"RULES error saving to {self.rules_file}: {exc}", force=True)

    def _load_rules_file(self) -> None:
        """Load (or reload) the rules file and report the result."""
        assert self.rules_file is not None
        try:
            # Clear all runtime overrides in classifier before reset.
            for name in list(self.classifier.cat_overrides):
                self.classifier.set_cat_override(name, None)
            self.filter_engine.reset()
            self.throttle_engine.reset()

            n = self.filter_engine.load_rules_file(self.rules_file)
            nt = self.throttle_engine.load_from_rules_file(self.rules_file)
            # Sync all category overrides (deny + allow) from rules file to classifier.
            for name, state in self.filter_engine.cat_overrides.items():
                self.classifier.set_cat_override(name, state)
            overrides = self.filter_engine.cat_overrides
            cats = sum(1 for v in overrides.values() if v)
            throttle_msg = f", {nt} throttle rule(s)" if nt else ""
            self._proxy_log(
                f"RULES loaded {n} rule(s), {cats} blocked category/ies"
                f"{throttle_msg} "
                f"from {self.rules_file.name} [mode: {self.filter_engine.mode.value}]",
                force=True
            )
            # Force immediate categories panel refresh (bypass 3-tick throttle).
            self._cat_tick = 3
        except OSError as exc:
            self._proxy_log(f"RULES error reading {self.rules_file}: {exc}", force=True)
