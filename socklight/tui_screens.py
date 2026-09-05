"""Screen widgets for the sockLight TUI — HelpScreen, CatsScreen."""

from __future__ import annotations

from rich.markup import escape as markup_escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static

# ---------------------------------------------------------------------------
# Help text
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
  [cyan]F8[/]           soft reset  [dim](clear history + log, keep active connections)[/]
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
  [cyan]save adblock[/] [dim]<path>[/]      export Adblock Plus / uBlock Origin filter list  [dim](deny rules → ||host^)[/]

  [dim]Category overrides[/]  [dim](use @name or @ABBREV)[/]
  [cyan]deny[/] [dim]@<name|abbrev>[/]      [red]⊘[/] block category  [dim](e.g. deny @ADV)[/]
  [cyan]allow[/] [dim]@<name|abbrev>[/]     [green]✓[/] explicitly allow category  [dim](overrides TOML default block)[/]
  [cyan]remove[/] [dim]@<name|abbrev>[/]    reset category to TOML default  [dim](no validation)[/]

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

# ---------------------------------------------------------------------------
# Category display constants — also imported by tui.py for _refresh_table /
# _refresh_categories which need _SEV_COLOR and _CATS_SEVERITY_RANK.
# ---------------------------------------------------------------------------

_CATS_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}
_CATS_SEV_LABEL = {
    "high":   "── high ──",
    "medium": "── medium ──",
    "low":    "── low ──",
    "info":   "── info ──",
}
_SEV_COLOR = {
    "high":   "dim red",
    "medium": "dim yellow",
    "low":    "dim green",
}


def _build_cats_markup(cats: list, classifier=None) -> str:
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
        col = _SEV_COLOR.get(sev, "white")
        abbrev_text = f"{markup_escape(cat.abbrev):<5}"
        name_text = markup_escape(f"{cat.name:<24}")
        geo = f" [dim]{markup_escape(cat.geo_hint)}[/]" if cat.geo_hint else ""
        blocked = (
            classifier.is_category_blocked(cat.name) if classifier is not None else False
        )
        blk = " [red]● blocked[/]" if blocked else ""
        desc = f" [dim]{markup_escape(cat.description)}[/]" if cat.description else ""
        lines.append(f"  [{col}]{abbrev_text}[/]  [bold]{name_text}[/]{geo}{blk}{desc}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Modal screens
# ---------------------------------------------------------------------------

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
