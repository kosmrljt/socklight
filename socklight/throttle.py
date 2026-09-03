"""
Connection Throttle Engine
==========================

Controls how fast individual connections can transfer data.  Rules
are pattern-based (same fnmatch syntax as filter rules) and are
applied at connection time.  Active connections can also be throttled
or re-throttled live via the ``ThrottleState`` object that is shared
between the relay and the TUI.

Speed format
------------
  ``200k``   → 200 KB/s  (200 000 bytes/s)
  ``1m``     → 1 MB/s    (1 000 000 bytes/s)
  ``500``    → 500 B/s

Rule format in rules file
--------------------------
  throttle *.slow-api.com 200k
  throttle *.cdn.example.com down:500k up:2m
  throttle api.remote.com delay:300ms
  throttle *.heavy.com down:100k up:1m delay:200ms
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path


# ---------------------------------------------------------------------------
# Speed helpers
# ---------------------------------------------------------------------------

def parse_speed(s: str) -> int:
    """Parse a human speed string to bytes/sec.

    Examples::

        parse_speed("200k")  → 200_000
        parse_speed("1m")    → 1_000_000
        parse_speed("500")   → 500
    """
    s = s.strip().lower()
    if s.endswith("m"):
        return int(float(s[:-1]) * 1_000_000)
    if s.endswith("k"):
        return int(float(s[:-1]) * 1_000)
    return int(s)


def format_speed(bps: int) -> str:
    """Format bytes/sec to a compact human string."""
    if bps >= 1_000_000:
        v = bps / 1_000_000
        return f"{v:.1f}M" if v != int(v) else f"{int(v)}M"
    if bps >= 1_000:
        return f"{bps // 1_000}K"
    return f"{bps}B"


# ---------------------------------------------------------------------------
# ThrottleState — mutable, shared between relay and TUI
# ---------------------------------------------------------------------------

class ThrottleState:
    """Per-connection throttle settings.

    This object is created when a connection starts and stored in the
    server's ``_conn_throttle`` dict.  The relay reads ``download_bps``
    and ``upload_bps`` on every chunk, so changing them from the TUI
    (T key) takes effect on the very next chunk — no restart needed.
    """

    __slots__ = ("download_bps", "upload_bps")

    def __init__(
        self,
        download_bps: int | None = None,
        upload_bps: int | None = None,
    ) -> None:
        self.download_bps = download_bps
        self.upload_bps = upload_bps

    @property
    def active(self) -> bool:
        return self.download_bps is not None or self.upload_bps is not None

    def summary(self) -> str:
        """Short display string, e.g. '↓200K ↑1M'."""
        parts = []
        if self.download_bps is not None:
            parts.append(f"↓{format_speed(self.download_bps)}")
        if self.upload_bps is not None:
            parts.append(f"↑{format_speed(self.upload_bps)}")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# ThrottleRule — immutable rule stored in ThrottleEngine
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ThrottleRule:
    """One throttle rule — immutable after creation."""

    pattern: str
    download_bps: int | None = None
    upload_bps: int | None = None
    delay_ms: int = 0
    original: str = ""

    def make_state(self) -> ThrottleState:
        return ThrottleState(
            download_bps=self.download_bps,
            upload_bps=self.upload_bps,
        )

    def summary(self) -> str:
        parts = []
        if self.download_bps is not None:
            parts.append(f"down:{format_speed(self.download_bps)}")
        if self.upload_bps is not None:
            parts.append(f"up:{format_speed(self.upload_bps)}")
        if self.delay_ms:
            parts.append(f"delay:{self.delay_ms}ms")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def parse_throttle_args(args: str) -> tuple[int | None, int | None, int]:
    """Parse throttle argument string.

    Returns ``(download_bps, upload_bps, delay_ms)``.

    Examples::

        "200k"               → (200_000, 200_000, 0)   # both directions
        "down:100k up:1m"    → (100_000, 1_000_000, 0)
        "delay:300ms"        → (None, None, 300)
        "down:50k delay:200ms" → (50_000, None, 200)
    """
    download_bps: int | None = None
    upload_bps: int | None = None
    delay_ms = 0
    simple_speed: int | None = None

    for part in args.lower().split():
        if part.startswith("down:"):
            download_bps = parse_speed(part[5:])
        elif part.startswith("up:"):
            upload_bps = parse_speed(part[3:])
        elif part.startswith("delay:"):
            v = part[6:]
            if v.endswith("ms"):
                delay_ms = int(v[:-2])
            elif v.endswith("s"):
                delay_ms = int(float(v[:-1]) * 1000)
            else:
                delay_ms = int(v)
        else:
            simple_speed = parse_speed(part)

    if simple_speed is not None:
        if download_bps is None:
            download_bps = simple_speed
        if upload_bps is None:
            upload_bps = simple_speed

    return download_bps, upload_bps, delay_ms


# ---------------------------------------------------------------------------
# ThrottleEngine
# ---------------------------------------------------------------------------

class ThrottleEngine:
    """Ordered list of throttle rules.  First matching rule wins.

    Two rule types coexist:
    - Host pattern rules (fnmatch): matched against the connection host.
    - Category rules: matched against the classifier category name.

    Host rules take priority over category rules (more specific wins).
    """

    def __init__(self) -> None:
        self._rules: list[ThrottleRule] = []
        self._compiled: dict[str, re.Pattern] = {}
        self._cat_rules: dict[str, ThrottleRule] = {}  # category → rule
        self.version: int = 0

    @property
    def rules(self) -> list[ThrottleRule]:
        return list(self._rules)

    @property
    def cat_rules(self) -> dict[str, ThrottleRule]:
        return dict(self._cat_rules)

    def add_rule(self, pattern: str, args: str) -> ThrottleRule:
        """Add or replace a throttle rule for *pattern*."""
        download_bps, upload_bps, delay_ms = parse_throttle_args(args)
        pat = pattern.strip().lower()
        original = f"{pat} {args.strip()}"
        rule = ThrottleRule(
            pattern=pat,
            download_bps=download_bps,
            upload_bps=upload_bps,
            delay_ms=delay_ms,
            original=original,
        )
        for i, r in enumerate(self._rules):
            if r.pattern == pat:
                self._rules[i] = rule
                self.version += 1
                return rule
        self._rules.append(rule)
        if pat not in self._compiled:
            self._compiled[pat] = re.compile(
                fnmatch.translate(pat), re.IGNORECASE
            )
        self.version += 1
        return rule

    def remove_rule(self, pattern: str) -> bool:
        pat = pattern.strip().lower()
        for i, r in enumerate(self._rules):
            if r.pattern == pat:
                del self._rules[i]
                self.version += 1
                return True
        return False

    def add_cat_rule(self, category: str, args: str) -> ThrottleRule:
        """Add or replace a throttle rule for *category* (e.g. 'analytics')."""
        download_bps, upload_bps, delay_ms = parse_throttle_args(args)
        cat = category.strip().lower()
        rule = ThrottleRule(
            pattern=f"@{cat}",
            download_bps=download_bps,
            upload_bps=upload_bps,
            delay_ms=delay_ms,
            original=f"@{cat} {args.strip()}",
        )
        self._cat_rules[cat] = rule
        self.version += 1
        return rule

    def remove_cat_rule(self, category: str) -> bool:
        """Remove the category rule for *category*.  Returns True if removed."""
        cat = category.strip().lower()
        if cat in self._cat_rules:
            del self._cat_rules[cat]
            self.version += 1
            return True
        return False

    def match_cat(self, category: str) -> ThrottleRule | None:
        """Return the category rule for *category*, or None."""
        return self._cat_rules.get(category.lower())

    def match(self, host: str, category: str = "") -> ThrottleRule | None:
        """Return the effective throttle rule for *host* (and *category*), or None.

        Host pattern rules are checked first (more specific).
        If none match, falls back to the category rule.
        """
        h = host.lower()
        for rule in self._rules:
            regex = self._compiled.get(rule.pattern)
            if regex is None:
                regex = re.compile(
                    fnmatch.translate(rule.pattern), re.IGNORECASE
                )
                self._compiled[rule.pattern] = regex
            if regex.match(h):
                return rule
        if category:
            return self._cat_rules.get(category.lower())
        return None

    def reset(self) -> None:
        self._rules.clear()
        self._compiled.clear()
        self._cat_rules.clear()
        self.version += 1

    def load_from_rules_file(self, path: str | Path) -> int:
        """Read ``throttle`` lines from *path*.  Returns count loaded."""
        added = 0
        try:
            with open(path) as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 2)
                    if parts[0].lower() != "throttle" or len(parts) < 3:
                        continue
                    try:
                        target = parts[1]
                        if target.startswith("@"):
                            self.add_cat_rule(target[1:], parts[2])
                        else:
                            self.add_rule(target, parts[2])
                        added += 1
                    except (ValueError, IndexError):
                        pass
        except OSError:
            pass
        # add_rule already incremented version per rule; one final bump
        # ensures callers that loaded 0 rules still see a clean state.
        if added == 0:
            self.version += 1
        return added
