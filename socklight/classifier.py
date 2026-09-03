"""
Connection Classifier
=====================

Classifies proxy connections by category (advertising, analytics,
telemetry, geo-suspicious, etc.) using domain pattern matching.

Category definitions are loaded from a TOML file so the user can
extend them without touching Python code.  See categories.toml for
the shipped defaults.

Usage
-----
    classifier = Classifier()
    classifier.load_file("categories.toml")

    cat = classifier.classify("google-analytics.com")
    # → Category(name="analytics", color="yellow", abbrev="ANA", ...)

    # Block a category at runtime (TUI command: block analytics)
    classifier.set_blocked("analytics", True)
    if classifier.is_category_blocked(cat.name):
        # deny the connection
        ...

TOML format
-----------
    [categories.advertising]
    color       = "red"
    abbrev      = "ADV"
    description = "Ad networks"
    block       = false     # block by default (false = allow, toggle at runtime)
    geo_hint    = ""        # optional 2-letter country code shown in the panel
    patterns    = [
        "*.doubleclick.net",
        "googlesyndication.com",
    ]

First-match-wins: categories are checked in the order they appear in the
TOML file, so list more-specific categories before catch-alls.
"""

from __future__ import annotations

import fnmatch
import re
import sys
from dataclasses import dataclass, field

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib
from pathlib import Path


@dataclass
class Category:
    """One category definition loaded from the TOML file."""

    name: str
    color: str = "white"
    abbrev: str = "???"
    description: str = ""
    geo_hint: str = ""
    severity: str = "info"   # high | medium | low | info
    patterns: list[str] = field(default_factory=list)


# Returned when no category matches — never None, so callers don't need guards.
_UNKNOWN = Category(name="unknown", color="dim", abbrev="???", description="Unclassified")


class Classifier:
    """Load categories from TOML, classify hostnames, track blocked categories."""

    def __init__(self) -> None:
        self._categories: list[Category] = []
        self._by_name: dict[str, Category] = {}
        # Runtime overrides: True=explicitly denied, False=explicitly allowed.
        # Absent = default allow.  Cleared by set_cat_override(name, None).
        self._cat_overrides: dict[str, bool] = {}
        # Two-level index: TLD → domain → RE list.
        # classify() does 2 dict lookups to find a small candidate bucket
        # (~10-20 patterns) instead of scanning all patterns linearly.
        # Patterns whose TLD or second-level label contains a wildcard go to
        # _fallback and are checked only when the bucket produces no match.
        self._index: dict[str, dict[str, list[tuple[re.Pattern, Category]]]] = {}
        self._fallback: list[tuple[re.Pattern, Category]] = []

    # ---- loading ----

    def load_file(self, path: str | Path) -> int:
        """Load category definitions from *path*.  Returns count loaded."""
        with open(path, "rb") as fh:
            data = tomllib.load(fh)

        for name, cfg in data.get("categories", {}).items():
            cat = Category(
                name=name,
                color=cfg.get("color", "white"),
                abbrev=cfg.get("abbrev", name[:3].upper()),
                description=cfg.get("description", ""),
                geo_hint=cfg.get("geo_hint", ""),
                severity=cfg.get("severity", "info"),
                patterns=cfg.get("patterns", []),
            )
            self._categories.append(cat)
            self._by_name[name] = cat
            for pattern in cat.patterns:
                p_lower = pattern.lower()
                compiled = re.compile(fnmatch.translate(p_lower))
                self._index_pattern(p_lower, compiled, cat)

        return len(data.get("categories", {}))

    # ---- classification ----

    def _index_pattern(
        self, pattern: str, compiled: re.Pattern, cat: Category
    ) -> None:
        """Route one compiled pattern into the two-level index or fallback."""
        clean = pattern.lstrip("*.")
        parts = clean.split(".")
        if len(parts) >= 2 and "*" not in parts[-1] and "*" not in parts[-2]:
            tld, domain = parts[-1], parts[-2]
            self._index.setdefault(tld, {}).setdefault(domain, []).append(
                (compiled, cat)
            )
        else:
            self._fallback.append((compiled, cat))

    def classify(self, host: str) -> Category:
        """Return the first matching Category for *host*, or _UNKNOWN.

        Comparison is case-insensitive.  Patterns use fnmatch wildcards
        (* matches any string including dots, ? matches one character).
        Categories are checked in definition order — first match wins.

        Fast path: two dict lookups by TLD + second-level domain select a
        small bucket of candidates; only those RE are tested.  Patterns that
        could not be indexed (wildcard TLD, single-label) are in _fallback
        and checked only when the bucket produces no match.
        """
        h = host.lower()
        parts = h.split(".")
        if len(parts) >= 2:
            for regex, cat in self._index.get(parts[-1], {}).get(parts[-2], ()):
                if regex.match(h):
                    return cat
        for regex, cat in self._fallback:
            if regex.match(h):
                return cat
        return _UNKNOWN

    def get_by_name(self, name: str) -> Category | None:
        """Return a Category by its name key, or None."""
        if name == "unknown":
            return _UNKNOWN
        return self._by_name.get(name)

    # ---- blocking ----

    def is_category_blocked(self, name: str) -> bool:
        """Return True if *name* has an explicit deny override."""
        return self._cat_overrides.get(name.lower(), False)

    def get_cat_override(self, name: str) -> bool | None:
        """Return the runtime override for *name*, or None if at TOML default."""
        return self._cat_overrides.get(name.lower())

    def set_cat_override(self, name: str, state: bool | None) -> None:
        """Set or clear the runtime override for *name*.

        state=True  → explicitly denied (blocked)
        state=False → explicitly allowed (overrides TOML block=true)
        state=None  → reset to TOML default
        """
        key = name.lower()
        if state is None:
            self._cat_overrides.pop(key, None)
        else:
            self._cat_overrides[key] = state

    def set_blocked(self, name: str, blocked: bool) -> None:
        """Backward-compatible alias for set_cat_override(name, blocked)."""
        self.set_cat_override(name, blocked)

    def toggle_blocked(self, name: str) -> bool:
        """Toggle between denied and allowed override; return new blocked state."""
        new_state = not self.is_category_blocked(name)
        self.set_cat_override(name, new_state)
        return new_state

    # ---- queries ----

    @property
    def categories(self) -> list[Category]:
        return list(self._categories)

    @property
    def blocked_categories(self) -> frozenset[str]:
        """Names of all currently blocked categories (explicit deny overrides only)."""
        return frozenset(
            cat.name for cat in self._categories
            if self._cat_overrides.get(cat.name.lower()) is True
        )

    @property
    def cat_overrides(self) -> dict[str, bool]:
        """Runtime overrides only (not TOML defaults). True=deny, False=allow."""
        return dict(self._cat_overrides)

    def unknown_category(self) -> Category:
        return _UNKNOWN
