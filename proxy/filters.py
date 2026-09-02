"""
Connection Filter Engine
========================

Controls which outbound connections the proxy allows.  Rules are
evaluated in order — the first matching rule wins.  If no rule
matches, the default policy (``mode``) applies:

  DENYLIST (default)
    → allow unless a DENY rule matches first.
    Good for: "let everything through but block a few things."

  ALLOWLIST
    → block unless an ALLOW rule matches first.
    Good for: "only let my app's servers through, block everything else."

Because each rule carries its own DENY / ALLOW kind, you can mix both
in a single engine::

    engine = FilterEngine(FilterMode.ALLOWLIST)   # default: block all
    engine.add_rule("api.github.com:443", RuleKind.ALLOW)
    engine.add_rule("*.python.org",       RuleKind.ALLOW)
    # everything else is denied by the default policy

Rule patterns:
  "example.com"           → exact host, any port
  "example.com:443"       → exact host + port
  "*.example.com"         → any subdomain
  "*.example.com:8080"    → any subdomain on port 8080
  "*"                     → everything

Rules file (``--rules-file``)::

    # comment
    mode allowlist          # set the default policy

    allow api.github.com:443
    allow *.python.org
    deny  ads.example.com   # first-match wins, so this overrides the default
"""

from __future__ import annotations

import enum
import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path


class FilterMode(enum.Enum):
    """Default policy when no rule matches."""

    DENYLIST = "denylist"   # default: allow connection
    ALLOWLIST = "allowlist" # default: deny connection


class RuleKind(enum.Enum):
    """What a matching rule does to the connection."""

    DENY = "deny"
    ALLOW = "allow"


@dataclass(frozen=True, slots=True)
class FilterRule:
    """One filter rule — immutable after creation.

    Attributes
    ----------
    pattern :
        Host pattern matched with ``fnmatch`` (supports ``*`` / ``?``).
    port :
        If set, only match when the port equals this value.
    kind :
        ``DENY`` blocks the connection; ``ALLOW`` permits it.
    original :
        The raw text the user typed (kept for display only).
    """

    pattern: str
    port: int | None = None
    kind: RuleKind = RuleKind.DENY
    original: str = ""

    @classmethod
    def parse(cls, text: str, kind: RuleKind = RuleKind.DENY) -> FilterRule:
        """Parse a rule from user input.

        Examples::

            FilterRule.parse("example.com")
                → pattern="example.com", port=None, kind=DENY

            FilterRule.parse("example.com:443", RuleKind.ALLOW)
                → pattern="example.com", port=443, kind=ALLOW
        """
        import ipaddress
        text = text.strip().lower()
        original = text
        port = None

        # Check for bracketed IPv6 format first, e.g. [2001:db8::1]:80 or [2001:db8::1]
        if text.startswith("["):
            end_idx = text.find("]")
            if end_idx != -1:
                host_part = text[1:end_idx]
                port_part = text[end_idx + 1:]
                if port_part.startswith(":"):
                    port_str = port_part[1:]
                    if port_str.isdigit():
                        port = int(port_str)
                text = host_part
                return cls(pattern=text, port=port, kind=kind, original=original)

        # Check if the entire string is a valid raw IPv6 address (no brackets, no port)
        try:
            ipaddress.IPv6Address(text)
            return cls(pattern=text, port=None, kind=kind, original=original)
        except ValueError:
            pass

        # Fallback to splitting on the last colon for IPv4 or hostnames (e.g. host:port)
        if ":" in text:
            host_part, port_part = text.rsplit(":", 1)
            if port_part.isdigit():
                port = int(port_part)
                text = host_part

        return cls(pattern=text, port=port, kind=kind, original=original)

    def matches(self, host: str, port: int) -> bool:
        """Return True if (host, port) matches this rule."""
        if not fnmatch.fnmatch(host.lower(), self.pattern):
            return False
        if self.port is not None and self.port != port:
            return False
        return True


class FilterEngine:
    """Ordered rule list with a fallback default policy.

    Evaluation
    ----------
    Rules are checked in insertion order.  The first rule that matches
    determines the outcome — its ``kind`` says DENY or ALLOW.  If no
    rule matches, ``mode`` is the fallback:

    * ``DENYLIST`` → allow  (permit by default; rules can deny)
    * ``ALLOWLIST`` → deny  (block by default; rules can allow)

    Usage::

        engine = FilterEngine(FilterMode.DENYLIST)
        engine.add_rule("*.ads.com")                     # kind=DENY default
        engine.add_rule("safe-ad-server.com", RuleKind.ALLOW)  # exception

        engine.is_allowed("tracker.ads.com", 443)  # → False (DENY rule matched)
        engine.is_allowed("safe-ad-server.com", 80)  # → True (ALLOW rule matched)
        engine.is_allowed("github.com", 443)        # → True (no match → DENYLIST default)
    """

    def __init__(self, mode: FilterMode = FilterMode.DENYLIST) -> None:
        self.mode = mode
        self._rules: list[FilterRule] = []
        self._compiled: dict[str, re.Pattern] = {}  # pattern → compiled regex
        # Runtime category overrides: True=explicitly denied, False=explicitly allowed.
        # Absent = use TOML default.  Mirrors Classifier._cat_overrides for persistence.
        self._cat_overrides: dict[str, bool] = {}
        # Incremented on every rule/mode/category change so the TUI can
        # detect changes with a single integer comparison instead of copying
        # the full rules list into a tuple every second.
        self.version: int = 0

    # ---- rule management ----

    @property
    def rules(self) -> list[FilterRule]:
        """Read-only snapshot of the current rules."""
        return list(self._rules)

    def add_rule(self, text: str, kind: RuleKind = RuleKind.DENY) -> FilterRule:
        """Parse and append a rule.  Exact duplicates are silently skipped."""
        rule = FilterRule.parse(text, kind)
        if rule not in self._rules:
            self._rules.append(rule)
            if rule.pattern not in self._compiled:
                self._compiled[rule.pattern] = re.compile(
                    fnmatch.translate(rule.pattern), re.IGNORECASE
                )
            self.version += 1
        return rule

    def prepend_rule(self, text: str, kind: RuleKind = RuleKind.DENY) -> FilterRule:
        """Parse and insert a rule at position 0 (highest priority)."""
        rule = FilterRule.parse(text, kind)
        if rule not in self._rules:
            self._rules.insert(0, rule)
            if rule.pattern not in self._compiled:
                self._compiled[rule.pattern] = re.compile(
                    fnmatch.translate(rule.pattern), re.IGNORECASE
                )
            self.version += 1
        return rule

    def find_rule(self, text: str) -> "FilterRule | None":
        """Return the first rule whose pattern and port match *text*, or None."""
        probe = FilterRule.parse(text.strip().lower())
        for rule in self._rules:
            if rule.pattern == probe.pattern and rule.port == probe.port:
                return rule
        return None

    def remove_rule(self, text: str) -> bool:
        """Remove the first rule whose pattern and port match *text*.

        The rule's ``kind`` is ignored when searching — useful when the
        user types ``remove *.ads.com`` without specifying kind.
        Returns True if a rule was removed.
        """
        probe = FilterRule.parse(text.strip().lower())
        for i, rule in enumerate(self._rules):
            if rule.pattern == probe.pattern and rule.port == probe.port:
                del self._rules[i]
                # Prune compiled regex cache if no other rule uses this pattern.
                if not any(r.pattern == probe.pattern for r in self._rules):
                    self._compiled.pop(probe.pattern, None)
                self.version += 1
                return True
        return False

    def set_mode(self, mode: FilterMode) -> None:
        """Change the filter mode and increment the change version."""
        self.mode = mode
        self.version += 1

    def clear_rules(self) -> None:
        """Remove all filter rules (does not touch blocked categories)."""
        self._rules.clear()
        self._compiled.clear()
        self.version += 1

    def reset(self) -> None:
        """Clear all state (rules, categories, mode) — used before reload."""
        self._rules.clear()
        self._compiled.clear()
        self._cat_overrides.clear()
        self.mode = FilterMode.DENYLIST
        self.version += 1

    # ---- category overrides (persisted in rules file) ----

    @property
    def blocked_categories(self) -> frozenset[str]:
        """Names explicitly denied via runtime override (True entries only)."""
        return frozenset(k for k, v in self._cat_overrides.items() if v)

    @property
    def cat_overrides(self) -> dict[str, bool]:
        """All runtime overrides: True=deny, False=allow."""
        return dict(self._cat_overrides)

    def block_category(self, name: str) -> None:
        self._cat_overrides[name.lower()] = True
        self.version += 1

    def unblock_category(self, name: str) -> None:
        self._cat_overrides[name.lower()] = False
        self.version += 1

    def reset_category(self, name: str) -> None:
        """Clear override — category returns to its TOML default."""
        self._cat_overrides.pop(name.lower(), None)
        self.version += 1

    def toggle_mode(self) -> FilterMode:
        """Swap DENYLIST ↔ ALLOWLIST and return the new mode."""
        self.mode = (
            FilterMode.ALLOWLIST
            if self.mode == FilterMode.DENYLIST
            else FilterMode.DENYLIST
        )
        self.version += 1
        return self.mode

    # ---- evaluation ----

    def _matches(self, rule: FilterRule, host_lower: str, port: int) -> bool:
        """Match using precompiled regex (avoids fnmatch recompilation).

        *host_lower* must already be lowercased by the caller.
        """
        regex = self._compiled.get(rule.pattern)
        if regex is None:
            # Fallback for rules loaded before _compiled was populated.
            regex = re.compile(fnmatch.translate(rule.pattern), re.IGNORECASE)
            self._compiled[rule.pattern] = regex
        if not regex.match(host_lower):
            return False
        return rule.port is None or rule.port == port

    def is_allowed(self, host: str, port: int) -> bool:
        """Return True if the connection should be permitted."""
        host_lower = host.lower()
        for rule in self._rules:
            if self._matches(rule, host_lower, port):
                return rule.kind == RuleKind.ALLOW   # first match wins
        return self.mode == FilterMode.DENYLIST       # fallback policy

    def check_verbose(
        self, host: str, port: int
    ) -> tuple[bool, FilterRule | None]:
        """Like ``is_allowed`` but also returns the matching rule (or None)."""
        host_lower = host.lower()
        for rule in self._rules:
            if self._matches(rule, host_lower, port):
                return rule.kind == RuleKind.ALLOW, rule
        return self.mode == FilterMode.DENYLIST, None

    # ---- file loading ----

    def load_rules_file(self, path: str | Path) -> int:
        """Load rules from *path*.  Returns the number of rules added.

        Each non-blank, non-comment line must start with a keyword:

        ``mode denylist | allowlist``
            Set the default policy.
        ``deny <pattern>``
            Add a DENY rule.
        ``allow <pattern>``
            Add an ALLOW rule.

        Lines starting with ``#`` and blank lines are ignored.
        """
        added = 0
        with open(path) as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                cmd = parts[0].lower()
                arg = parts[1].strip() if len(parts) > 1 else ""

                if cmd == "mode":
                    try:
                        self.mode = FilterMode(arg.lower())
                    except ValueError:
                        pass  # unknown value — skip silently
                elif cmd == "deny" and arg.startswith("@"):
                    self.block_category(arg[1:])
                elif cmd == "allow" and arg.startswith("@"):
                    self.unblock_category(arg[1:])
                elif cmd == "remove" and arg.startswith("@"):
                    self.reset_category(arg[1:])
                elif cmd == "deny" and arg:
                    before = len(self._rules)
                    self.add_rule(arg, RuleKind.DENY)
                    added += len(self._rules) - before
                elif cmd == "allow" and arg:
                    before = len(self._rules)
                    self.add_rule(arg, RuleKind.ALLOW)
                    added += len(self._rules) - before
                elif cmd == "block" and arg:   # backward compat
                    self.block_category(arg)
                elif cmd == "unblock" and arg:  # backward compat
                    self.unblock_category(arg)

        self.version += 1
        return added

    def save_rules_file(
        self,
        path: str | Path,
        throttle_engine: "ThrottleEngine | None" = None,
    ) -> None:
        """Write all current rules to *path* in the rules file format.

        The output can be loaded again with ``load_rules_file``.
        Pass *throttle_engine* to also persist throttle rules.
        """
        from proxy.throttle import ThrottleEngine as _TE  # local import avoids circular
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as fh:
            fh.write("# SOCKS5 proxy rules — auto-saved\n")
            fh.write(f"mode {self.mode.value}\n")
            if self._rules:
                fh.write("\n# host rules\n")
                for rule in self._rules:
                    fh.write(f"{rule.kind.value} {rule.original}\n")
            if self._cat_overrides:
                fh.write("\n# category overrides\n")
                for name, state in sorted(self._cat_overrides.items()):
                    verb = "deny" if state else "allow"
                    fh.write(f"{verb} @{name}\n")
            if throttle_engine is not None:
                host_rules = throttle_engine.rules
                cat_rules = throttle_engine.cat_rules
                if host_rules or cat_rules:
                    fh.write("\n# throttle rules\n")
                    for t in host_rules:
                        fh.write(f"throttle {t.original}\n")
                    for t in sorted(cat_rules.values(), key=lambda r: r.pattern):
                        fh.write(f"throttle {t.original}\n")
