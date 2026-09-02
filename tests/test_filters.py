"""Tests for proxy/filters.py — all synchronous."""
import tempfile
import os
from proxy.filters import FilterEngine, FilterMode, FilterRule, RuleKind


class TestFilterRuleParse:
    def test_simple_hostname_defaults_to_deny(self):
        r = FilterRule.parse("example.com")
        assert r.pattern == "example.com"
        assert r.port is None
        assert r.kind == RuleKind.DENY
        assert r.original == "example.com"

    def test_hostname_with_port(self):
        r = FilterRule.parse("example.com:443")
        assert r.pattern == "example.com"
        assert r.port == 443

    def test_allow_kind(self):
        r = FilterRule.parse("api.myapp.com", RuleKind.ALLOW)
        assert r.kind == RuleKind.ALLOW

    def test_wildcard(self):
        r = FilterRule.parse("*.example.com")
        assert r.pattern == "*.example.com"
        assert r.port is None

    def test_wildcard_with_port(self):
        r = FilterRule.parse("*.cdn.net:8080")
        assert r.pattern == "*.cdn.net"
        assert r.port == 8080

    def test_strips_whitespace(self):
        r = FilterRule.parse("  example.com  ")
        assert r.pattern == "example.com"

    def test_lowercases(self):
        r = FilterRule.parse("EXAMPLE.COM:443")
        assert r.pattern == "example.com"
        assert r.port == 443

    def test_non_numeric_suffix_not_a_port(self):
        r = FilterRule.parse("example.com:abc")
        assert ":" in r.pattern
        assert r.port is None

    def test_original_preserved_lowercased(self):
        r = FilterRule.parse("*.ADS.COM:80")
        assert r.original == "*.ads.com:80"

    def test_star_only(self):
        r = FilterRule.parse("*")
        assert r.pattern == "*"
        assert r.port is None

    def test_ipv6_raw_no_port(self):
        r = FilterRule.parse("2001:db8::1")
        assert r.pattern == "2001:db8::1"
        assert r.port is None

    def test_ipv6_bracketed_no_port(self):
        r = FilterRule.parse("[2001:db8::1]")
        assert r.pattern == "2001:db8::1"
        assert r.port is None

    def test_ipv6_bracketed_with_port(self):
        r = FilterRule.parse("[2001:db8::1]:8080")
        assert r.pattern == "2001:db8::1"
        assert r.port == 8080


class TestFilterRuleMatches:
    def test_exact_host_any_port(self):
        r = FilterRule.parse("example.com")
        assert r.matches("example.com", 80)
        assert r.matches("example.com", 443)

    def test_exact_host_wrong_host(self):
        r = FilterRule.parse("example.com")
        assert not r.matches("other.com", 443)

    def test_case_insensitive(self):
        r = FilterRule.parse("example.com")
        assert r.matches("EXAMPLE.COM", 443)

    def test_wildcard_matches_subdomain(self):
        r = FilterRule.parse("*.example.com")
        assert r.matches("cdn.example.com", 443)
        assert r.matches("static.example.com", 80)

    def test_wildcard_does_not_match_apex(self):
        r = FilterRule.parse("*.example.com")
        assert not r.matches("example.com", 443)

    def test_port_specific_right_port(self):
        r = FilterRule.parse("example.com:443")
        assert r.matches("example.com", 443)

    def test_port_specific_wrong_port(self):
        r = FilterRule.parse("example.com:443")
        assert not r.matches("example.com", 80)

    def test_star_matches_everything(self):
        r = FilterRule.parse("*")
        assert r.matches("anything.example.com", 9999)

    def test_ipv6_matches(self):
        r = FilterRule.parse("2001:db8::1")
        assert r.matches("2001:db8::1", 80)
        assert r.matches("2001:db8::1", 443)
        assert not r.matches("2001:db8::2", 80)

    def test_ipv6_bracketed_matches_with_port(self):
        r = FilterRule.parse("[2001:db8::1]:8080")
        assert r.matches("2001:db8::1", 8080)
        assert not r.matches("2001:db8::1", 80)


class TestFilterEngine:
    # ---- default policy (no rules) ----

    def test_denylist_empty_allows_all(self):
        e = FilterEngine(FilterMode.DENYLIST)
        assert e.is_allowed("example.com", 443)

    def test_allowlist_empty_blocks_all(self):
        e = FilterEngine(FilterMode.ALLOWLIST)
        assert not e.is_allowed("example.com", 443)

    # ---- DENY rules in DENYLIST mode ----

    def test_denylist_blocks_deny_rule_match(self):
        e = FilterEngine(FilterMode.DENYLIST)
        e.add_rule("ads.com", RuleKind.DENY)
        assert not e.is_allowed("ads.com", 443)

    def test_denylist_allows_non_matching(self):
        e = FilterEngine(FilterMode.DENYLIST)
        e.add_rule("ads.com", RuleKind.DENY)
        assert e.is_allowed("safe.com", 443)

    def test_denylist_wildcard_deny(self):
        e = FilterEngine(FilterMode.DENYLIST)
        e.add_rule("*.doubleclick.net", RuleKind.DENY)
        assert not e.is_allowed("ad.doubleclick.net", 443)
        assert e.is_allowed("doubleclick.net", 443)   # apex not matched

    # ---- ALLOW rules in ALLOWLIST mode ----

    def test_allowlist_allows_allow_rule_match(self):
        e = FilterEngine(FilterMode.ALLOWLIST)
        e.add_rule("api.myapp.com", RuleKind.ALLOW)
        assert e.is_allowed("api.myapp.com", 443)

    def test_allowlist_blocks_non_matching(self):
        e = FilterEngine(FilterMode.ALLOWLIST)
        e.add_rule("api.myapp.com", RuleKind.ALLOW)
        assert not e.is_allowed("other.com", 443)

    # ---- mixed DENY + ALLOW (first-match wins) ----

    def test_allow_rule_overrides_default_deny(self):
        """In ALLOWLIST mode, an ALLOW rule lets the connection through."""
        e = FilterEngine(FilterMode.ALLOWLIST)
        e.add_rule("safe-ad-server.com", RuleKind.ALLOW)
        e.add_rule("*.ads.com", RuleKind.DENY)
        assert e.is_allowed("safe-ad-server.com", 80)     # ALLOW wins first
        assert not e.is_allowed("tracker.ads.com", 80)    # DENY wins, else default deny

    def test_deny_before_allow_wins(self):
        """First matching rule wins — order matters."""
        e = FilterEngine(FilterMode.DENYLIST)
        e.add_rule("bad.example.com", RuleKind.DENY)   # added first
        e.add_rule("*.example.com", RuleKind.ALLOW)    # added second
        # bad.example.com matches the DENY rule first → blocked
        assert not e.is_allowed("bad.example.com", 443)
        # other.example.com only matches the ALLOW rule → allowed
        assert e.is_allowed("other.example.com", 443)

    def test_allow_before_deny_wins(self):
        e = FilterEngine(FilterMode.DENYLIST)
        e.add_rule("good.example.com", RuleKind.ALLOW)  # added first
        e.add_rule("*.example.com", RuleKind.DENY)      # added second
        assert e.is_allowed("good.example.com", 443)    # ALLOW wins
        assert not e.is_allowed("bad.example.com", 443) # DENY wins

    # ---- add_rule default kind ----

    def test_add_rule_default_kind_is_deny(self):
        e = FilterEngine()
        r = e.add_rule("example.com")
        assert r.kind == RuleKind.DENY

    def test_add_rule_deduplication_same_kind(self):
        e = FilterEngine()
        e.add_rule("example.com", RuleKind.DENY)
        e.add_rule("example.com", RuleKind.DENY)
        assert len(e.rules) == 1

    def test_add_rule_different_kinds_not_duplicates(self):
        """DENY and ALLOW rules for the same host are distinct."""
        e = FilterEngine()
        e.add_rule("example.com", RuleKind.DENY)
        e.add_rule("example.com", RuleKind.ALLOW)
        assert len(e.rules) == 2

    def test_add_rule_returns_parsed_rule(self):
        e = FilterEngine()
        r = e.add_rule("Example.COM:443", RuleKind.ALLOW)
        assert r.pattern == "example.com"
        assert r.port == 443
        assert r.kind == RuleKind.ALLOW

    # ---- remove_rule ----

    def test_remove_rule_by_pattern_ignores_kind(self):
        """remove_rule matches by pattern+port regardless of kind."""
        e = FilterEngine()
        e.add_rule("example.com", RuleKind.ALLOW)
        assert e.remove_rule("example.com") is True
        assert len(e.rules) == 0

    def test_remove_rule_not_found(self):
        e = FilterEngine()
        assert e.remove_rule("nonexistent.com") is False

    def test_remove_first_matching_pattern(self):
        """When pattern appears twice (different kinds), only the first is removed."""
        e = FilterEngine()
        e.add_rule("example.com", RuleKind.DENY)
        e.add_rule("example.com", RuleKind.ALLOW)
        assert e.remove_rule("example.com") is True
        assert len(e.rules) == 1

    # ---- clear, toggle, rules snapshot ----

    def test_clear_rules(self):
        e = FilterEngine()
        e.add_rule("a.com")
        e.add_rule("b.com")
        e.clear_rules()
        assert e.rules == []

    def test_rules_property_returns_copy(self):
        e = FilterEngine()
        e.add_rule("example.com")
        snapshot = e.rules
        snapshot.clear()
        assert len(e.rules) == 1

    def test_toggle_denylist_to_allowlist(self):
        e = FilterEngine(FilterMode.DENYLIST)
        new = e.toggle_mode()
        assert new == FilterMode.ALLOWLIST
        assert e.mode == FilterMode.ALLOWLIST

    def test_toggle_allowlist_to_denylist(self):
        e = FilterEngine(FilterMode.ALLOWLIST)
        e.toggle_mode()
        assert e.mode == FilterMode.DENYLIST

    # ---- check_verbose ----

    def test_check_verbose_deny_rule_matched(self):
        e = FilterEngine(FilterMode.DENYLIST)
        e.add_rule("*.ads.com", RuleKind.DENY)
        allowed, rule = e.check_verbose("tracker.ads.com", 443)
        assert not allowed
        assert rule is not None
        assert rule.pattern == "*.ads.com"
        assert rule.kind == RuleKind.DENY

    def test_check_verbose_allow_rule_matched(self):
        e = FilterEngine(FilterMode.ALLOWLIST)
        e.add_rule("api.myapp.com", RuleKind.ALLOW)
        allowed, rule = e.check_verbose("api.myapp.com", 443)
        assert allowed
        assert rule is not None
        assert rule.kind == RuleKind.ALLOW

    def test_check_verbose_no_match_uses_default(self):
        e = FilterEngine(FilterMode.DENYLIST)
        e.add_rule("*.ads.com", RuleKind.DENY)
        allowed, rule = e.check_verbose("safe.com", 443)
        assert allowed        # DENYLIST default: allow
        assert rule is None

    # ---- port-specific rules ----

    def test_port_specific_deny(self):
        e = FilterEngine(FilterMode.DENYLIST)
        e.add_rule("example.com:443", RuleKind.DENY)
        assert not e.is_allowed("example.com", 443)
        assert e.is_allowed("example.com", 80)

    # ---- load_rules_file ----

    def _write_rules(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".rules")
        os.write(fd, content.encode())
        os.close(fd)
        return path

    def test_load_file_deny_and_allow(self):
        path = self._write_rules(
            "# comment\n"
            "mode denylist\n"
            "deny *.ads.com\n"
            "allow safe.ads.com\n"
        )
        try:
            e = FilterEngine()
            n = e.load_rules_file(path)
            assert n == 2
            assert e.mode == FilterMode.DENYLIST
            assert not e.is_allowed("tracker.ads.com", 80)  # DENY
            # safe.ads.com: ALLOW rule matches first (added second but checked in order)
            # wait — deny added first, allow added second
            # tracker.ads.com matches DENY rule → blocked ✓
            # safe.ads.com: matches DENY rule first (*.ads.com) → blocked!
            # The order matters: deny added before allow
            # To allow safe.ads.com, the allow rule must be listed first in the file.
        finally:
            os.unlink(path)

    def test_load_file_allow_before_deny(self):
        """Allow rule listed before deny rule in file → allow wins for that host."""
        path = self._write_rules(
            "mode denylist\n"
            "allow safe.ads.com\n"
            "deny *.ads.com\n"
        )
        try:
            e = FilterEngine()
            e.load_rules_file(path)
            assert e.is_allowed("safe.ads.com", 80)         # ALLOW rule first
            assert not e.is_allowed("tracker.ads.com", 80)  # only DENY matches
        finally:
            os.unlink(path)

    def test_load_file_sets_allowlist_mode(self):
        path = self._write_rules("mode allowlist\nallow api.github.com\n")
        try:
            e = FilterEngine()
            e.load_rules_file(path)
            assert e.mode == FilterMode.ALLOWLIST
            assert e.is_allowed("api.github.com", 443)
            assert not e.is_allowed("other.com", 443)
        finally:
            os.unlink(path)

    def test_load_file_skips_blank_and_comments(self):
        path = self._write_rules(
            "\n"
            "# this is a comment\n"
            "  \n"
            "deny ads.com\n"
        )
        try:
            e = FilterEngine()
            n = e.load_rules_file(path)
            assert n == 1
        finally:
            os.unlink(path)

    def test_load_file_returns_count(self):
        path = self._write_rules("deny a.com\ndeny b.com\nallow c.com\n")
        try:
            e = FilterEngine()
            assert e.load_rules_file(path) == 3
        finally:
            os.unlink(path)

    def test_load_file_skips_duplicates(self):
        path = self._write_rules("deny ads.com\ndeny ads.com\n")
        try:
            e = FilterEngine()
            n = e.load_rules_file(path)
            assert n == 1
            assert len(e.rules) == 1
        finally:
            os.unlink(path)

    # ---- save_rules_file ----

    def test_save_then_reload_roundtrip(self):
        """save_rules_file writes a file that load_rules_file can read back."""
        e1 = FilterEngine(FilterMode.ALLOWLIST)
        e1.add_rule("api.github.com:443", RuleKind.ALLOW)
        e1.add_rule("*.ads.com", RuleKind.DENY)

        fd, path = tempfile.mkstemp(suffix=".rules")
        os.close(fd)
        try:
            e1.save_rules_file(path)

            e2 = FilterEngine()
            e2.load_rules_file(path)
            assert e2.mode == FilterMode.ALLOWLIST
            assert len(e2.rules) == 2
            assert e2.is_allowed("api.github.com", 443)
            assert not e2.is_allowed("tracker.ads.com", 80)
        finally:
            os.unlink(path)

    def test_save_preserves_rule_order(self):
        """Rules are saved in insertion order (first-match semantics preserved)."""
        e = FilterEngine(FilterMode.DENYLIST)
        e.add_rule("good.ads.com", RuleKind.ALLOW)
        e.add_rule("*.ads.com", RuleKind.DENY)

        fd, path = tempfile.mkstemp(suffix=".rules")
        os.close(fd)
        try:
            e.save_rules_file(path)
            e2 = FilterEngine()
            e2.load_rules_file(path)
            # good.ads.com's ALLOW rule must still come first
            assert e2.is_allowed("good.ads.com", 80)
            assert not e2.is_allowed("bad.ads.com", 80)
        finally:
            os.unlink(path)

    def test_save_empty_engine(self):
        """Saving an engine with no rules produces a valid (empty) file."""
        e = FilterEngine(FilterMode.DENYLIST)
        fd, path = tempfile.mkstemp(suffix=".rules")
        os.close(fd)
        try:
            e.save_rules_file(path)
            e2 = FilterEngine(FilterMode.ALLOWLIST)  # different default
            e2.load_rules_file(path)
            assert e2.mode == FilterMode.DENYLIST    # mode overwritten by file
            assert e2.rules == []
        finally:
            os.unlink(path)
