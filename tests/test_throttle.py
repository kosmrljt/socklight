"""Tests for socklight.throttle — parse_speed, parse_throttle_args, ThrottleEngine."""

from __future__ import annotations

import pytest
from pathlib import Path

from socklight.throttle import (
    ThrottleEngine,
    ThrottleRule,
    ThrottleState,
    format_speed,
    parse_speed,
    parse_throttle_args,
)


# ---------------------------------------------------------------------------
# parse_speed
# ---------------------------------------------------------------------------

class TestParseSpeed:
    def test_bare_integer(self):
        assert parse_speed("500") == 500

    def test_kilobytes(self):
        assert parse_speed("200k") == 200_000

    def test_megabytes(self):
        assert parse_speed("1m") == 1_000_000

    def test_fractional_megabytes(self):
        assert parse_speed("1.5m") == 1_500_000

    def test_fractional_kilobytes(self):
        assert parse_speed("2.5k") == 2_500

    def test_uppercase_units(self):
        assert parse_speed("100K") == 100_000
        assert parse_speed("2M") == 2_000_000

    def test_whitespace_stripped(self):
        assert parse_speed("  300k  ") == 300_000

    def test_invalid_raises(self):
        with pytest.raises((ValueError, TypeError)):
            parse_speed("fast")


# ---------------------------------------------------------------------------
# format_speed
# ---------------------------------------------------------------------------

class TestFormatSpeed:
    def test_bytes(self):
        assert format_speed(500) == "500B"

    def test_kilobytes_exact(self):
        assert format_speed(200_000) == "200K"

    def test_megabytes_exact(self):
        assert format_speed(2_000_000) == "2M"

    def test_megabytes_fractional(self):
        assert format_speed(1_500_000) == "1.5M"


# ---------------------------------------------------------------------------
# parse_throttle_args
# ---------------------------------------------------------------------------

class TestParseThrottleArgs:
    def test_simple_speed_sets_both_directions(self):
        down, up, delay = parse_throttle_args("200k")
        assert down == 200_000
        assert up == 200_000
        assert delay == 0

    def test_explicit_down_only(self):
        down, up, delay = parse_throttle_args("down:100k")
        assert down == 100_000
        assert up is None
        assert delay == 0

    def test_explicit_up_only(self):
        down, up, delay = parse_throttle_args("up:1m")
        assert down is None
        assert up == 1_000_000

    def test_down_and_up(self):
        down, up, delay = parse_throttle_args("down:100k up:1m")
        assert down == 100_000
        assert up == 1_000_000
        assert delay == 0

    def test_delay_ms(self):
        down, up, delay = parse_throttle_args("delay:300ms")
        assert down is None
        assert up is None
        assert delay == 300

    def test_delay_seconds(self):
        _, _, delay = parse_throttle_args("delay:2s")
        assert delay == 2000

    def test_speed_with_delay(self):
        down, up, delay = parse_throttle_args("down:50k delay:200ms")
        assert down == 50_000
        assert up is None
        assert delay == 200

    def test_simple_speed_does_not_override_explicit(self):
        # "200k down:50k" — simple sets up only because down is already set
        down, up, delay = parse_throttle_args("200k down:50k")
        assert down == 50_000
        assert up == 200_000

    def test_case_insensitive(self):
        down, up, _ = parse_throttle_args("DOWN:100K UP:200K")
        assert down == 100_000
        assert up == 200_000


# ---------------------------------------------------------------------------
# ThrottleState
# ---------------------------------------------------------------------------

class TestThrottleState:
    def test_active_when_either_set(self):
        assert ThrottleState(download_bps=100).active
        assert ThrottleState(upload_bps=100).active
        assert not ThrottleState().active

    def test_summary_both(self):
        s = ThrottleState(download_bps=200_000, upload_bps=1_000_000)
        assert "↓200K" in s.summary()
        assert "↑1M" in s.summary()

    def test_summary_download_only(self):
        s = ThrottleState(download_bps=500)
        assert s.summary() == "↓500B"
        assert "↑" not in s.summary()


# ---------------------------------------------------------------------------
# ThrottleEngine — add / remove / version
# ---------------------------------------------------------------------------

class TestThrottleEngineRules:
    def test_add_rule_increments_version(self):
        e = ThrottleEngine()
        v0 = e.version
        e.add_rule("*.example.com", "100k")
        assert e.version > v0

    def test_update_existing_rule_increments_version(self):
        e = ThrottleEngine()
        e.add_rule("*.example.com", "100k")
        v1 = e.version
        e.add_rule("*.example.com", "200k")  # update
        assert e.version > v1
        assert len(e.rules) == 1
        assert e.rules[0].download_bps == 200_000

    def test_remove_rule_increments_version(self):
        e = ThrottleEngine()
        e.add_rule("*.example.com", "100k")
        v1 = e.version
        removed = e.remove_rule("*.example.com")
        assert removed is True
        assert e.version > v1
        assert len(e.rules) == 0

    def test_remove_nonexistent_returns_false(self):
        e = ThrottleEngine()
        assert e.remove_rule("*.nothing.com") is False

    def test_reset_clears_all(self):
        e = ThrottleEngine()
        e.add_rule("*.example.com", "100k")
        e.add_cat_rule("analytics", "50k")
        e.reset()
        assert e.rules == []
        assert e.cat_rules == {}


# ---------------------------------------------------------------------------
# ThrottleEngine — matching
# ---------------------------------------------------------------------------

class TestThrottleEngineMatch:
    def test_exact_host_matches(self):
        e = ThrottleEngine()
        e.add_rule("ads.example.com", "100k")
        r = e.match("ads.example.com")
        assert r is not None
        assert r.download_bps == 100_000

    def test_wildcard_matches_subdomain(self):
        e = ThrottleEngine()
        e.add_rule("*.example.com", "100k")
        assert e.match("sub.example.com") is not None
        assert e.match("example.com") is None

    def test_no_match_returns_none(self):
        e = ThrottleEngine()
        e.add_rule("*.example.com", "100k")
        assert e.match("other.org") is None

    def test_host_rule_takes_priority_over_cat_rule(self):
        e = ThrottleEngine()
        e.add_rule("ads.example.com", "100k")
        e.add_cat_rule("advertising", "500k")
        r = e.match("ads.example.com", category="advertising")
        assert r.download_bps == 100_000  # host rule wins

    def test_cat_rule_fallback(self):
        e = ThrottleEngine()
        e.add_cat_rule("analytics", "50k")
        r = e.match("unknown.host.com", category="analytics")
        assert r is not None
        assert r.download_bps == 50_000

    def test_match_case_insensitive(self):
        e = ThrottleEngine()
        e.add_rule("*.Example.COM", "100k")
        assert e.match("sub.example.com") is not None

    def test_first_rule_wins(self):
        e = ThrottleEngine()
        e.add_rule("*.example.com", "100k")
        e.add_rule("sub.example.com", "999k")  # more specific but added second
        r = e.match("sub.example.com")
        assert r.download_bps == 100_000  # first match wins


# ---------------------------------------------------------------------------
# ThrottleEngine — category rules
# ---------------------------------------------------------------------------

class TestThrottleEngineCatRules:
    def test_add_cat_rule(self):
        e = ThrottleEngine()
        e.add_cat_rule("analytics", "down:100k up:200k")
        r = e.match_cat("analytics")
        assert r is not None
        assert r.download_bps == 100_000
        assert r.upload_bps == 200_000

    def test_remove_cat_rule(self):
        e = ThrottleEngine()
        e.add_cat_rule("analytics", "100k")
        assert e.remove_cat_rule("analytics") is True
        assert e.match_cat("analytics") is None

    def test_remove_nonexistent_cat_rule(self):
        e = ThrottleEngine()
        assert e.remove_cat_rule("nope") is False

    def test_cat_rule_case_insensitive(self):
        e = ThrottleEngine()
        e.add_cat_rule("Analytics", "100k")
        assert e.match_cat("analytics") is not None


# ---------------------------------------------------------------------------
# ThrottleEngine — load_from_rules_file
# ---------------------------------------------------------------------------

class TestThrottleEngineLoad:
    def test_load_host_rules(self, tmp_path):
        p = tmp_path / "rules.txt"
        p.write_text("throttle *.ads.com 100k\nthrottle slow.api.com down:50k\n")
        e = ThrottleEngine()
        n = e.load_from_rules_file(p)
        assert n == 2
        assert e.match("x.ads.com") is not None
        assert e.match("slow.api.com") is not None

    def test_load_cat_rules(self, tmp_path):
        p = tmp_path / "rules.txt"
        p.write_text("throttle @analytics 50k\n")
        e = ThrottleEngine()
        n = e.load_from_rules_file(p)
        assert n == 1
        assert e.match_cat("analytics") is not None

    def test_skips_comments_and_blank_lines(self, tmp_path):
        p = tmp_path / "rules.txt"
        p.write_text("# comment\n\nthrottle *.example.com 100k\n")
        e = ThrottleEngine()
        n = e.load_from_rules_file(p)
        assert n == 1

    def test_skips_non_throttle_lines(self, tmp_path):
        p = tmp_path / "rules.txt"
        p.write_text("deny bad.com\nallow good.com\nthrottle slow.com 100k\n")
        e = ThrottleEngine()
        n = e.load_from_rules_file(p)
        assert n == 1

    def test_missing_file_returns_zero(self):
        e = ThrottleEngine()
        n = e.load_from_rules_file("/nonexistent/path/rules.txt")
        assert n == 0

    def test_version_incremented_even_when_zero_rules(self, tmp_path):
        p = tmp_path / "empty.txt"
        p.write_text("# nothing here\n")
        e = ThrottleEngine()
        v0 = e.version
        e.load_from_rules_file(p)
        assert e.version > v0
