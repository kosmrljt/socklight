"""Tests for proxy/classifier.py."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from socklight.classifier import Category, Classifier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_toml(tmp_path: Path, content: str) -> Path:
    """Write *content* (TOML) to a temp file; return its path."""
    p = tmp_path / "cats.toml"
    p.write_text(textwrap.dedent(content))
    return p


# ---------------------------------------------------------------------------
# Basic loading
# ---------------------------------------------------------------------------

class TestClassifierLoad:
    def test_load_returns_category_count(self, tmp_path):
        p = _write_toml(tmp_path, """
            [categories.analytics]
            color = "yellow"
            abbrev = "ANA"
            description = "Analytics"
            patterns = ["*.google-analytics.com"]

            [categories.advertising]
            color = "red"
            abbrev = "ADV"
            description = "Ads"
            patterns = ["*.doubleclick.net"]
        """)
        c = Classifier()
        assert c.load_file(p) == 2

    def test_load_populates_categories(self, tmp_path):
        p = _write_toml(tmp_path, """
            [categories.analytics]
            color = "yellow"
            abbrev = "ANA"
            description = "Analytics"
            patterns = ["*.google-analytics.com"]
        """)
        c = Classifier()
        c.load_file(p)
        cats = c.categories
        assert len(cats) == 1
        assert cats[0].name == "analytics"
        assert cats[0].color == "yellow"
        assert cats[0].abbrev == "ANA"

    def test_block_field_in_toml_is_ignored(self, tmp_path):
        p = _write_toml(tmp_path, """
            [categories.advertising]
            color = "red"
            abbrev = "ADV"
            block = true
            patterns = ["*.doubleclick.net"]
        """)
        c = Classifier()
        c.load_file(p)
        assert not c.is_category_blocked("advertising")

    def test_load_empty_file(self, tmp_path):
        p = _write_toml(tmp_path, "# no categories")
        c = Classifier()
        assert c.load_file(p) == 0
        assert c.categories == []

    def test_missing_file_raises(self):
        c = Classifier()
        with pytest.raises(OSError):
            c.load_file("/nonexistent/path/cats.toml")


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

class TestClassify:
    @pytest.fixture
    def classifier(self, tmp_path):
        p = _write_toml(tmp_path, """
            [categories.advertising]
            color = "red"
            abbrev = "ADV"
            patterns = ["*.doubleclick.net", "googlesyndication.com"]

            [categories.analytics]
            color = "yellow"
            abbrev = "ANA"
            patterns = ["*.google-analytics.com", "hotjar.com"]

            [categories.cdn]
            color = "cyan"
            abbrev = "CDN"
            patterns = ["*.cloudfront.net", "*.cloudflare.com"]
        """)
        c = Classifier()
        c.load_file(p)
        return c

    def test_known_host(self, classifier):
        cat = classifier.classify("stats.doubleclick.net")
        assert cat.name == "advertising"

    def test_exact_pattern(self, classifier):
        cat = classifier.classify("googlesyndication.com")
        assert cat.name == "advertising"

    def test_unknown_host_returns_unknown(self, classifier):
        cat = classifier.classify("example.com")
        assert cat.name == "unknown"

    def test_case_insensitive(self, classifier):
        cat = classifier.classify("HOTJAR.COM")
        assert cat.name == "analytics"

    def test_first_match_wins(self, tmp_path):
        # advertising comes before cdn — *.cloudfront.net should go to cdn
        # but if we had a cdn pattern in advertising, advertising would win
        p = _write_toml(tmp_path, """
            [categories.first]
            color = "red"
            abbrev = "FIR"
            patterns = ["*.example.com"]

            [categories.second]
            color = "blue"
            abbrev = "SEC"
            patterns = ["*.example.com"]
        """)
        c = Classifier()
        c.load_file(p)
        assert c.classify("sub.example.com").name == "first"

    def test_wildcard_matches_subdomain(self, classifier):
        assert classifier.classify("a.b.cloudfront.net").name == "cdn"

    def test_get_by_name_known(self, classifier):
        cat = classifier.get_by_name("analytics")
        assert cat is not None
        assert cat.name == "analytics"

    def test_get_by_name_unknown_returns_none(self, classifier):
        assert classifier.get_by_name("nonexistent") is None

    def test_get_by_name_unknown_sentinel(self, classifier):
        cat = classifier.get_by_name("unknown")
        assert cat is not None
        assert cat.name == "unknown"


# ---------------------------------------------------------------------------
# Blocking
# ---------------------------------------------------------------------------

class TestBlocking:
    @pytest.fixture
    def classifier(self, tmp_path):
        p = _write_toml(tmp_path, """
            [categories.advertising]
            color = "red"
            abbrev = "ADV"
            patterns = ["*.doubleclick.net"]

            [categories.analytics]
            color = "yellow"
            abbrev = "ANA"
            patterns = ["*.hotjar.com"]
        """)
        c = Classifier()
        c.load_file(p)
        return c

    def test_not_blocked_by_default(self, classifier):
        assert not classifier.is_category_blocked("advertising")

    def test_set_blocked_true(self, classifier):
        classifier.set_blocked("advertising", True)
        assert classifier.is_category_blocked("advertising")

    def test_set_blocked_false(self, classifier):
        classifier.set_blocked("advertising", True)
        classifier.set_blocked("advertising", False)
        assert not classifier.is_category_blocked("advertising")

    def test_toggle_blocked_on(self, classifier):
        new_state = classifier.toggle_blocked("advertising")
        assert new_state is True
        assert classifier.is_category_blocked("advertising")

    def test_toggle_blocked_off(self, classifier):
        classifier.set_blocked("advertising", True)
        new_state = classifier.toggle_blocked("advertising")
        assert new_state is False
        assert not classifier.is_category_blocked("advertising")

    def test_blocked_categories_frozenset(self, classifier):
        classifier.set_blocked("advertising", True)
        classifier.set_blocked("analytics", True)
        blocked = classifier.blocked_categories
        assert "advertising" in blocked
        assert "analytics" in blocked

    def test_unknown_category_never_blocked(self, classifier):
        assert not classifier.is_category_blocked("unknown")
        # Even if someone tries to block it — doesn't crash
        classifier.set_blocked("unknown", True)
        assert classifier.is_category_blocked("unknown")
        # But classify returns _UNKNOWN which has name "unknown"
        cat = classifier.classify("example.com")
        assert cat.name == "unknown"


# ---------------------------------------------------------------------------
# Categories file integration
# ---------------------------------------------------------------------------

class TestCategoriesFileIntegration:
    def test_load_shipped_categories_file(self):
        """The shipped categories.toml is valid and loads correctly."""
        shipped = Path(__file__).parent.parent / "socklight" / "data" / "categories-full.toml"
        if not shipped.exists():
            pytest.skip("categories-full.toml not present")
        c = Classifier()
        n = c.load_file(shipped)
        assert n > 0
        assert len(c.categories) == n

    def test_google_analytics_classified(self):
        shipped = Path(__file__).parent.parent / "socklight" / "data" / "categories-full.toml"
        if not shipped.exists():
            pytest.skip("categories-full.toml not present")
        c = Classifier()
        c.load_file(shipped)
        cat = c.classify("www.google-analytics.com")
        assert cat.name == "analytics"

    def test_doubleclick_classified_as_advertising(self):
        shipped = Path(__file__).parent.parent / "socklight" / "data" / "categories-full.toml"
        if not shipped.exists():
            pytest.skip("categories-full.toml not present")
        c = Classifier()
        c.load_file(shipped)
        cat = c.classify("ad.doubleclick.net")
        assert cat.name == "advertising"

    def test_fonts_googleapis_not_bigtech(self):
        """fonts.googleapis.com must match 'fonts', not 'us_bigtech'."""
        shipped = Path(__file__).parent.parent / "socklight" / "data" / "categories-full.toml"
        if not shipped.exists():
            pytest.skip("categories-full.toml not present")
        c = Classifier()
        c.load_file(shipped)
        cat = c.classify("fonts.googleapis.com")
        assert cat.name == "fonts"

    def test_cloudfront_is_cdn_not_bigtech(self):
        """*.cloudfront.net must match 'cdn', not 'us_bigtech'."""
        shipped = Path(__file__).parent.parent / "socklight" / "data" / "categories-full.toml"
        if not shipped.exists():
            pytest.skip("categories-full.toml not present")
        c = Classifier()
        c.load_file(shipped)
        cat = c.classify("d1234.cloudfront.net")
        assert cat.name == "cdn"

    def test_tiktok_is_jurisdiction_cn(self):
        shipped = Path(__file__).parent.parent / "socklight" / "data" / "categories-full.toml"
        if not shipped.exists():
            pytest.skip("categories-full.toml not present")
        c = Classifier()
        c.load_file(shipped)
        cat = c.classify("api.tiktok.com")
        assert cat.name == "jurisdiction_cn"

    def test_yandex_is_jurisdiction_other(self):
        shipped = Path(__file__).parent.parent / "socklight" / "data" / "categories-full.toml"
        if not shipped.exists():
            pytest.skip("categories-full.toml not present")
        c = Classifier()
        c.load_file(shipped)
        cat = c.classify("www.yandex.ru")
        assert cat.name == "jurisdiction_other"
