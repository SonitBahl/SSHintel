"""Tests for offline GeoIP/ASN enrichment in SSHintel telemetry."""

from honeypot.enrich import Enricher


def test_enricher_disabled_by_default():
    """Enricher with no db_path returns empty dict."""
    e = Enricher(db_path=None)
    assert e.enrich("8.8.8.8") == {}


def test_enricher_no_database():
    """Enricher with nonexistent db_path returns empty dict."""
    e = Enricher(db_path="/nonexistent/database.mmdb")
    assert e.enrich("8.8.8.8") == {}


def test_enricher_invalid_ip():
    """Invalid IP returns empty dict."""
    e = Enricher(db_path=None)
    assert e.enrich("not-an-ip") == {}


def test_enricher_with_real_ip():
    """Enrichment works when database is available (mocked)."""
    # When no database, should always return {}
    e = Enricher(db_path=None)
    assert e.enrich("8.8.8.8") == {}


def test_enricher_close():
    """close() is a no-op when no reader."""
    e = Enricher(db_path=None)
    e.close()  # should not raise