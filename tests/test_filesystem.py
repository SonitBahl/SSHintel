"""Tests for the in-memory fake filesystem.

Verifies filesystem creation, path handling, file/directory operations,
and per-session isolation guarantees.
"""
import pytest

from honeypot.fs import create_filesystem, normalize_path, resolve_abs, split_path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fs():
    """Return a fresh fake filesystem."""
    return create_filesystem()


# ---------------------------------------------------------------------------
# Filesystem creation
# ---------------------------------------------------------------------------

class TestFilesystemCreation:
    """Verify the fake filesystem is created with the expected structure."""

    def test_returns_dict(self, fs):
        assert isinstance(fs, dict)

    def test_has_root_directories(self, fs):
        expected = {'bin', 'etc', 'home', 'root', 'tmp', 'usr', 'var'}
        assert set(fs.keys()) == expected

    def test_etc_has_passwd(self, fs):
        assert 'passwd' in fs['etc']

    def test_etc_has_hostname(self, fs):
        assert 'hostname' in fs['etc']

    def test_home_has_user(self, fs):
        assert 'user1' in fs['home']
        assert 'Documents' in fs['home']['user1']
        assert 'Downloads' in fs['home']['user1']

    def test_var_has_log(self, fs):
        assert 'log' in fs['var']

    def test_nested_directory_is_dict(self, fs):
        assert isinstance(fs['home']['user1'], dict)
        assert isinstance(fs['etc'], dict)

    def test_file_is_string(self, fs):
        assert isinstance(fs['etc']['passwd'], str)

    def test_tmp_has_files(self, fs):
        # tmp directory has a readme.txt file by default
        assert 'readme.txt' in fs['tmp']
