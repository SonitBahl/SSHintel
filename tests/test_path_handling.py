"""Tests for path handling in the fake filesystem."""
import pytest

from honeypot.fs import normalize_path, resolve_abs, split_path


class TestPathNormalization:
    """Verify path normalization collapses . and .. components.

    Note: normalize_path always produces an absolute path, so relative inputs
    get a leading "/" prepended (e.g. "Documents" -> "/Documents").
    """

    def test_empty_path_returns_root(self):
        assert normalize_path('') == '/'

    def test_single_slash(self):
        assert normalize_path('/') == '/'

    def test_absolute_path(self):
        assert normalize_path('/home/user1') == '/home/user1'

    def test_removes_dot(self):
        assert normalize_path('/home/./user1') == '/home/user1'

    def test_removes_double_dot(self):
        # /home/user1/../etc -> go up from user1 to home, then into etc
        assert normalize_path('/home/user1/../etc') == '/home/etc'

    def test_multiple_double_dots(self):
        assert normalize_path('/a/b/c/../../d') == '/a/d'

    def test_double_dot_beyond_root(self):
        # Cannot go above root
        assert normalize_path('/../../etc') == '/etc'

    def test_relative_path_becomes_absolute(self):
        assert normalize_path('Documents') == '/Documents'

    def test_relative_with_dot(self):
        assert normalize_path('./Documents') == '/Documents'


class TestSplitPath:
    """Verify path splitting into (parent, basename) components."""

    def test_absolute_path(self):
        assert split_path('/home/user1') == ('/home', 'user1')

    def test_root(self):
        assert split_path('/') == ('/', '')

    def test_deep_path(self):
        assert split_path('/a/b/c') == ('/a/b', 'c')

    def test_empty_path_normalizes_to_root(self):
        assert split_path('') == ('/', '')


class TestResolveAbs:
    """Verify absolute path resolution."""

    def test_already_absolute(self):
        # When target is absolute, it is used directly (cwd ignored)
        assert resolve_abs('/home/user1', '/etc') == '/etc'

    def test_relative_from_cwd(self):
        # When target is relative, it is resolved against cwd
        assert resolve_abs('/home/user1', 'Documents') == '/home/user1/Documents'

    def test_relative_with_dotdot(self):
        # ../etc from /home/user1 goes up to /home, then etc -> /home/etc
        assert resolve_abs('/home/user1', '../etc') == '/home/etc'

    def test_double_dotdot_goes_above_home(self):
        # ../../etc from /home/user1 goes up two levels (home, user1) -> /etc
        assert resolve_abs('/home/user1', '../../etc') == '/etc'

    def test_root_cwd_with_relative(self):
        assert resolve_abs('/', 'etc') == '/etc'

    def test_empty_relative(self):
        assert resolve_abs('/home/user1', '') == '/home/user1'
