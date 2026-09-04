"""Tests for per-session filesystem isolation."""
import pytest

from honeypot.fs import create_filesystem


class TestSessionIsolation:
    """Each session must get a completely independent filesystem."""

    def test_two_filesystems_are_independent(self):
        fs1 = create_filesystem()
        fs2 = create_filesystem()
        assert fs1 is not fs2

    def test_mutate_one_does_not_affect_other(self):
        fs1 = create_filesystem()
        fs2 = create_filesystem()
        fs1['tmp']['secret'] = 'attacker data'
        assert 'secret' not in fs2['tmp']

    def test_deletion_isolated(self):
        fs1 = create_filesystem()
        fs2 = create_filesystem()
        del fs1['etc']['passwd']
        assert 'passwd' in fs2['etc']

    def test_directory_creation_isolated(self):
        fs1 = create_filesystem()
        fs2 = create_filesystem()
        fs1['home']['user1']['hacked'] = {}
        assert 'hacked' not in fs2['home']['user1']

    def test_deep_nested_mutation_isolated(self):
        fs1 = create_filesystem()
        fs2 = create_filesystem()
        fs1['home']['user1']['Documents']['payload.sh'] = 'malicious'
        assert 'payload.sh' not in fs2['home']['user1']['Documents']

    def test_filesystem_is_deep_copy(self):
        """Verify create_filesystem returns a deep copy."""
        fs1 = create_filesystem()
        fs2 = create_filesystem()
        assert fs1['home'] is not fs2['home']
        assert fs1['etc'] is not fs2['etc']
        assert fs1['home']['user1'] is not fs2['home']['user1']

    def test_create_filesystem_factory_returns_fresh(self):
        """Calling the factory repeatedly must never return a shared reference."""
        filesystems = [create_filesystem() for _ in range(10)]
        for i, fs_i in enumerate(filesystems):
            for j, fs_j in enumerate(filesystems):
                if i != j:
                    assert fs_i is not fs_j


class TestFileOperations:
    """Verify file/directory creation, lookup, and deletion."""

    def test_lookup_existing_file(self, fs):
        passwd = fs['etc']['passwd']
        assert isinstance(passwd, str)
        assert len(passwd) > 0

    def test_lookup_existing_directory(self, fs):
        home = fs['home']
        assert isinstance(home, dict)

    def test_lookup_nonexistent_file(self, fs):
        with pytest.raises(KeyError):
            _ = fs['nonexistent']

    def test_create_file(self, fs):
        fs['etc']['newfile.txt'] = 'new content'
        assert fs['etc']['newfile.txt'] == 'new content'

    def test_create_directory(self, fs):
        fs['home']['user1']['newdir'] = {}
        assert isinstance(fs['home']['user1']['newdir'], dict)

    def test_delete_file(self, fs):
        fs['etc']['passwd'] = 'test'
        del fs['etc']['passwd']
        assert 'passwd' not in fs['etc']

    def test_delete_directory(self, fs):
        fs['home']['user1']['deleteme'] = {}
        del fs['home']['user1']['deleteme']
        assert 'deleteme' not in fs['home']['user1']

    def test_write_updates_content(self, fs):
        fs['etc']['passwd'] = 'updated'
        assert fs['etc']['passwd'] == 'updated'


@pytest.fixture
def fs():
    return create_filesystem()


class TestNoRealFilesystemAccess:
    """Verify the fake filesystem never touches the host filesystem."""

    def test_filesystem_contains_no_paths(self, fs):
        for key in fs:
            assert '/' not in key
            assert key != ''
            assert isinstance(key, str)

    def test_no_pathlib_or_os_in_fs_module(self):
        import inspect
        import honeypot.fs as fs_module
        source = inspect.getsource(fs_module)
        assert 'import os' not in source
        assert 'import pathlib' not in source

    def test_no_subprocess_in_fs_module(self):
        import inspect
        import honeypot.fs as fs_module
        source = inspect.getsource(fs_module)
        assert 'subprocess' not in source
        assert 'os.system' not in source

    def test_no_open_calls_in_fs_module(self):
        import inspect
        import honeypot.fs as fs_module
        source = inspect.getsource(fs_module)
        assert 'open(' not in source

    def test_no_network_in_fs_module(self):
        import inspect
        import honeypot.fs as fs_module
        source = inspect.getsource(fs_module)
        assert 'socket' not in source
        assert 'urllib' not in source
        assert 'requests' not in source
