"""Tests for fake shell command handlers - system and identity commands."""
import pytest

from honeypot.shell import FakeShell
from honeypot.session import Session


@pytest.fixture
def shell():
    session = Session(source_ip='127.0.0.1')
    return FakeShell(session)


class TestSystemCommands:
    """Verify system reconnaissance commands."""

    def test_env(self, shell):
        output = shell.execute('env')
        assert len(output) > 0

    def test_printenv(self, shell):
        output = shell.execute('printenv')
        assert len(output) > 0

    def test_date(self, shell):
        output = shell.execute('date')
        assert len(output) > 0

    def test_uptime(self, shell):
        output = shell.execute('uptime')
        assert len(output) > 0

    def test_ps(self, shell):
        output = shell.execute('ps')
        assert len(output) > 0

    def test_df(self, shell):
        output = shell.execute('df')
        assert len(output) > 0

    def test_free(self, shell):
        output = shell.execute('free')
        assert len(output) > 0


class TestIdentityCommands:
    """Verify identity/reconnaissance commands."""

    def test_whoami(self, shell):
        assert shell.execute('whoami') == 'user1'

    def test_hostname(self, shell):
        output = shell.execute('hostname')
        assert len(output) > 0

    def test_uname(self, shell):
        output = shell.execute('uname -a')
        assert 'Linux' in output

    def test_id(self, shell):
        output = shell.execute('id')
        assert 'uid' in output

    def test_groups(self, shell):
        output = shell.execute('groups')
        assert len(output) > 0


class TestShellCommands:
    """Verify shell interaction commands."""

    def test_history(self, shell):
        output = shell.execute('history')
        # History returns a simulated bash_history content
        assert 'ls' in output or 'pwd' in output or 'whoami' in output
        assert len(output) > 0

    def test_which(self, shell):
        output = shell.execute('which ls')
        assert len(output) > 0

    def test_type(self, shell):
        output = shell.execute('type ls')
        assert len(output) > 0

    def test_help(self, shell):
        output = shell.execute('help')
        assert len(output) > 0
