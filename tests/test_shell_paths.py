"""Tests for fake shell - new filesystem commands and path handling."""
import pytest

from honeypot.shell import FakeShell
from honeypot.session import Session


@pytest.fixture
def shell():
    session = Session(source_ip='127.0.0.1')
    return FakeShell(session)


class TestNewFilesystemCommands:
    """Verify newer filesystem commands."""

    def test_tree(self, shell):
        output = shell.execute('tree /home/user1')
        assert 'Documents' in output
        assert 'Downloads' in output

    def test_find(self, shell):
        output = shell.execute('find /etc')
        assert 'passwd' in output

    def test_head(self, shell):
        output = shell.execute('head /etc/passwd')
        assert len(output) > 0

    def test_tail(self, shell):
        output = shell.execute('tail /etc/passwd')
        assert len(output) > 0

    def test_grep(self, shell):
        output = shell.execute('grep root /etc/passwd')
        assert 'root' in output

    def test_wc(self, shell):
        output = shell.execute('wc /etc/passwd')
        assert len(output) > 0

    def test_stat(self, shell):
        output = shell.execute('stat /etc/passwd')
        assert len(output) > 0


class TestPathHandling:
    """Verify path handling across commands."""

    def test_absolute_path(self, shell):
        output = shell.execute('cat /etc/passwd')
        assert 'root' in output

    def test_relative_path(self, shell):
        shell.execute('cd /home/user1')
        output = shell.execute('ls')
        assert 'Documents' in output

    def test_dot_notation(self, shell):
        shell.execute('cd /home/user1')
        output = shell.execute('ls .')
        assert 'Documents' in output

    def test_dotdot_notation(self, shell):
        shell.execute('cd /home/user1')
        shell.execute('cd ..')
        assert shell.session.cwd == '/home'

    def test_nested_path(self, shell):
        output = shell.execute('ls /home/user1/Documents')
        assert output is not None


class TestPerSessionIsolation:
    """Verify each session has independent filesystem and cwd."""

    def test_independent_filesystem(self):
        s1 = Session(source_ip='127.0.0.1')
        s2 = Session(source_ip='127.0.0.1')
        shell1 = FakeShell(s1)
        shell2 = FakeShell(s2)
        shell1.execute('touch /home/user1/secret.txt')
        output = shell2.execute('ls /home/user1')
        assert 'secret.txt' not in output

    def test_independent_cwd(self):
        s1 = Session(source_ip='127.0.0.1')
        s2 = Session(source_ip='127.0.0.1')
        shell1 = FakeShell(s1)
        shell2 = FakeShell(s2)
        shell1.execute('cd /etc')
        assert shell2.execute('pwd') == '/home/user1'
        assert shell1.execute('pwd') == '/etc'
