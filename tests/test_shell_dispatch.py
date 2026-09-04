"""Tests for the fake shell command dispatcher and handlers."""
import pytest

from honeypot.shell import FakeShell, COMMAND_REGISTRY
from honeypot.session import Session


@pytest.fixture
def shell():
    """Return a fresh FakeShell with a fresh session."""
    session = Session(source_ip='127.0.0.1')
    return FakeShell(session)


class TestCommandDispatch:
    """Verify the command dispatcher routes correctly."""

    def test_known_command_returns_output(self, shell):
        output = shell.execute('pwd')
        assert output == '/home/user1'

    def test_unknown_command_returns_error(self, shell):
        output = shell.execute('nonexistent_command_xyz')
        assert 'command not found' in output

    def test_empty_input_returns_empty(self, shell):
        output = shell.execute('')
        assert output == ''

    def test_whitespace_only_returns_empty(self, shell):
        output = shell.execute('   ')
        assert output == ''

    def test_exit_sets_exited_flag(self, shell):
        shell.execute('exit')
        assert shell.exited is True


class TestCommandRegistry:
    """Verify the COMMAND_REGISTRY contains expected commands."""

    def test_has_filesystem_commands(self):
        for cmd in ['pwd', 'cd', 'ls', 'mkdir', 'rm', 'touch', 'cat', 'echo']:
            assert cmd in COMMAND_REGISTRY, f"Missing command: {cmd}"

    def test_has_new_commands(self):
        for cmd in ['tree', 'find', 'head', 'tail', 'grep', 'wc', 'stat']:
            assert cmd in COMMAND_REGISTRY, f"Missing command: {cmd}"

    def test_has_env_commands(self):
        for cmd in ['env', 'printenv', 'date', 'uptime', 'ps', 'df', 'free']:
            assert cmd in COMMAND_REGISTRY, f"Missing command: {cmd}"

    def test_has_identity_commands(self):
        for cmd in ['whoami', 'hostname', 'uname', 'id', 'groups', 'user']:
            assert cmd in COMMAND_REGISTRY, f"Missing command: {cmd}"

    def test_has_shell_commands(self):
        for cmd in ['history', 'which', 'type', 'help']:
            assert cmd in COMMAND_REGISTRY, f"Missing command: {cmd}"

    def test_has_suspicious_commands(self):
        for cmd in ['wget', 'curl', 'sudo', 'chmod', 'chown', 'ssh', 'scp']:
            assert cmd in COMMAND_REGISTRY, f"Missing command: {cmd}"
