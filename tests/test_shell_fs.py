"""Tests for fake shell command handlers - filesystem and navigation."""
import pytest

from honeypot.shell import FakeShell
from honeypot.session import Session


@pytest.fixture
def shell():
    session = Session(source_ip='127.0.0.1')
    return FakeShell(session)


class TestFilesystemCommands:
    """Verify filesystem-related commands."""

    def test_pwd(self, shell):
        assert shell.execute('pwd') == '/home/user1'

    def test_ls(self, shell):
        output = shell.execute('ls')
        assert 'Documents' in output
        assert 'Downloads' in output

    def test_ls_la(self, shell):
        output = shell.execute('ls -la')
        assert 'Documents' in output

    def test_cd_changes_cwd(self, shell):
        shell.execute('cd /etc')
        assert shell.session.cwd == '/etc'

    def test_cd_home(self, shell):
        shell.execute('cd /etc')
        shell.execute('cd /home/user1')
        assert shell.session.cwd == '/home/user1'

    def test_mkdir_creates_directory(self, shell):
        shell.execute('mkdir /home/user1/newdir')
        assert 'newdir' in shell.session.fake_filesystem['home']['user1']

    def test_touch_creates_file(self, shell):
        shell.execute('touch /home/user1/test.txt')
        assert 'test.txt' in shell.session.fake_filesystem['home']['user1']

    def test_rm_removes_file(self, shell):
        shell.execute('touch /home/user1/test.txt')
        shell.execute('rm /home/user1/test.txt')
        assert 'test.txt' not in shell.session.fake_filesystem['home']['user1']

    def test_cat_reads_file(self, shell):
        output = shell.execute('cat /etc/passwd')
        assert len(output) > 0
        assert 'root' in output

    def test_echo_argument(self, shell):
        output = shell.execute('echo hello world')
        assert output == 'hello world'

    def test_echo_redirect_creates_file(self, shell):
        shell.execute('echo "test content" > /home/user1/output.txt')
        assert shell.session.fake_filesystem['home']['user1']['output.txt'] == 'test content'
