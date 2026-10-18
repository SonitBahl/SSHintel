"""Tests for shell realism — Commit 08 (/proc + system-information responses).

Every fabricated value is static content in ``honeypot/fs.py`` (plus uname
parts in ``honeypot/shell.py``), so successive reads always agree both within
a session and across sessions (resolves Open Question Q3: no per-session
random is needed — static content cannot disagree).
"""
import pytest

from honeypot.shell import FakeShell, KERNEL_RELEASE, KERNEL_VERSION, MACHINE
from honeypot.session import Session


@pytest.fixture
def shell():
    session = Session(source_ip='127.0.0.1')
    return FakeShell(session)


@pytest.fixture
def shell2():
    session = Session(source_ip='10.0.0.2')
    return FakeShell(session)


class TestProcFiles:
    """Each /proc path must be readable with plausible content."""

    @pytest.mark.parametrize("path", [
        '/proc/cpuinfo',
        '/proc/meminfo',
        '/proc/version',
        '/proc/uptime',
        '/proc/loadavg',
    ])
    def test_proc_paths_readable(self, shell, path):
        output = shell.execute(f'cat {path}')
        assert 'No such file' not in output
        assert len(output.strip()) > 0

    def test_cpuinfo_has_cpu_block(self, shell):
        output = shell.execute('cat /proc/cpuinfo')
        assert 'model name' in output
        assert 'processor' in output

    def test_cpuinfo_serial_redacted_but_present(self, shell):
        # X-style redaction marker: a fixed literal, not host data.
        output = shell.execute('cat /proc/cpuinfo')
        assert 'XXXX' in output

    def test_meminfo_matches_free(self, shell):
        meminfo = shell.execute('cat /proc/meminfo')
        free = shell.execute('free')
        assert 'MemTotal' in meminfo
        # MemTotal kB in meminfo agrees with the KiB figure in `free`.
        assert '7964156' in meminfo
        assert '7964156' in free

    def test_version_matches_uname(self, shell):
        version = shell.execute('cat /proc/version')
        assert KERNEL_RELEASE in version
        assert KERNEL_VERSION in version

    def test_uptime_proc_matches_uptime_cmd(self, shell):
        # /proc/uptime holds up/idle seconds (uptime duration agrees with the
        # 4-days figure in `uptime`); load averages live in /proc/loadavg.
        proc = shell.execute('cat /proc/uptime')
        cmd = shell.execute('uptime')
        assert 'load average' in cmd
        assert proc.split()[0] == '364320.00'  # 4 days, 5:12 in seconds
        loadavg = shell.execute('cat /proc/loadavg')
        for avg in ('0.08', '0.03', '0.01'):
            assert avg in loadavg
            assert avg in cmd


class TestEtcFiles:
    @pytest.mark.parametrize("path,marker", [
        ('/etc/hosts', 'localhost'),
        ('/etc/resolv.conf', 'nameserver'),
        ('/etc/group', 'root:x:0:'),
    ])
    def test_etc_paths_readable(self, shell, path, marker):
        output = shell.execute(f'cat {path}')
        assert 'No such file' not in output
        assert marker in output

    def test_hosts_mentions_hostname(self, shell):
        assert 'ubuntu' in shell.execute('cat /etc/hosts')


class TestUnameFlags:
    def test_bare_uname_is_kernel_name(self, shell):
        assert shell.execute('uname') == 'Linux'

    def test_flags_return_distinct_values(self, shell):
        r = shell.execute('uname -r')
        m = shell.execute('uname -m')
        n = shell.execute('uname -n')
        s = shell.execute('uname -s')
        assert r == KERNEL_RELEASE
        assert m == MACHINE
        assert m != r
        assert n == 'ubuntu'
        assert s == 'Linux'

    def test_uname_v_returns_version(self, shell):
        assert KERNEL_VERSION in shell.execute('uname -v')

    def test_combined_flags_concatenate(self, shell):
        assert shell.execute('uname -sm') == f'Linux {MACHINE}'

    def test_uname_a_contains_all_parts(self, shell):
        a = shell.execute('uname -a')
        for part in ('Linux', 'ubuntu', KERNEL_RELEASE, MACHINE):
            assert part in a

    def test_invalid_flag_errors(self, shell):
        output = shell.execute('uname -z')
        assert 'invalid option' in output


class TestStability:
    def test_values_stable_within_session(self, shell):
        first = shell.execute('cat /proc/cpuinfo')
        second = shell.execute('cat /proc/cpuinfo')
        assert first == second

    def test_values_stable_across_sessions(self, shell, shell2):
        assert (shell.execute('cat /proc/cpuinfo')
                == shell2.execute('cat /proc/cpuinfo'))
        assert (shell.execute('uname -a') == shell2.execute('uname -a'))


class TestNoHostLeak:
    def test_proc_is_virtual_not_host(self, shell):
        # Real host PIDs must not appear; the fake /proc has a fixed file set.
        assert 'No such file' in shell.execute('cat /proc/1/cmdline')
        assert 'self' not in shell.execute('ls /proc').split()

    def test_proc_files_match_fixed_set(self, shell):
        entries = shell.execute('ls /proc').split()
        assert set(entries) == {
            'cpuinfo', 'meminfo', 'version', 'uptime', 'loadavg',
        }
