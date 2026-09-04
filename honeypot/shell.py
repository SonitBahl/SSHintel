"""Fake, fully-simulated Linux shell for SSHintel.

This module provides the command interpreter for the honeypot. It is a
maintainable alternative to a single giant conditional chain: commands are
registered in a dict (``COMMAND_REGISTRY``) mapping a command name to a small
handler function. Each handler is responsible only for its own behavior.

Nothing here touches the real host: there is no ``os``, no ``subprocess``, no
network access, and no host filesystem access. Every command operates on the
per-session in-memory fake filesystem owned by ``Session``.
"""

import fnmatch
import re
import shlex
import time

from .fs import get_dir, resolve_abs, split_path

# Commands that a honeypot explicitly simulates as suspicious/intent telemetry.
# They perform no real action (no network, no exec, no host permission change);
# the full command line including arguments is recorded via the standard
# structured ``command`` telemetry for every command, so these are covered.
HOME = "/home/user1"
HOSTNAME = "ubuntu"
UNAME = "Linux ubuntu 5.15.0-50-generic #56~20.04 SMP x86_64 GNU/Linux"


def _flag_tokens(tokens):
    """Return (flags, positionals) for a token list.

    A token is a flag if it starts with ``-`` and is longer than one character.
    A bare ``-`` (stdin marker etc.) counts as a positional.
    """
    flags = [t for t in tokens if t.startswith("-") and len(t) > 1]
    positionals = [t for t in tokens if not (t.startswith("-") and len(t) > 1)]
    return flags, positionals


def _node(shell, path):
    """Return the fake-filesystem node at the absolute ``path`` or None."""
    return get_dir(path, shell.session.fake_filesystem)


def _read_file(shell, target):
    """Return file content string at ``target``, or a simulated error message."""
    node = _node(shell, shell._resolve(target))
    if node is None:
        return f"cat: {target}: No such file or directory"
    if isinstance(node, dict):
        return f"cat: {target}: Is a directory"
    return node


def _format_ls_long(shell, abs_path, entries):
    """Produce a believable ``ls -l`` listing for the given directory entries."""
    lines = [f"total {len(entries) * 4}"]
    for name in entries:
        if abs_path == "/":
            node = _node(shell, "/" + name)
        else:
            node = _node(shell, abs_path.rstrip("/") + "/" + name)
        if isinstance(node, dict):
            perm, size = "drwxr-xr-x", 4096
        else:
            perm, size = "-rw-r--r--", max(len(node), 1)
        lines.append(f"{perm} 1 user1 user1 {size:>9} Sep  3 09:41 {name}")
    return "\n".join(lines)
# --------------------------------------------------------------------------- #
# Filesystem / navigation commands
# --------------------------------------------------------------------------- #
def _cmd_pwd(shell, args):
    return shell.session.cwd


def _cmd_cd(shell, args):
    if not args:
        target = HOME
    else:
        target = args[0]
    new_path = shell._resolve(target)
    node = _node(shell, new_path)
    if node is None:
        return f"bash: cd: {target}: No such file or directory"
    if not isinstance(node, dict):
        return f"bash: cd: {target}: Not a directory"
    shell.session.cwd = new_path
    return ""


def _cmd_ls(shell, args):
    flags, positionals = _flag_tokens(args)
    all_flag = "a" in "".join(flags)
    long_flag = "l" in "".join(flags)
    target = positionals[-1] if positionals else "."
    abs_path = shell._resolve(target)
    node = _node(shell, abs_path)
    if node is None:
        return f"ls: cannot access '{target}': No such file or directory"
    if isinstance(node, str):
        return abs_path.rstrip("/").split("/")[-1]
    entries = [e for e in node.keys()]
    if not all_flag:
        entries = [e for e in entries if not e.startswith(".")]
    entries.sort()
    if long_flag:
        return _format_ls_long(shell, abs_path, entries)
    return "  ".join(entries)


def _cmd_mkdir(shell, args):
    flags, positionals = _flag_tokens(args)
    if not positionals:
        return "mkdir: missing operand\nTry 'mkdir --help' for more information."
    for target in positionals:
        abs_path = shell._resolve(target)
        parent, base = split_path(abs_path)
        node = _node(shell, parent)
        if node is None or not isinstance(node, dict):
            return f"mkdir: cannot create directory '{target}': No such file or directory"
        if base in node:
            return f"mkdir: cannot create directory '{target}': File exists"
        node[base] = {}
    return ""


def _cmd_touch(shell, args):
    flags, positionals = _flag_tokens(args)
    if not positionals:
        return "touch: missing file operand\nTry 'touch --help' for more information."
    for target in positionals:
        abs_path = shell._resolve(target)
        parent, base = split_path(abs_path)
        node = _node(shell, parent)
        if node is None or not isinstance(node, dict):
            return f"touch: cannot touch '{target}': No such file or directory"
        if base in node and isinstance(node[base], dict):
            return f"touch: cannot touch '{target}': Is a directory"
        node[base] = ""
    return ""


def _cmd_rm(shell, args):
    flags, positionals = _flag_tokens(args)
    force = "f" in "".join(flags)
    if not positionals:
        return "rm: missing operand\nTry 'rm --help' for more information."
    for target in positionals:
        abs_path = shell._resolve(target)
        parent, base = split_path(abs_path)
        node = _node(shell, parent)
        if node is None or not isinstance(node, dict) or base not in node:
            if not force:
                return f"rm: cannot remove '{target}': No such file or directory"
            continue
        del node[base]
    return ""


def _cmd_cat(shell, args):
    flags, positionals = _flag_tokens(args)
    if not positionals:
        return "cat: missing file operand"
    return "\n".join(_read_file(shell, t) for t in positionals)


def _cmd_echo(shell, args):
    redirect = None
    tokens = []
    newline = True
    i = 0
    while i < len(args):
        a = args[i]
        if a == ">":
            if i + 1 < len(args):
                redirect = args[i + 1]
                i += 2
                continue
            return "bash: syntax error near unexpected token `newline'"
        if a == "-n":
            newline = False
        elif a.startswith("-n") and len(a) > 2:
            newline = False
            tokens.append(a[2:])
        else:
            tokens.append(a)
        i += 1
    msg = " ".join(tokens)
    if redirect:
        abs_path = shell._resolve(redirect)
        parent, base = split_path(abs_path)
        node = _node(shell, parent)
        if node is None or not isinstance(node, dict):
            return f"bash: {redirect}: No such file or directory"
        if base in node and isinstance(node[base], dict):
            return f"bash: {redirect}: Is a directory"
        node[base] = msg
        return ""
    return msg if not newline else msg
def _cmd_tree(shell, args):
    flags, positionals = _flag_tokens(args)
    target = positionals[-1] if positionals else "."
    root = shell._resolve(target)
    node = _node(shell, root)
    if node is None:
        return f"tree: {target}: No such file or directory"
    if isinstance(node, str):
        return root

    lines = [root if root != "/" else "/"]
    count_dirs = [0]
    count_files = [0]

    def walk(path, prefix):
        n = _node(shell, path) or {}
        children = sorted(n.keys())
        children = [c for c in children if not c.startswith(".")]
        for i, name in enumerate(children):
            last = i == len(children) - 1
            branch = "`-- " if last else "|-- "
            connect = "    " if last else "|   "
            lines.append(prefix + branch + name)
            child_path = path.rstrip("/") + "/" + name
            child = _node(shell, child_path)
            if isinstance(child, dict):
                count_dirs[0] += 1
                walk(child_path, prefix + connect)
            else:
                count_files[0] += 1

    walk(root, "")
    lines.append("")
    lines.append(f"{count_dirs[0]} directories, {count_files[0]} files")
    return "\n".join(lines)


def _cmd_find(shell, args):
    positions = []
    name_filter = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-name" and i + 1 < len(args):
            name_filter = args[i + 1]
            i += 2
            continue
        if not a.startswith("-"):
            positions.append(a)
        i += 1
    target = positions[0] if positions else "."
    root = shell._resolve(target)
    node = _node(shell, root)
    if node is None:
        return f"find: '{target}': No such file or directory"

    lines = [root]
    def walk(path, n):
        if isinstance(n, dict):
            for name in sorted(n.keys()):
                child_path = path.rstrip("/") + "/" + name
                child = _node(shell, child_path)
                if name_filter is None or fnmatch.fnmatch(name, name_filter):
                    lines.append(child_path)
                if isinstance(child, dict):
                    walk(child_path, child)
    walk(root, node)
    return "\n".join(lines)


def _head_tail(shell, args, head=True):
    n = 10
    files = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-n" and i + 1 < len(args):
            try:
                n = int(args[i + 1])
                i += 2
                continue
            except ValueError:
                return f"head/tail: invalid number: '{args[i + 1]}'"
        if a.startswith("-n") and len(a) > 2:
            try:
                n = int(a[2:])
                i += 1
                continue
            except ValueError:
                return f"head/tail: invalid number: '{a[2:]}'"
        # Support the common short form: head -3 FILE == head -n 3 FILE.
        if a.startswith("-") and len(a) > 1 and a[1:].isdigit():
            n = int(a[1:])
            i += 1
            continue
        files.append(a)
        i += 1
    if not files:
        return "usage: --help"
    out = []
    for f in files:
        content = _read_file(shell, f)
        if content.startswith("cat: "):
            out.append(content)
            continue
        lines = content.splitlines()
        if head:
            out.extend(lines[:n])
        else:
            out.extend(lines[-n:])
    return "\n".join(out)


def _cmd_head(shell, args):
    return _head_tail(shell, args, head=True)


def _cmd_tail(shell, args):
    return _head_tail(shell, args, head=False)
def _cmd_grep(shell, args):
    flags, positionals = _flag_tokens(args)
    ignore_case = "i" in "".join(flags)
    if not positionals:
        return "Usage: grep [OPTIONS] PATTERN [FILE...]"
    pattern = positionals[0]
    files = positionals[1:]
    try:
        regex = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error as exc:
        return f"grep: Invalid regular expression: {exc}"
    out = []
    for f in files:
        content = _read_file(shell, f)
        if content.startswith("cat: "):
            out.append(f"grep: {f}: No such file or directory")
            continue
        for line in content.splitlines():
            if regex.search(line):
                if len(files) > 1:
                    out.append(f"{f}:{line}")
                else:
                    out.append(line)
    if not out:
        return ""
    return "\n".join(out)


def _cmd_wc(shell, args):
    flags, positionals = _flag_tokens(args)
    want_l = "l" in "".join(flags)
    want_w = "w" in "".join(flags)
    want_c = "c" in "".join(flags)
    if not any((want_l, want_w, want_c)):
        want_l = want_w = want_c = True
    lines_out = []
    for f in positionals:
        content = _read_file(shell, f)
        if content.startswith("cat: "):
            lines_out.append(content)
            continue
        n_lines = content.count("\n") + (0 if content.endswith("\n") else 1)
        n_words = len(content.split())
        n_chars = len(content)
        counts = []
        if want_l:
            counts.append(f"{n_lines:7d}")
        if want_w:
            counts.append(f"{n_words:7d}")
        if want_c:
            counts.append(f"{n_chars:7d}")
        lines_out.append("".join(counts) + " " + f)
    return "\n".join(lines_out)


def _cmd_stat(shell, args):
    flags, positionals = _flag_tokens(args)
    if not positionals:
        return "stat: missing operand\nTry 'stat --help' for more information."
    target = positionals[-1]
    node = _node(shell, shell._resolve(target))
    if node is None:
        return f"stat: cannot stat '{target}': No such file or directory"
    if isinstance(node, dict):
        kind, size = "directory", 4096
    else:
        kind, size = "regular file", len(node)
    return (
        f"  File: {target}\n"
        f"  Size: {size}\tBlocks: 8\tIO Block: 4096\t{kind}\n"
        f"  Device: fd01h/64769d\tInode: 1234567\tLinks: 1\n"
        f"  Access: (0755/-rwxr-xr-x)\tUid: ( 1001/\tuser1)\tGid: ( 1001/\tuser1)\n"
        f"  Access: 2026-09-03 09:41:00.000000000 +0000\n"
        f"  Modify: 2026-09-03 09:41:00.000000000 +0000\n"
    )
# --------------------------------------------------------------------------- #
# Environment / system reconnaissance
# --------------------------------------------------------------------------- #
_DUMMY_ENV = (
    "SHELL=/bin/bash\n"
    "SESSION_MANAGER=local/ubuntu:@/tmp/.ICE-unix/1234\n"
    "QT_ACCESSIBILITY=1\n"
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
    "PWD=/home/user1\n"
    "LANG=C.UTF-8\n"
    "USER=user1\n"
    "HOME=/home/user1\n"
    "LOGNAME=user1\n"
)


def _cmd_env(shell, args):
    return _DUMMY_ENV


def _cmd_printenv(shell, args):
    if args:
        name = args[0].lstrip("$")
        table = dict(line.split("=", 1) for line in _DUMMY_ENV.strip().splitlines())
        return table.get(name, "")
    return _DUMMY_ENV


def _cmd_date(shell, args):
    return time.strftime("%a %b %d %H:%M:%S UTC %Y")


def _cmd_uptime(shell, args):
    return " 10:34:22 up 4 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01"


def _cmd_ps(shell, args):
    return (
        "  PID TTY          TIME CMD\n"
        " 1234 pts/0    00:00:00 bash\n"
        " 1240 pts/0    00:00:00 ps\n"
    )


def _cmd_df(shell, args):
    return (
        "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
        "udev             3959088       0   3959088   0% /dev\n"
        "tmpfs             799984    1344    798640   1% /run\n"
        "/dev/sda1      102535340 25461280  71703584  27% /\n"
        "tmpfs             3999912       0   3999912   0% /dev/shm\n"
    )


def _cmd_free(shell, args):
    return (
        "              total        used        free      shared  buff/cache   available\n"
        "Mem:         7964156      874552     5416200       16740     1673404     6703124\n"
        "Swap:          0           0           0\n"
    )


# --------------------------------------------------------------------------- #
# Identity / shell interaction
# --------------------------------------------------------------------------- #
def _cmd_whoami(shell, args):
    return "user1"


def _cmd_user(shell, args):
    return "user1"


def _cmd_hostname(shell, args):
    return HOSTNAME


def _cmd_uname(shell, args):
    flags = "".join(_flag_tokens(args)[0])
    if not flags:
        return "Linux"
    if flags == "a":
        return UNAME
    return UNAME


def _cmd_id(shell, args):
    return "uid=1001(user1) gid=1001(user1) groups=1001(user1),27(sudo)"


def _cmd_groups(shell, args):
    return "user1 sudo"


def _cmd_clear(shell, args):
    return "\033[2J\033[H"


def _cmd_history(shell, args):
    lines_out = []
    idx = 1
    for line in _DUMMY_HISTORY.splitlines():
        lines_out.append(f"{idx:5d}  {line}")
        idx += 1
    return "\n".join(lines_out)


_DUMMY_HISTORY = (
    "ls\n"
    "cd /etc\n"
    "cat /etc/passwd\n"
    "whoami\n"
    "sudo -l\n"
)


def _cmd_which(shell, args):
    if not args:
        return "which: no arguments"
    for prog in args:
        if prog in ("bash", "cat", "ls", "grep", "python3", "perl", "nc"):
            return f"/usr/bin/{prog}"
        if prog in ("sudo", "su"):
            return f"/usr/bin/{prog}"
    return ""


def _cmd_type(shell, args):
    if not args:
        return ""
    name = args[0]
    if name == "exit":
        return "exit is a shell builtin"
    if name == "cd":
        return "cd is a shell builtin"
    if name in COMMAND_REGISTRY:
        return f"{name} is {_which_path(name)}"
    return f"{name}: not found"


def _which_path(name):
    return f"/usr/bin/{name}"


def _cmd_help(shell, args):
    return (
        "These shell commands are defined internally.  Type `help' to see this list.\n"
        "  cd  echo  exit  pwd  ls  cat  grep  head  tail  tree  find  wc  stat\n"
        "  mkdir  touch  rm  whoami  id  hostname  uname  env  ps  df  free\n"
        "  date  uptime  history  which  type  chmod  chown  sudo  wget  curl  ssh  scp\n"
    )


def _cmd_exit(shell, args):
    return "__EXIT__"
# --------------------------------------------------------------------------- #
# Suspicious / common attacker commands (fully simulated)
# --------------------------------------------------------------------------- #
def _cmd_sudo(shell, args):
    # Simulated: no privilege escalation is performed on the real host.
    if not args:
        return "usage: sudo -h | -k | -K | -V\nusage: sudo -l [-AbTknSuv]\n"
    if args[0] in ("-l", "--list"):
        return "Matching Defaults entries for user1 on ubuntu:\n    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\nuser1 may run the following commands on ubuntu:\n    (ALL : ALL) ALL\n"
    if args[0] in ("-i", "--login"):
        return "root@ubuntu:~# "
    cmd = " ".join(args)
    if cmd in ("whoami", "id"):
        return "root"
    return f"[sudo] password for user1:\nuser1 is not in the sudoers file.  This incident will be reported."


def _cmd_chmod(shell, args):
    return ""


def _cmd_chown(shell, args):
    return ""


def _cmd_wget(shell, args):
    # No real download. Record the URL via telemetry; return a believable error.
    flags, positionals = _flag_tokens(args)
    url = next((a for a in args if "://" in a or a.startswith("http")), None)
    if url:
        return f"Connecting to host...\nwget: unable to resolve host address"
    return "wget: missing URL\nUsage: wget [OPTION]... [URL]..."


def _cmd_curl(shell, args):
    url = next((a for a in args if "://" in a or a.startswith("http")), None)
    if url:
        return f"curl: (6) Could not resolve host"
    return "curl: try 'curl --help' or 'curl --manual' for more information"


def _cmd_ssh(shell, args):
    # Simulated: no connection is made.
    target = next((a for a in args if not a.startswith("-") and "@" in a), None)
    if not target:
        return "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]\n"
    host = target.rsplit("@", 1)[-1]
    return f"ssh: connect to host {host} port 22: Connection refused"


def _cmd_scp(shell, args):
    target = next((a for a in args if not a.startswith("-") and "@" in a), None)
    if not target:
        return "usage: scp [-346BCpqrTv] [-c cipher] [-F ssh_config] [-i identity_file]\n"
    host = target.rsplit("@", 1)[-1]
    return f"ssh: connect to host {host} port 22: Connection refused"


# --------------------------------------------------------------------------- #
# Command registry
# --------------------------------------------------------------------------- #
COMMAND_REGISTRY = {
    "pwd": _cmd_pwd,
    "cd": _cmd_cd,
    "ls": _cmd_ls,
    "mkdir": _cmd_mkdir,
    "touch": _cmd_touch,
    "rm": _cmd_rm,
    "cat": _cmd_cat,
    "echo": _cmd_echo,
    "tree": _cmd_tree,
    "find": _cmd_find,
    "head": _cmd_head,
    "tail": _cmd_tail,
    "grep": _cmd_grep,
    "wc": _cmd_wc,
    "stat": _cmd_stat,
    "env": _cmd_env,
    "printenv": _cmd_printenv,
    "date": _cmd_date,
    "uptime": _cmd_uptime,
    "ps": _cmd_ps,
    "df": _cmd_df,
    "free": _cmd_free,
    "whoami": _cmd_whoami,
    "user": _cmd_user,
    "hostname": _cmd_hostname,
    "uname": _cmd_uname,
    "id": _cmd_id,
    "groups": _cmd_groups,
    "clear": _cmd_clear,
    "history": _cmd_history,
    "which": _cmd_which,
    "type": _cmd_type,
    "help": _cmd_help,
    "exit": _cmd_exit,
    "sudo": _cmd_sudo,
    "chmod": _cmd_chmod,
    "chown": _cmd_chown,
    "wget": _cmd_wget,
    "curl": _cmd_curl,
    "ssh": _cmd_ssh,
    "scp": _cmd_scp,
}


class FakeShell:
    """A per-session command interpreter backed by a fake filesystem.

    ``Session`` owns a ``FakeShell``. This keeps all shell state (cwd,
    filesystem) tied to one connection: nothing is module-global, so concurrent
    sessions are fully isolated.
    """

    def __init__(self, session):
        self.session = session
        self._commands = dict(COMMAND_REGISTRY)
        self.exited = False

    def _resolve(self, target):
        """Resolve a (possibly relative) path against the session cwd."""
        return resolve_abs(self.session.cwd, target)

    def execute(self, line):
        """Parse and run one command line. Returns output string ('' ok).

        Never raises on malformed input; malformed commands produce a simulated
        shell error instead.
        """
        line = line.strip()
        if not line:
            return ""
        try:
            tokens = shlex.split(line)
        except ValueError:
            return "bash: syntax error near unexpected token `newline'"
        if not tokens:
            return ""
        name = tokens[0]
        args = tokens[1:]

        if ">" in args:
            # A redirect as its own token is only meaningful to echo; treat any
            # other use as a shell error. echo handles ">" itself.
            idx = args.index(">")
            if name != "echo":
                if idx + 1 < len(args):
                    return f"bash: {name}: cannot create {args[idx + 1]}: No such file or directory"
                return f"bash: syntax error near unexpected token `newline'"

        handler = self._commands.get(name)
        if handler is None:
            return f"bash: {name}: command not found"

        result = handler(self, args)
        if result is None:
            result = ""
        if result == "__EXIT__":
            self.exited = True
            return ""
        return result
