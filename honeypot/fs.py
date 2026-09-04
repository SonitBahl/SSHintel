"""In-memory fake filesystem for SSHintel.

Each SSH session receives its own independent fake filesystem so that attacker
interactions are fully isolated and never touch the real host machine. Every
function here operates purely on Python dicts/strings held in memory.

The path handling is intentionally simple and inherited from the original
prototype: paths are looked up against the in-memory tree, so there is no way
for a path to escape into the real host filesystem.
"""

import copy

# The initial structure every new session's filesystem is copied from. Each
# session gets a deep copy, so nested dicts are never shared between sessions.
# Files are represented as strings; directories as dicts.
_DEFAULT_FS = {
    "bin": {
        "bash": "", "cat": "", "chmod": "", "cp": "", "curl": "", "date": "",
        "df": "", "echo": "", "find": "", "free": "", "grep": "", "head": "",
        "hostname": "", "id": "", "ls": "", "mkdir": "", "mv": "", "ps": "",
        "pwd": "", "rm": "", "scp": "", "ssh": "", "stat": "", "tail": "",
        "touch": "", "tree": "", "uname": "", "uptime": "", "wc": "",
        "wget": "", "which": "",
    },
    "etc": {
        "passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "user1:x:1001:1001::::/home/user1:/bin/bash\n"
        ),
        "hostname": "ubuntu",
        "os-release": (
            'NAME="Ubuntu"\n'
            'VERSION="22.04 LTS (Jammy Jellyfish)"\n'
            'ID=ubuntu\n'
            'ID_LIKE=debian\n'
            'VERSION_ID="22.04"\n'
        ),
        "shadow": (
            "root:!:19000:0:99999:7:::\n"
            "user1:*:19000:0:99999:7:::\n"
        ),
    },
    "home": {
        "user1": {
            "notes.txt": "This is a test file.",
            "script.sh": "#!/bin/bash\necho Hello World",
            ".bashrc": "export PS1='\\u@\\h:\\w$ '\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n",
            ".bash_history": "ls\ncd /etc\ncat /etc/passwd\nsudo whoami\n",
            "Documents": {},
            "Downloads": {},
        }
    },
    "root": {},
    "tmp": {
        "readme.txt": "temporary file, safe to delete",
    },
    "usr": {
        "bin": {},
    },
    "var": {
        "log": {
            "syslog": (
                "Sep  3 09:40:01 ubuntu systemd[1]: Started Session 4 of user user1.\n"
                "Sep  3 09:40:02 ubuntu systemd[1]: Starting Daily apt download activities...\n"
            ),
            "auth.log": (
                "Sep  3 09:35:11 ubuntu sshd[1234]: Failed password for invalid user root from 10.10.10.10 port 50231 ssh2\n"
                "Sep  3 09:35:12 ubuntu sshd[1234]: Failed password for invalid user admin from 10.10.10.10 port 50232 ssh2\n"
            ),
        },
        "tmp": {},
    },
}


def create_filesystem():
    """Return a fresh, independent copy of the initial fake filesystem.

    ``copy.deepcopy`` guarantees every session gets its own nested mutable
    state rather than sharing references with other sessions.
    """
    return copy.deepcopy(_DEFAULT_FS)


def normalize_path(path):
    """Normalize an absolute path, resolving ``.`` and ``..`` segments."""
    parts = []
    for seg in str(path).split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
        else:
            parts.append(seg)
    return "/" + "/".join(parts)


def resolve_path(cwd, target):
    """Resolve a (possibly relative) target against the given working directory."""
    if target.startswith("/"):
        return target
    return cwd.rstrip("/") + "/" + target


def resolve_abs(cwd, target):
    """Resolve ``target`` against ``cwd`` and normalize the result."""
    if target.startswith("/"):
        base = target
    else:
        base = cwd.rstrip("/") + "/" + target
    return normalize_path(base)


def split_path(path):
    """Return ``(parent_path, basename)`` for an absolute path.

    Example: ``/tmp/x.txt`` -> ``('/tmp', 'x.txt')``; ``/`` -> ``('/', '')``.
    """
    path = normalize_path(path)
    if path == "/":
        return "/", ""
    parent, _, base = path.rpartition("/")
    return parent or "/", base


def get_dir(path, filesystem):
    """Walk ``filesystem`` (a dict tree) following the absolute ``path``.

    Returns the found node (dict/str) or ``None`` if any segment is missing.
    """
    parts = [p for p in path.strip("/").split("/") if p]
    cur = filesystem
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur
