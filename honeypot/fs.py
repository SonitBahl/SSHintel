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
_DEFAULT_FS = {
    "home": {
        "user1": {
            "notes.txt": "This is a test file.",
            "script.sh": "#!/bin/bash\necho Hello World",
            "Documents": {},
            "Downloads": {},
        }
    }
}


def create_filesystem():
    """Return a fresh, independent copy of the initial fake filesystem.

    ``copy.deepcopy`` guarantees every session gets its own nested mutable
    state rather than sharing references with other sessions.
    """
    return copy.deepcopy(_DEFAULT_FS)


def resolve_path(cwd, target):
    """Resolve a (possibly relative) target against the given working directory."""
    if target.startswith("/"):
        return target
    return cwd.rstrip("/") + "/" + target


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