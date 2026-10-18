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
        "group": (
            "root:x:0:\n"
            "daemon:x:1:\n"
            "bin:x:2:\n"
            "sys:x:3:\n"
            "adm:x:4:user1\n"
            "sudo:x:27:user1\n"
            "user1:x:1001:\n"
        ),
        "hosts": (
            "127.0.0.1 localhost\n"
            "127.0.1.1 ubuntu\n"
            "\n"
            "# The following lines are desirable for IPv6 capable hosts\n"
            "::1     ip6-localhost ip6-loopback\n"
            "fe00::0 ip6-localnet\n"
            "ff00::0 ip6-mcastprefix\n"
            "ff02::1 ip6-allnodes\n"
            "ff02::2 ip6-allrouters\n"
        ),
        "resolv.conf": (
            "# Dynamic resolv.conf(5) file for glibc resolver(3)\n"
            "nameserver 127.0.0.53\n"
            "options edns0 trust-ad\n"
            "search localdomain\n"
        ),
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
    "proc": {
        # Static fabricated values, identical for every session (deep-copied
        # from _DEFAULT_FS). Q3 resolution: static content cannot disagree
        # across successive reads, so no per-session random is needed. The
        # serial is X-redacted style with the variable digits fixed.
        "cpuinfo": (
            "processor\t: 0\n"
            "vendor_id\t: GenuineIntel\n"
            "cpu family\t: 6\n"
            "model\t\t: 142\n"
            "model name\t: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz\n"
            "stepping\t: 10\n"
            "microcode\t: 0xffffffff\n"
            "cpu MHz\t\t: 1992.000\n"
            "cache size\t: 8192 KB\n"
            "physical id\t: 0\n"
            "siblings\t: 1\n"
            "core id\t\t: 0\n"
            "cpu cores\t: 1\n"
            "apicid\t\t: 0\n"
            "initial apicid\t: 0\n"
            "fpu\t\t: yes\n"
            "fpu_exception\t: yes\n"
            "cpuid level\t: 22\n"
            "wp\t\t: yes\n"
            "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr "
            "pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall "
            "nx pdpe1gb rdtscp lm constant_tsc arch_perfmon nopl xtopology "
            "tsc_reliable nonstop_tsc cpuid pni pclmulqdq ssse3 cx16 pcid "
            "sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx rdrand "
            "hypervisor lahf_lm abm invpcid_single pti fsgsbase avx2 invpcid "
            "rdseed clflushopt md_clear flush_l1d arch_capabilities\n"
            "bugs\t\t: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass "
            "l1tf mds swapgs itlb_multihit\n"
            "bogomips\t: 3984.00\n"
            "clflush size\t: 64\n"
            "cache_alignment\t: 64\n"
            "address sizes\t: 39 bits physical, 48 bits virtual\n"
            "power management:\n"
            "\n"
            "serial\t\t: SNXXXX20220415\n"
        ),
        # MemTotal (kB) matches the `free` handler output (7964156 KiB).
        "meminfo": (
            "MemTotal:        7964156 kB\n"
            "MemFree:         5416200 kB\n"
            "MemAvailable:    6703124 kB\n"
            "Buffers:           42318 kB\n"
            "Cached:          1450152 kB\n"
            "SwapCached:            0 kB\n"
            "Active:           927544 kB\n"
            "Inactive:        1082304 kB\n"
            "SwapTotal:             0 kB\n"
            "SwapFree:              0 kB\n"
        ),
        # Matches the uname handler parts below.
        "version": (
            "Linux version 5.15.0-50-generic (buildd@lcy02-amd64-007) "
            "(gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0, GNU ld "
            "(GNU Binutils for Ubuntu) 2.34) #56~20.04 SMP "
            "Tue Sep 20 13:23:26 UTC 2022\n"
        ),
        # Matches the `uptime` handler output.
        "uptime": "364320.00 1440000.00\n",
        "loadavg": "0.08 0.03 0.01 1/187 1234\n",
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
