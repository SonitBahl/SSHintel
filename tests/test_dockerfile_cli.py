"""Tests that verify the Dockerfile CMD invocation matches the current CLI.

These tests parse the exact `python run.py ...` command from the Dockerfile's CMD
instruction and assert it is well-formed for the CLI surface. They do NOT execute
the command — they only verify argument structure and compatibility.
"""

import re
import shlex
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCKERFILE = REPO_ROOT / "Dockerfile"


def _extract_cmd_args():
    """Extract argv (after `python run.py`) from the Dockerfile CMD."""
    text = DOCKERFILE.read_text()
    match = re.search(r'CMD \["sh", "-c", "(.+)"\]', text)
    assert match, "Could not find CMD entry in Dockerfile"

    cmd_str = match.group(1).replace('\\"', '"')
    prefix = "python run.py "
    idx = cmd_str.index(prefix)
    args_str = cmd_str[idx + len(prefix):]
    return shlex.split(args_str)


class TestDockerfileCLICompatibility:
    """Ensure the Dockerfile CMD invokes run.py with valid CLI arguments."""

    def test_cmd_uses_serve_subcommand(self):
        """The Dockerfile must use the 'serve' subcommand, not bare flags."""
        args = _extract_cmd_args()
        assert args[0] == "serve"

    def test_cmd_args_contain_required_flags(self):
        """All expected CLI flags must be present in the Dockerfile CMD."""
        args = _extract_cmd_args()
        required = ["--host", "--port", "--username", "--password", "--sensor-id", "--db"]
        for flag in required:
            assert flag in args, f"Dockerfile CMD missing required flag: {flag}"

    def test_cmd_db_path_uses_env(self):
        """The Dockerfile should pass --db using ${HONEYPOT_DB_PATH}."""
        args = _extract_cmd_args()
        db_idx = args.index("--db")
        assert "HONEYPOT_DB_PATH" in args[db_idx + 1].upper()

    def test_cmd_uses_exec(self):
        """The CMD should use 'exec' for proper PID 1 handling."""
        text = DOCKERFILE.read_text()
        assert "exec python run.py" in text

    def test_cmd_port_uses_env_var(self):
        """The port argument should use the ${PORT} environment variable."""
        args = _extract_cmd_args()
        port_idx = args.index("--port")
        port_value = args[port_idx + 1]
        assert "${PORT}" in port_value, f"Expected --port to use ${{PORT}} env var, got: {port_value}"
