"""Tests that verify the Dockerfile CMD invocation matches the current CLI.

These tests parse the exact `python run.py ...` command from the Dockerfile's CMD
instruction and assert it is well-formed for the CLI surface. They do NOT execute
the command — they only verify argument structure and compatibility.
"""

import re
import shlex
import pathlib

import run
from honeypot.config import load_config

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

    def test_cmd_parses_without_overriding_configuration(self):
        """Docker must let Python resolve env/file settings, not force CLI values."""
        args = _extract_cmd_args()
        parsed = run.build_parser().parse_args(args)
        assert vars(parsed) == {"command": "serve"}

    def test_cmd_db_path_uses_env(self):
        """The Docker database environment default is consumed by the loader."""
        text = DOCKERFILE.read_text()
        env = dict(re.findall(r"^ENV (\w+)=(.*)$", text, re.MULTILINE))
        settings = load_config(environ=env)
        assert settings["db_path"] == "/app/data/sshintel.db"

    def test_cmd_uses_exec(self):
        """The CMD should use 'exec' for proper PID 1 handling."""
        text = DOCKERFILE.read_text()
        assert "exec python run.py" in text

    def test_cmd_port_uses_env_var(self):
        """Legacy PORT still works, without shell expansion of credentials."""
        assert load_config(environ={"PORT": "3333"})["port"] == 3333
        assert "${HONEYPOT_PASSWORD}" not in DOCKERFILE.read_text()
