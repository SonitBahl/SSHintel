"""Dependency-free sensor configuration (CLI > environment > file > defaults)."""

import json
import os
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.8-3.10 use the JSON configuration format.
    tomllib = None


DEFAULTS = {
    "host": "0.0.0.0",
    "port": 2222,
    "username": "user1",
    "password": "pass123",
    "tarpit": False,
    "tarpit_max_seconds": 120,
    "max_connections": 50,
    "auth_timeout": 60,
    "session_idle_timeout": 300,
    "sensor_id": None,
    "db_path": None,
    "no_db": False,
    "fetch_payloads": False,
    "capture_keystrokes": True,
    "max_keystrokes": 5000,
    "max_line_length": 4096,
    "output_preview_chars": 500,
}


class ConfigError(ValueError):
    """Invalid operator configuration; safe to display without secret values."""


def _validate(key, value, environment=False):
    if key not in DEFAULTS:
        raise ConfigError("Unknown configuration key: {}".format(key))
    default = DEFAULTS[key]
    if isinstance(default, bool):
        if environment and isinstance(value, str):
            choices = {"true": True, "1": True, "yes": True, "on": True,
                       "false": False, "0": False, "no": False, "off": False}
            value = choices.get(value.lower().strip(), value)
        if type(value) is not bool:
            raise ConfigError("{} must be a boolean".format(key))
    elif isinstance(default, int):
        if environment and isinstance(value, str):
            try:
                value = int(value)
            except ValueError:
                raise ConfigError("{} must be an integer".format(key)) from None
        if type(value) is not int:
            raise ConfigError("{} must be an integer".format(key))
        if value <= 0 or (key == "port" and value > 65535):
            raise ConfigError("{} is outside its valid range".format(key))
    elif value is None and key in ("sensor_id", "db_path"):
        return value
    elif not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ConfigError("{} must be a non-empty string".format(key))
    return value


def _read_file(path):
    path = Path(path)
    if path.suffix.lower() not in (".json", ".toml"):
        raise ConfigError("Configuration must use a .json or .toml file")
    if path.suffix.lower() == ".toml" and tomllib is None:
        raise ConfigError("TOML requires Python 3.11+; use sshintel.json on Python 3.8-3.10")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise ConfigError("Cannot read configuration file: {}".format(path)) from None
    try:
        data = json.loads(text) if path.suffix.lower() == ".json" else tomllib.loads(text)
    except ValueError:
        # Parser exceptions can include the input (including credentials).
        raise ConfigError("Malformed configuration file: {}".format(path)) from None
    if not isinstance(data, dict):
        raise ConfigError("Configuration must be a flat mapping of settings")
    return {key: _validate(key, value) for key, value in data.items()}


def load_config(cli=None, environ=None, config_path=None):
    """Resolve serve settings, validating each supplied source before startup.

    Explicit files must exist. Otherwise discover sshintel.toml, then
    sshintel.json in the current directory. Relative paths remain cwd-relative.
    Environment settings use HONEYPOT_<UPPERCASE_KEY>; PORT is a legacy alias.
    """
    cli = {} if cli is None else cli
    environ = os.environ if environ is None else environ
    path = config_path if config_path is not None else environ.get("HONEYPOT_CONFIG")
    if path is None:
        path = next((name for name in ("sshintel.toml", "sshintel.json")
                     if Path(name).is_file()), None)
    settings = DEFAULTS.copy()
    if path is not None:
        settings.update(_read_file(path))
    for key in DEFAULTS:
        name = "HONEYPOT_" + key.upper()
        if name in environ:
            settings[key] = _validate(key, environ[name], environment=True)
        elif key == "port" and "PORT" in environ:
            settings[key] = _validate(key, environ["PORT"], environment=True)
    for key, value in cli.items():
        settings[key] = _validate(key, value)
    if settings["fetch_payloads"]:
        raise ConfigError("fetch_payloads is not implemented; it must remain false")
    return settings