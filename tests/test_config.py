"""Configuration precedence, strict validation, and CLI startup wiring."""

import json
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

import run
from honeypot import config


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name in list(config.os.environ):
        if name.startswith("HONEYPOT_") or name == "PORT":
            monkeypatch.delenv(name)


def write_json(tmp_path, values):
    path = tmp_path / "sshintel.json"
    path.write_text(json.dumps(values), encoding="utf-8")
    return path


def test_defaults():
    assert config.load_config(environ={}) == config.DEFAULTS


def test_precedence(tmp_path):
    write_json(tmp_path, {"port": 3333, "username": "file-user", "host": "127.0.0.1"})
    env = {"HONEYPOT_PORT": "4444", "HONEYPOT_USERNAME": "env-user"}
    assert config.load_config(environ=env)["port"] == 4444
    settings = config.load_config({"port": 5555}, env)
    assert settings["port"] == 5555
    assert settings["username"] == "env-user"
    assert settings["host"] == "127.0.0.1"
    assert settings["auth_timeout"] == 60


@pytest.mark.parametrize("key", list(config.DEFAULTS))
def test_every_environment_setting(key):
    value = config.DEFAULTS[key]
    if isinstance(value, bool):
        value = False if key == "fetch_payloads" else True
        encoded = str(value).lower()
    elif isinstance(value, int):
        value += 1
        encoded = str(value)
    else:
        value = "configured-value"
        encoded = value
    settings = config.load_config(environ={"HONEYPOT_" + key.upper(): encoded})
    assert settings[key] == value


@pytest.mark.parametrize("text,expected", [("true", True), ("1", True), ("YES", True),
                                          ("on", True), ("false", False), ("0", False),
                                          ("NO", False), ("off", False)])
def test_environment_booleans(text, expected):
    assert config.load_config(environ={"HONEYPOT_TARPIT": text})["tarpit"] is expected


def test_legacy_port_alias():
    assert config.load_config(environ={"PORT": "3333"})["port"] == 3333
    assert config.load_config(environ={"PORT": "3333", "HONEYPOT_PORT": "4444"})["port"] == 4444


def test_explicit_file_overrides_environment_file(tmp_path):
    first = write_json(tmp_path, {"port": 3333})
    second = tmp_path / "other.json"
    second.write_text('{"port": 4444}')
    assert config.load_config(environ={"HONEYPOT_CONFIG": str(first)})["port"] == 3333
    settings = config.load_config(environ={"HONEYPOT_CONFIG": str(first)}, config_path=second)
    assert settings["port"] == 4444


@pytest.mark.parametrize("content", ["{", "[]", '{"password": "SECRET", broken}',
                                    '{"port": NaN}'])
def test_malformed_json(tmp_path, content):
    path = tmp_path / "sshintel.json"
    path.write_text(content)
    with pytest.raises(config.ConfigError) as exc:
        config.load_config(environ={})
    assert "SECRET" not in str(exc.value)


@pytest.mark.parametrize("key,value", [
    ("port", 0), ("port", 65536), ("port", True), ("port", 2.5), ("port", "2222"),
    ("max_connections", -1), ("auth_timeout", 0), ("session_idle_timeout", 0),
    ("tarpit_max_seconds", 0), ("tarpit", "false"), ("no_db", 1),
    ("host", ""), ("username", []), ("password", ""), ("password", "bad\x00value"),
    ("sensor_id", 12), ("db_path", ""), ("unknown_option", "SECRET"),
])
def test_invalid_file_settings(tmp_path, key, value):
    write_json(tmp_path, {key: value})
    with pytest.raises(config.ConfigError):
        config.load_config(environ={})


@pytest.mark.parametrize("key,value", [("PORT", "invalid"), ("HONEYPOT_PORT", "3.5"),
                                      ("HONEYPOT_TARPIT", "maybe"),
                                      ("HONEYPOT_AUTH_TIMEOUT", "-1")])
def test_invalid_environment(key, value):
    with pytest.raises(config.ConfigError):
        config.load_config(environ={key: value})


def test_missing_explicit_file_and_unsupported_extension(tmp_path):
    for path in (tmp_path / "missing.json", tmp_path / "settings.yaml"):
        with pytest.raises(config.ConfigError):
            config.load_config(environ={}, config_path=path)


def test_toml_on_older_python_has_actionable_error(tmp_path, monkeypatch):
    (tmp_path / "sshintel.toml").write_text("port = 3333")
    monkeypatch.setattr(config, "tomllib", None)
    with pytest.raises(config.ConfigError, match="use sshintel.json"):
        config.load_config(environ={})


@pytest.mark.skipif(config.tomllib is None, reason="stdlib TOML requires Python 3.11+")
def test_toml_and_discovery_priority(tmp_path):
    write_json(tmp_path, {"port": 4444})
    path = tmp_path / "sshintel.toml"
    path.write_text('port = 3333\ntarpit = true\npassword = "with spaces $;"')
    settings = config.load_config(environ={})
    assert settings["port"] == 3333
    assert settings["tarpit"] is True
    assert settings["password"] == "with spaces $;"
    path.write_text('password = "SECRET"\nport = [broken')
    with pytest.raises(config.ConfigError) as exc:
        config.load_config(environ={})
    assert "SECRET" not in str(exc.value)


def test_examples_are_valid(tmp_path):
    root = Path(__file__).resolve().parents[1]
    for extension in ("json", "toml"):
        if extension == "toml" and config.tomllib is None:
            continue
        path = tmp_path / ("example." + extension)
        path.write_text((root / ("sshintel." + extension + ".example")).read_text())
        settings = config.load_config(environ={}, config_path=path)
        assert settings["port"] == 2222
        assert settings["fetch_payloads"] is False


def test_payload_fetching_cannot_silently_enable():
    with pytest.raises(config.ConfigError, match="not implemented"):
        config.load_config(environ={"HONEYPOT_FETCH_PAYLOADS": "true"})


def test_parser_only_supplies_explicit_values():
    parser = run.build_parser()
    assert vars(parser.parse_args(["serve"])) == {"command": "serve"}
    values = vars(parser.parse_args(["serve", "--no-tarpit", "--db-enabled", "--no-fetch-payloads"]))
    assert values == {"command": "serve", "tarpit": False, "no_db": False, "fetch_payloads": False}


def test_cli_wires_resolved_settings(tmp_path, monkeypatch):
    path = write_json(tmp_path, {"port": 3333, "tarpit": True, "no_db": True,
                                 "db_path": "custom.db", "sensor_id": "from-file"})
    monkeypatch.setenv("HONEYPOT_PORT", "4444")
    monkeypatch.setenv("HONEYPOT_PASSWORD", "password with spaces;$()")
    store = Mock(db_path="custom.db")
    get_store = Mock(return_value=store)
    sensor = Mock()
    server = Mock()
    monkeypatch.setattr(run, "_get_store", get_store)
    monkeypatch.setattr(run, "set_telemetry_store", Mock())
    monkeypatch.setattr(run, "set_sensor_id", sensor)
    monkeypatch.setattr(run, "honeypot", server)
    run.main(["serve", "--config", str(path), "--port", "5555", "--no-tarpit", "--db-enabled"])
    get_store.assert_called_once_with("custom.db", False)
    sensor.assert_called_once_with("from-file")
    server.assert_called_once_with(
        address="0.0.0.0", port=5555, username="user1", password="password with spaces;$()",
        tarpit=False, max_connections=50, auth_timeout=60, session_idle_timeout=300,
        tarpit_max_seconds=120, telemetry_db="custom.db",
    )
    store.open.assert_called_once_with()
    store.close.assert_called_once_with()


def test_cli_invalid_config_fails_before_store(tmp_path, monkeypatch, capsys):
    write_json(tmp_path, {"password": ["SECRET"]})
    get_store = Mock()
    monkeypatch.setattr(run, "_get_store", get_store)
    with pytest.raises(SystemExit) as exc:
        run.main(["serve"])
    assert exc.value.code == 2
    get_store.assert_not_called()
    assert "SECRET" not in capsys.readouterr().err


def test_cli_closes_store_on_server_error(monkeypatch):
    store = Mock(db_path=None)
    monkeypatch.setattr(run, "_get_store", Mock(return_value=store))
    monkeypatch.setattr(run, "set_telemetry_store", Mock())
    monkeypatch.setattr(run, "set_sensor_id", Mock())
    monkeypatch.setattr(run, "honeypot", Mock(side_effect=RuntimeError("server failed")))
    with pytest.raises(RuntimeError, match="server failed"):
        run.main(["serve", "--no-db"])
    store.close.assert_called_once_with()


def test_query_commands_do_not_read_sensor_config(tmp_path, monkeypatch):
    (tmp_path / "sshintel.json").write_text("invalid")
    store = Mock()
    monkeypatch.setattr(run, "_get_store", Mock(return_value=store))
    stats = Mock()
    monkeypatch.setattr(run, "cmd_stats", stats)
    run.main(["stats"])
    stats.assert_called_once_with(store)


@pytest.mark.parametrize("extension", ["json", "toml"])
def test_live_sensor_from_config_file(tmp_path, extension):
    """A real CLI process accepts SSH credentials from the example config."""
    if extension == "toml" and config.tomllib is None:
        pytest.skip("stdlib TOML requires Python 3.11+")
    import paramiko

    root = Path(__file__).resolve().parents[1]
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    database = tmp_path / "live.db"
    values = json.loads((root / "sshintel.json.example").read_text())
    values.update(host="127.0.0.1", port=port, username="config-user",
                  password="config password;$", db_path=str(database))
    path = tmp_path / ("sshintel." + extension)
    if extension == "json":
        path.write_text(json.dumps(values))
    else:
        # This flat schema uses the same scalar literals in JSON and TOML.
        path.write_text("\n".join("{} = {}".format(key, json.dumps(value))
                                  for key, value in values.items()))
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    with (tmp_path / "server.log").open("w+") as output:
        process = subprocess.Popen([sys.executable, str(root / "run.py"), "serve"],
                                   cwd=str(tmp_path), stdout=output, stderr=output)
        try:
            deadline = time.monotonic() + 10
            while True:
                assert process.poll() is None, "Configured sensor exited before accepting SSH"
                try:
                    client.connect("127.0.0.1", port=port, username=values["username"],
                                   password=values["password"], timeout=1,
                                   allow_agent=False, look_for_keys=False)
                    break
                except (OSError, paramiko.SSHException):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)
            channel = client.invoke_shell()
            channel.settimeout(3)
            assert channel.recv(4096)
            channel.send("exit\n")
            channel.close()
            client.close()
            deadline = time.monotonic() + 5
            while True:
                with sqlite3.connect(str(database)) as connection:
                    count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                if count:
                    break
                assert time.monotonic() < deadline, "No telemetry persisted"
                time.sleep(0.1)
        finally:
            client.close()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)