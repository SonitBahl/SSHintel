# SSHintel — Lightweight SSH Honeypot

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/Python-3.12%2B-blue)
![Last Commit](https://img.shields.io/github/last-commit/sonitbahl/SSHintel)
![Repo Size](https://img.shields.io/github/repo-size/sonitbahl/SSHintel)

&#x20; &#x20;

`SSHintel` is a lightweight SSH honeypot built using Python and Paramiko. It simulates a fake Linux shell to log unauthorized access attempts, capture credentials, and analyze attacker behavior in a controlled environment.

---

## 🔧 Features

- Logs SSH login attempts with IP, username, and password
- Emulates a minimal interactive Linux shell
- Supports basic commands (`ls`, `cd`, `pwd`, `cat`, `echo`, etc.)
- Optional `--tarpit` mode to slow down attackers with delayed output
- Fake filesystem with file creation and reading support

---

## 🛠️ Setup

### 1. 🔑 Generate SSH Host Key

```bash
ssh-keygen -t rsa -b 2048 -m PEM -f static/server.key
```

> This will generate a private key at `static/server.key`. **Do not set a passphrase.**

---

### 2. 📦 Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Running the Honeypot

Run the honeypot with a specific port, username, and password:

```bash
python run.py --port 2222 --username user1 --password pass123
```

> Default port is `2222` and host is `0.0.0.0`.

To enable tarpit mode:

```bash
python run.py --port 2222 --username user1 --password pass123 --tarpit
```

## 🛡️ Connection limits & timeouts

SSHintel guards against resource exhaustion from many concurrent connections or connections kept alive indefinitely. These are configurable via the CLI:

| Flag | Default | Purpose |
|---|---|---|
| `--max-connections` | `50` | Maximum simultaneous active connections; extra connections are rejected and logged as a `connection_rejected` event |
| `--auth-timeout` | `60` (s) | Time allowed to complete the SSH handshake/authentication; stalled clients are disconnected |
| `--session-idle-timeout` | `300` (s) | Inactivity timeout for an authenticated shell; an idle session is ended, but an actively-typing attacker is never killed |

Example:

```bash
python run.py --port 2222 --username user1 --password pass123 \
  --max-connections 25 --auth-timeout 30 --session-idle-timeout 300
```

When too many connections are open, the extra connection is closed immediately and a `connection_rejected` security event (with `reason: connection_limit`) is written to the JSONL log. A stalled authentication is recorded as a disconnect with `reason: auth_timeout`; an idle shell ends with `reason: idle_timeout`.

> Tarpit mode intentionally sends output slowly to keep an attacker engaged, so the tarpit banner loop is not subject to the inactivity timeout — but tarpit sessions *do* count against the connection limit.

---

## 🔐 Testing from Another Terminal

Open a second terminal and try connecting:

```bash
ssh user1@localhost -p 2222
```

If the credentials match, you’ll be dropped into the emulated shell.

---

## 🚑 Optional: Clear Known Hosts (If Reconnecting)

To remove stale SSH fingerprints:

```bash
notepad "%USERPROFILE%\.ssh\known_hosts"
```

> Delete the relevant line containing `localhost` or the honeypot's IP.

---

## 📝 Logged Information

- Credentials are logged to `creds_logger`
- Shell commands are logged via `funnel_logger`
- Structured security events are written to `log_files/events.jsonl` as **JSON Lines (JSONL)** — one valid JSON object per line

Each JSONL event includes a UTC ISO-8601 `timestamp`, an `event_type`, a unique `session_id`, and the `source_ip`. Connection, authentication attempts/results, command execution, tarpit activation, and disconnects are all recorded as structured events.

Each incoming SSH connection is tracked as an independent **session** with its own `session_id`. A session records the source IP, connect/disconnect times, the authentication outcome, and the connection duration, and every event generated within that connection carries the same `session_id` (so authentication attempts, commands, and disconnects can be tied back to a single connection). Sessions are isolated per connection — no state is shared between concurrent clients.

Every session also receives its **own isolated, in-memory fake filesystem** — the simulated filesystem is created fresh for each connection and cleaned up when the connection ends. Files, directories, and the working directory created or changed by one attacker are never visible to another attacker connected at the same time. The entire filesystem is simulated in Python memory and **never touches the real host filesystem**.

Current `event_type` values: `connect`, `auth_attempt`, `auth_success`, `auth_failure`, `command`, `disconnect`, `tarpit`.

You can extend `logger.py` to send logs to files, remote servers, or alerting systems.

---

## 📂 File Structure

```
SSHintel/
├── honeypot/                  # Core honeypot logic
│   ├── __init__.py
│   ├── main.py                # CLI entrypoint
│   ├── handlers.py            # Shell logic + tarpit
│   ├── server.py              # Paramiko-based server interface
│   ├── session.py             # Per-connection session tracking
│   ├── fs.py                  # In-memory fake filesystem (isolated per session)
│   ├── limits.py              # Thread-safe concurrent connection limiting
│   ├── logger.py              # Logging setup and methods
│   └── __pycache__/           # Compiled Python bytecode
│
├── log_files/                 # Logs for credentials, commands, and events
│   ├── creds_audits.log
│   ├── cmd_audits.log
│   └── events.jsonl           # Structured JSONL security events
│
├── static/                    # SSH key and dummy files
│   ├── server.key             # Private host key
│   ├── server.key.pub         # Public host key
│   └── notes.txt             
│
├── .gitignore
├── Dockerfile
├── README.md
├── requirements.txt           # Python dependencies
└── run.py                     # Script to launch honeypot
```

---

## 💪 Run with Docker (Alternative Method)

If you prefer to run the honeypot in a containerized environment, you can use the included Dockerfile.

### 🔨 Build the Docker Image

```bash
docker build -t sshintel .
```

> This creates a Docker image named `sshintel`.

---

### 🚀 Run the Container

```bash
docker run -p 2222:2222 sshintel
```

This will:

- Automatically generate the SSH private key at `static/server.key` (if it doesn't already exist)
- Launch the honeypot on port `2222` with default credentials:\
  `username: user1`, `password: pass123`

---

### 🔮 Test the Honeypot

Open a second terminal and connect via SSH:

```bash
ssh user1@localhost -p 2222
```

You’ll be dropped into the simulated shell if the credentials match.

---

### 🧼 Stop and Clean Up

To stop the container:

```bash
docker ps  # Find the container ID
docker stop <container_id>
```

To remove the image:

```bash
docker rmi sshintel
```

> You can also export the image using `docker save -o sshintel.tar sshintel` and load it later with `docker load -i sshintel.tar`.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 👤 Author

**Sonit Bahl**\
🔗 [LinkedIn](https://www.linkedin.com/in/sonitbahl)\
🔗 [Portfolio](https://sonitwebsite.vercel.app/)
