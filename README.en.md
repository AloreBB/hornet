# <img src="https://raw.githubusercontent.com/AloreBB/hornet/main/static/hornet-head.png" width="40" alt="Hornet" style="vertical-align: middle" /> Hornet

[🇪🇸 Español](README.md)

> *Hornet watches. Hallownest will not fall.*

Lightweight Linux server security monitor. Runs every 15 minutes, detects threats, and sends alerts to Telegram or via push with [ntfy](https://ntfy.sh).

## What it detects

| Check | What triggers an alert |
|-------|----------------------|
| 🔌 Exposed DB ports | PostgreSQL, MySQL, MongoDB, Redis open to `0.0.0.0` |
| 🦠 Shady processes | Executables running from `/tmp`, `/dev/shm`, `/var/tmp` |
| 🐳 Container infection | Suspicious binaries inside container `/tmp` |
| 🔥 CPU spike | Processes consuming >150% CPU for >1 minute |
| 💾 RAM / Disk | Usage above configurable thresholds |
| 🛡️ fail2ban down | Detects if brute-force protection goes offline |
| 🔄 Container health | Restart loops and dead containers |
| ⏰ Crontab changes | New or modified cron jobs (persistence detection) |
| 👤 New users / SSH keys | Backdoor detection |
| 📡 Mining pool connections | Outbound traffic to crypto mining ports |
| 🚪 New open ports | Ports not present in your baseline |
| 🔐 Suspicious SUID binaries | Privilege escalation detection |

## Requirements

- `bash`, `jq`, `docker`
- [`gum`](https://github.com/charmbracelet/gum) — installed automatically by `install.sh`
- A Telegram bot (recommended primary channel) or a [ntfy](https://ntfy.sh) server (free public instance or self-hosted)

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/AloreBB/hornet/main/install.sh | bash
```

> **Note:** the installer may ask for your `sudo` password to install `jq` and `gum` into `/usr/local/bin`. If they are already installed, no password will be required. Everything else (copying Hornet, setting up PATH) happens in your home directory without elevated permissions.

The installer:
1. Installs `jq` and `gum` if missing *(requires sudo)*
2. Copies Hornet to `~/.hornet/`
3. Adds `hornet` to your `PATH`
4. Launches the interactive setup wizard

## Setup

```bash
hornet init     # create config.json from scratch
hornet setup    # interactive wizard (Telegram, ntfy, whitelists)
```

The repo already includes `config.json` with placeholder values. Just edit it with your own data:

```bash
hornet setup    # recommended: interactive wizard
# or edit config.json directly
```

Tokens are stored in `~/.config/hornet/credentials` (auto-created by `hornet setup`, outside the repo):

```bash
TELEGRAM_BOT_TOKEN=...   # Telegram bot token
NTFY_TOKEN=...           # ntfy token (only if your server requires one)
```

You can also export `TELEGRAM_BOT_TOKEN` or `NTFY_TOKEN` in your shell session and Hornet will pick them up directly.

## Notifications

Hornet can alert via **Telegram** (primary channel) and/or **ntfy**. If you configure both, every alert goes to both.

**Telegram:**

1. Create a bot with [@BotFather](https://t.me/BotFather) (send it `/newbot`) and copy the token.
2. Send any message to your bot (so Hornet can find your chat).
3. Run `hornet setup` → *Notifications — Telegram*: paste the token, the wizard auto-detects your chat ID.
4. Verify with `hornet test` — if you read the test, alerts reach their destination.

The chat ID lives in `config.json` → `notifications.telegram_chat_id` and the token in `~/.config/hornet/credentials`.

**ntfy:** `hornet setup` → *Notifications — ntfy*. No server or topic is configured by default: if you use the public ntfy.sh instance, pick a topic nobody can guess, because anyone who knows it can read your alerts.

## Updating

```bash
hornet update
```

Compares your local version against the latest on GitHub and downloads the new files if an update is available. Your `config.json` and token are never touched.

## Usage

```bash
# Run a scan now
hornet run

# View recent scan history
hornet status

# Send a test notification
hornet test

# Manage whitelists (interactive)
hornet whitelist

# Manage whitelists (direct commands)
hornet whitelist list
hornet whitelist add port 25565        # Minecraft server
hornet whitelist add process java      # JVM apps
hornet whitelist add container myapp   # Skip /tmp check for a container
hornet whitelist add ext dylib         # Additional safe extension

hornet whitelist remove port 8080

# Uninstall
hornet uninstall
```

## `config.json` structure

```json
{
  "notifications": {
    "telegram_chat_id": "123456789",
    "url": "https://ntfy.sh",
    "topic": "my-alerts",
    "icon": ""
  },
  "baseline": {
    "users": ["root:/bin/bash", "myuser:/bin/bash"],
    "ssh_keys": ["/home/myuser/.ssh/authorized_keys:1"],
    "crontabs": ["myuser:MD5_HASH"]
  },
  "whitelist": {
    "ports": [22, 80, 443],
    "processes": [],
    "containers": [],
    "extensions": ["so", "py", "sh"]
  }
}
```

### `baseline` — known-good server state

Defines what your server looks like when everything is normal. Hornet alerts on any deviation.

| Field | What it monitors |
|-------|-----------------|
| `users` | Users with login shells (`user:shell`). Alerts if a new one appears. |
| `ssh_keys` | Key count in `authorized_keys` (`file:count`). Alerts if keys are added. |
| `crontabs` | MD5 hash of each user's crontab. Alerts if someone modifies it. |

Get the hash of your current crontab:

```bash
crontab -l | md5sum | cut -d' ' -f1
```

### `whitelist` — known-safe exceptions

| Field | What it ignores |
|-------|----------------|
| `ports` | Ports legitimately open to the internet |
| `processes` | Processes that may consume high CPU without being malware |
| `containers` | Containers that legitimately extract binaries to `/tmp` |
| `extensions` | File extensions to ignore in `/tmp` checks |

## Automated scans (cron)

Add to your crontab (`crontab -e`):

```cron
*/15 * * * * /path/to/hornet/monitor.sh >> /path/to/hornet/hornet.log 2>&1
```

The installer sets this up automatically.

## Updating the baseline

When you make a legitimate change (open a new port, edit cron, add an SSH key), update the baseline so Hornet stops alerting:

```bash
# Recalculate crontab hash after editing it
crontab -l | md5sum | cut -d' ' -f1
# Then update hornet.json → baseline.crontabs

# Or re-run setup
hornet setup
```

## What alerts look like (via Telegram or ntfy)

**🔴 Critical alert:**
> ⚔️ EXPOSED PORT — Port 5432 (PostgreSQL) open to internet in container "mydb". Close it NOW.

**🟡 Warning:**
> 🟡 MEMORY — RAM at 87% (20G/23G). Top consumers: node (2.1GB), postgres (1.4GB)...

**✅ Recovered:**
> ✅ Exposed port closed (mydb)

## License

MIT — see [LICENSE](LICENSE)

---

*Named after Hornet from [Hollow Knight](https://www.hollowknight.com/) — the guardian of Hallownest.*
