# 🕸️ Hornet

> *Hornet vigila. Hallownest no caerá.*

A lightweight server security monitor that runs every 15 minutes, detects threats, and sends push alerts via [ntfy](https://ntfy.sh). Built for Linux servers running Docker.

![Hornet CLI demo](https://raw.githubusercontent.com/AloreBB/hornet/main/static/hornet-head.png)

## What it detects

| Check | What triggers an alert |
|-------|----------------------|
| 🔌 Exposed DB ports | PostgreSQL, MySQL, MongoDB, Redis open to `0.0.0.0` |
| 🦠 Shady processes | Executables running from `/tmp`, `/dev/shm`, `/var/tmp` |
| 🐳 Container infection | Suspicious binaries inside container `/tmp` |
| 🔥 CPU spike | Processes consuming >150% CPU for >1 minute |
| 💾 RAM / Disk | Usage above configurable thresholds |
| 🔑 fail2ban | Detects if brute-force protection goes down |
| 🔄 Container health | Restart loops and dead containers |
| ⏰ Crontab changes | New or modified cron jobs (persistence detection) |
| 👤 New users / SSH keys | Backdoor detection |
| 📡 Mining pool connections | Outbound connections to known crypto mining ports |
| 🚪 New open ports | Ports not in your baseline |
| 🔐 Suspicious SUID binaries | Privilege escalation detection |

## Requirements

- `bash`
- `jq`
- `docker`
- [`gum`](https://github.com/charmbracelet/gum) (installed automatically by `install.sh`)
- A [ntfy](https://ntfy.sh) server (free public instance or self-hosted)

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/AloreBB/hornet/main/install.sh | bash
```

The installer:
1. Installs `jq` and `gum` if missing
2. Copies Hornet to `~/.hornet/`
3. Adds `hornet` to your `PATH`
4. Runs the interactive setup wizard

## Setup

```bash
hornet init     # create hornet.json from scratch
hornet setup    # interactive configuration wizard (ntfy, whitelists)
```

Configure ntfy notifications:
- **URL**: your ntfy server (`https://ntfy.sh` or self-hosted)
- **Topic**: your private channel name
- **Token**: optional access token (stored in `.hornet.env`, never committed)

## Usage

```bash
# Run a scan now
hornet run

# View recent scan history
hornet status

# Manage whitelists (interactive)
hornet whitelist

# Manage whitelists (direct commands)
hornet whitelist list
hornet whitelist add port 25565        # Minecraft server
hornet whitelist add process java      # JVM apps
hornet whitelist add container myapp   # Skip /tmp check for a container
hornet whitelist add ext dylib         # Additional safe extension

hornet whitelist remove port 8080
```

## Configuration

Copy `hornet.example.json` to `hornet.json` and edit it, or use `hornet setup`.

```json
{
  "notifications": {
    "url": "https://ntfy.sh",
    "topic": "my-alerts",
    "icon": ""
  },
  "baseline": {
    "users": ["root:/bin/bash", "myuser:/bin/bash"],
    "ssh_keys": ["/home/myuser/.ssh/authorized_keys:1"],
    "crontabs": ["myuser:HASH"]
  },
  "whitelist": {
    "ports": [22, 80, 443],
    "processes": [],
    "containers": [],
    "extensions": ["so", "py", "sh"]
  }
}
```

Your ntfy token goes in `.hornet.env` (auto-created, gitignored):

```bash
NTFY_TOKEN=your_token_here
```

## Scheduled scans (cron)

Add to your crontab (`crontab -e`):

```cron
*/15 * * * * /path/to/hornet/hornet.sh >> /path/to/hornet/hornet.log 2>&1
```

Or use the installer — it sets this up automatically.

## Updating the baseline

When you intentionally change something (new port, new cron, new SSH key), update the baseline so Hornet stops alerting:

```bash
# Recalculate crontab hash after editing it
crontab -l -u $USER | md5sum | cut -d' ' -f1
# Then update hornet.json → baseline.crontabs

# Or simply run setup again
hornet setup
```

## Alerts look like this (via ntfy)

**🔴 Critical alert:**
> ⚔️ EXPOSED PORT — Port 5432 (PostgreSQL) open to internet in container "mydb". Close it NOW.

**🟡 Warning:**
> 🟡 MEMORY — RAM at 87% (20G/23G). Top consumers: node (2.1GB), postgres (1.4GB)...

**✅ Recovery:**
> ✅ Exposed port closed (mydb)

## License

MIT — see [LICENSE](LICENSE)

---

*Named after Hornet from [Hollow Knight](https://www.hollowknight.com/) — the guardian of Hallownest.*
