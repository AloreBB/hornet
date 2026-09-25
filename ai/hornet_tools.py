#!/usr/bin/env python3
"""Hornet read-only server tools + secret redaction (stdlib only)."""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

os.environ.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
os.environ.setdefault("TZ", "America/Bogota")
time.tzset()

TRUNC_MARKER = "\n…[truncado]"
_KEYWORDS = r"(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth|credential|private[_-]?key|session|cookie)"

# Order matters: specific shapes first, generic key=value and emails last.
_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "***PRIVATE KEY***"),
    (re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)\S+"), r"\1***"),
    (re.compile(r"(\b[a-zA-Z][\w+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1***@"),
    (re.compile(r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+"), "***"),
    (re.compile(r"\b(?:sk-[\w-]{16,}|ghp_\w{20,}|github_pat_\w{20,}|gh[ousr]_\w{20,}"
                r"|xox[abpr]-[\w-]+|AKIA[0-9A-Z]{16}|\d{8,10}:[\w-]{35})"), "***"),
    (re.compile(r'(?i)("?[\w.-]*' + _KEYWORDS + r'[\w.-]*"?\s*[:=]\s*)("[^"]*"|\S+)'), r"\1***"),
    (re.compile(r"\b([\w.+-])[\w.+-]*@([\w-]+\.[\w.-]+)"), r"\1***@\2"),
]


def redact(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def truncate(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + TRUNC_MARKER


class ToolError(Exception):
    """Unknown tool or invalid argument (reported to the model as isError)."""


class ToolUnavailable(Exception):
    """A command failed, timed out or its binary is missing."""


def _now() -> datetime:
    return datetime.now().astimezone()


def hornet_dir() -> Path:
    return Path(os.environ.get("HORNET_DIR", Path(__file__).resolve().parent.parent))

def state_file() -> Path:
    return Path(os.environ.get("HORNET_STATE_FILE", "/tmp/.hornet-state"))

def auth_log_path() -> Path:
    return Path(os.environ.get("HORNET_AUTH_LOG", "/var/log/auth.log"))

def fail2ban_log_path() -> Path:
    return Path(os.environ.get("HORNET_FAIL2BAN_LOG", "/var/log/fail2ban.log"))

def authorized_keys_path() -> Path:
    return Path(os.environ.get("HORNET_AUTHORIZED_KEYS", Path.home() / ".ssh" / "authorized_keys"))


def _run(cmd: list[str], timeout: int = 10, merge_stderr: bool = False) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, timeout=timeout, shell=False)
    except FileNotFoundError:
        raise ToolUnavailable(f"{cmd[0]} no instalado")
    except subprocess.TimeoutExpired:
        raise ToolUnavailable("timeout")
    out = res.stdout.decode("utf-8", "replace")
    err = res.stderr.decode("utf-8", "replace")
    if res.returncode != 0:
        raise ToolUnavailable((err.strip() or f"exit {res.returncode}").splitlines()[-1][:200])
    return out + err if merge_stderr else out


_ISO_TS = r"(?P<iso>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?[+-]\d\d:\d\d)"
_CLASSIC_TS = r"(?P<classic>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d)"
_ACCEPTED = re.compile(
    rf"^(?:{_ISO_TS}|{_CLASSIC_TS}) \S+ sshd\[\d+\]: Accepted (?P<method>\S+) for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)(?: ssh2)?(?:: \S+ (?P<fp>SHA256:\S+))?")
_FAILED = re.compile(r"sshd\[\d+\]: Failed \S+ for (?:invalid user )?\S+ from (?P<ip>[0-9a-fA-F.:]+)")
_TS = re.compile(rf"^(?:{_ISO_TS}|{_CLASSIC_TS})")
_LAST = re.compile(r"^(\S+)\s+\S+\s+(\S+)\s+(\d{4}-\d\d-\d\dT[\d:]+[+-]\d\d:\d\d)")

# Human-readable method names for tool output.
_METHOD_NAMES = {
    "publickey": "key",
    "password": "contraseña",
}


def _human_method(method: str) -> str:
    if method in _METHOD_NAMES:
        return _METHOD_NAMES[method]
    if method.startswith("keyboard-interactive"):
        return "contraseña (PAM)"
    return method


def _parse_ts(line: str) -> datetime | None:
    m = _TS.match(line)
    if not m:
        return None
    if m.group("iso"):
        try:
            return datetime.fromisoformat(m.group("iso"))
        except ValueError:
            return None
    now = _now()
    try:
        dt = datetime.strptime(f"{now.year} {m.group('classic')}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    dt = dt.replace(tzinfo=now.tzinfo)
    if dt > now + timedelta(days=1):
        dt = dt.replace(year=dt.year - 1)
    return dt


def parse_auth_line(line: str) -> dict | None:
    m = _ACCEPTED.match(line)
    if not m:
        return None
    ts = _parse_ts(line)
    if ts is None:
        return None
    return {
        "ts": ts,
        "user": m.group("user"),
        "ip": m.group("ip"),
        "port": int(m.group("port")),
        "method": m.group("method"),
        "fingerprint": m.group("fp"),
    }


def _read_lines(path: Path) -> list[str] | None:
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None


def _auth_log_lines(since: datetime) -> list[str] | None:
    lines = _read_lines(auth_log_path())
    if lines is None:
        return None
    first_ts = None
    for line in lines:
        first_ts = _parse_ts(line)
        if first_ts is not None:
            break
    if first_ts is None or since < first_ts:
        rotated = _read_lines(Path(str(auth_log_path()) + ".1"))
        if rotated:
            lines = rotated + lines
    return lines


def accepted_logins(since: datetime) -> list[dict] | None:
    lines = _auth_log_lines(since)
    if lines is None:
        return None
    events = []
    for line in lines:
        ev = parse_auth_line(line)
        if ev is not None and ev["ts"] > since:
            events.append(ev)
    events.sort(key=lambda e: e["ts"])
    return events


def key_comments() -> dict[str, str]:
    try:
        out = _run(["ssh-keygen", "-lf", str(authorized_keys_path())])
    except ToolUnavailable:
        return {}
    comments = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1].startswith("SHA256:") and not parts[2].startswith("("):
            comments[parts[1]] = parts[2]
    return comments


def ssh_events_since(since: datetime) -> list[dict] | None:
    logins = accepted_logins(since)
    if logins is not None:
        comments = key_comments()
        for ev in logins:
            ev["key"] = comments.get(ev.get("fingerprint") or "", "")
        return logins
    try:
        out = _run(["last", "-i", "--time-format", "iso", "-s", since.isoformat()])
    except ToolUnavailable:
        return None
    events = []
    for line in out.splitlines():
        if line.startswith("wtmp"):
            continue
        m = _LAST.match(line)
        if not m:
            continue
        user, ip, ts_raw = m.group(1), m.group(2), m.group(3)
        if user == "reboot" or ip == "0.0.0.0":
            continue
        try:
            ts = datetime.fromisoformat(ts_raw)
        except ValueError:
            continue
        events.append({
            "ts": ts, "user": user, "ip": ip, "port": 0,
            "method": "desconocido", "fingerprint": None, "key": "",
        })
    events.sort(key=lambda e: e["ts"])
    return events


def _server_status() -> str:
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    info[parts[0].rstrip(":")] = int(parts[1])
        with open("/proc/loadavg") as f:
            load = f.read().split()[:3]
        with open("/proc/uptime") as f:
            uptime_s = float(f.read().split()[0])
        disk = shutil.disk_usage("/")
    except (OSError, ValueError, KeyError) as e:
        raise ToolUnavailable(f"sin datos ({e})")
    total_g = info["MemTotal"] / 1024 / 1024
    used_g = (info["MemTotal"] - info["MemAvailable"]) / 1024 / 1024
    swap_total = info.get("SwapTotal", 0) / 1024 / 1024
    swap_free = info.get("SwapFree", 0) / 1024 / 1024
    swap_used = swap_total - swap_free
    lines = [f"RAM: {used_g:.1f}/{total_g:.1f} GiB ({used_g / total_g * 100:.0f}%)"]
    if swap_total > 0:
        lines.append(f"Swap: {swap_used:.1f}/{swap_total:.1f} GiB ({swap_used / swap_total * 100:.0f}%)")
    else:
        lines.append("Swap: sin swap")
    lines.append(f"Load: {' '.join(load)} ({os.cpu_count()} CPUs)")
    disk_total = disk.total / 1024 ** 3
    disk_used = disk.used / 1024 ** 3
    lines.append(f"Disco /: {disk_used:.0f}/{disk_total:.0f} GiB ({disk_used / disk_total * 100:.0f}%)")
    days = int(uptime_s // 86400)
    hours = int((uptime_s % 86400) // 3600)
    mins = int((uptime_s % 3600) // 60)
    if days:
        lines.append(f"Uptime: {days} d {hours} h")
    elif hours:
        lines.append(f"Uptime: {hours} h {mins} min")
    else:
        lines.append(f"Uptime: {mins} min")
    return "\n".join(lines)


def _top_processes(sort: str = "mem", limit: int = 10) -> str:
    sort = sort if sort in ("mem", "cpu") else "mem"
    limit = max(1, min(15, limit))
    key = "-rss" if sort == "mem" else "-pcpu"
    out = _run(["ps", "-eo", "pid,user,pcpu,pmem,rss,etimes,comm", "--no-headers", f"--sort={key}"])
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 6)
        if len(parts) < 7:
            continue
        pid, user, pcpu, pmem, rss, etimes, comm = parts
        try:
            rss_mb = int(rss) // 1024
        except ValueError:
            continue
        rows.append(f"{pid} {user} {pcpu} {pmem} {rss_mb} {etimes}s {comm}")
        if len(rows) >= limit:
            break
    header = "PID USER %CPU %MEM RSS_MB EDAD COMANDO"
    return header + "\n" + "\n".join(rows) if rows else header + "\nSin datos."


def _docker_ps(all: bool = False) -> str:
    cmd = ["docker", "ps"] + (["-a"] if all else []) + ["--format", "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"]
    return _run(cmd).strip() or "sin containers"


def _docker_stats() -> str:
    out = _run(["docker", "stats", "--no-stream", "--format",
                "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"], timeout=20)
    return out.strip() or "sin datos"


def _container_logs(name: str, lines: int = 30) -> str:
    lines = max(1, min(50, lines))
    names = [n.strip() for n in _run(["docker", "ps", "-a", "--format", "{{.Names}}"]).splitlines() if n.strip()]
    if name not in names:
        return f"no existe el container '{name}'. Containers: {', '.join(names)}"
    return _run(["docker", "logs", "--tail", str(lines), name], merge_stderr=True)


def _open_ports() -> str:
    return _run(["ss", "-tlnpH"]).strip() or "sin puertos en escucha"


def _hornet_history(limit: int = 10) -> str:
    limit = max(1, min(20, limit))
    sections = []
    try:
        raw = state_file().read_text().strip()
    except OSError:
        raw = ""
    issues = [i for i in raw.split("|") if i.strip()]
    if issues:
        sections.append("Alertas activas:\n" + "\n".join(f"- {i}" for i in issues))
    else:
        sections.append("Alertas activas: ninguna")
    try:
        log_lines = (hornet_dir() / "hornet.log").read_text().splitlines()
    except OSError:
        log_lines = None
    if log_lines is None:
        sections.append("Últimos scans: sin datos")
    else:
        scans = [ln for ln in log_lines if "scan complete" in ln or "ERROR" in ln][-limit:]
        sections.append("Últimos scans:\n" + ("\n".join(scans) if scans else "sin datos"))
    try:
        alert_lines = (hornet_dir() / "alerts.jsonl").read_text().splitlines()
    except OSError:
        alert_lines = None
    if alert_lines is None:
        sections.append("Últimas alertas enviadas: sin datos")
    else:
        items = []
        for ln in alert_lines[-limit:]:
            try:
                a = json.loads(ln)
            except ValueError:
                continue
            items.append(f"{a.get('ts', '')} — {a.get('title', '')} — {a.get('message', '')} — Análisis: {a.get('analysis', '')}")
        sections.append("Últimas alertas enviadas:\n" + ("\n".join(items) if items else "sin datos"))
    return "\n\n".join(sections)


def _ssh_logins(hours: int = 24) -> str:
    hours = max(1, min(72, hours))
    since = _now() - timedelta(hours=hours)
    events = accepted_logins(since)
    if events is None:
        wtmp = ssh_events_since(since)
        head = "(auth.log no legible; datos de wtmp: sin método ni intentos fallidos)"
        if not wtmp:
            return head + "\nSin datos de sesiones."
        return head + "\n" + "\n".join(
            f"{e['ts'].strftime('%H:%M')} {e['user']} desde {e['ip']} ({e['method']})" for e in wtmp)
    comments = key_comments()
    out = []
    for e in events:
        method = _human_method(e["method"])
        key = comments.get(e.get("fingerprint") or "", "")
        detail = f"{method}, {key}" if key else method
        out.append(f"{e['ts'].strftime('%H:%M')} {e['user']} desde {e['ip']} ({detail})")
    if not out:
        out.append("Sin accesos SSH en este período.")
    failed: dict[str, int] = {}
    for line in _auth_log_lines(since) or []:
        m = _FAILED.search(line)
        if not m:
            continue
        ts = _parse_ts(line)
        if ts is not None and ts > since:
            failed[m.group("ip")] = failed.get(m.group("ip"), 0) + 1
    out.append(f"Intentos fallidos: {sum(failed.values())}")
    if failed:
        top = sorted(failed.items(), key=lambda kv: -kv[1])[:5]
        out.append("Top IPs atacantes: " + ", ".join(f"{ip} ({n})" for ip, n in top))
    try:
        with open(fail2ban_log_path(), "rb") as f:
            fb_lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        fb_lines = None
    if fb_lines is not None:
        bans = 0
        for line in fb_lines:
            if " Ban " not in line:
                continue
            try:
                ts = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=_now().tzinfo)
            except ValueError:
                continue
            if ts >= since:
                bans += 1
        out.append(f"Baneos fail2ban: {bans}")
    return "\n".join(out)


TOOLS: dict[str, dict] = {
    "server_status": {
        "fn": _server_status,
        "description": "Solo lectura. Estado del servidor: RAM, swap, carga, disco y uptime.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    "top_processes": {
        "fn": _top_processes,
        "description": "Solo lectura. Procesos con más CPU o memoria (sin argumentos de comandos).",
        "input_schema": {"type": "object", "properties": {
            "sort": {"type": "string", "enum": ["mem", "cpu"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 15},
        }, "additionalProperties": False},
    },
    "docker_ps": {
        "fn": _docker_ps,
        "description": "Solo lectura. Lista de containers Docker.",
        "input_schema": {"type": "object", "properties": {
            "all": {"type": "boolean"},
        }, "additionalProperties": False},
    },
    "docker_stats": {
        "fn": _docker_stats,
        "description": "Solo lectura. Uso de CPU y memoria por container.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    "container_logs": {
        "fn": _container_logs,
        "description": "Solo lectura. Últimas líneas del log de un container.",
        "input_schema": {"type": "object", "properties": {
            "name": {"type": "string"},
            "lines": {"type": "integer", "minimum": 1, "maximum": 50},
        }, "required": ["name"], "additionalProperties": False},
    },
    "open_ports": {
        "fn": _open_ports,
        "description": "Solo lectura. Puertos TCP en escucha.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    "hornet_history": {
        "fn": _hornet_history,
        "description": "Solo lectura. Alertas activas e historial de Hornet.",
        "input_schema": {"type": "object", "properties": {
            "limit": {"type": "integer", "minimum": 1, "maximum": 20},
        }, "additionalProperties": False},
    },
    "ssh_logins": {
        "fn": _ssh_logins,
        "description": "Solo lectura. Accesos SSH recientes, intentos fallidos y baneos.",
        "input_schema": {"type": "object", "properties": {
            "hours": {"type": "integer", "minimum": 1, "maximum": 72},
        }, "additionalProperties": False},
    },
}


def call_tool(name: str, args: dict) -> str:
    spec = TOOLS.get(name)
    if spec is None:
        raise ToolError(f"herramienta desconocida: {name}")
    args = dict(args or {})
    allowed = set(spec["input_schema"].get("properties", {}))
    args = {k: v for k, v in args.items() if k in allowed}
    try:
        if name == "server_status":
            text = _server_status()
        elif name == "top_processes":
            text = _top_processes(str(args.get("sort", "mem")), int(args.get("limit", 10)))
        elif name == "docker_ps":
            text = _docker_ps(bool(args.get("all", False)))
        elif name == "docker_stats":
            text = _docker_stats()
        elif name == "container_logs":
            if "name" not in args:
                raise ToolError("argumento inválido: name es requerido")
            text = _container_logs(str(args["name"]), int(args.get("lines", 30)))
        elif name == "open_ports":
            text = _open_ports()
        elif name == "hornet_history":
            text = _hornet_history(int(args.get("limit", 10)))
        elif name == "ssh_logins":
            text = _ssh_logins(int(args.get("hours", 24)))
        else:  # pragma: no cover - guarded by the TOOLS lookup above
            raise ToolError(f"herramienta desconocida: {name}")
    except (ValueError, TypeError) as e:
        raise ToolError(f"argumento inválido: {e}")
    except ToolUnavailable as e:
        return truncate(redact(f"error: {name} no disponible ({e})"))
    return truncate(redact(text))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "tool":
        tool_name = sys.argv[2] if len(sys.argv) > 2 else ""
        try:
            tool_args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        except ValueError as e:
            print(f"error: argumento inválido: {e}", file=sys.stderr)
            sys.exit(2)
        try:
            print(call_tool(tool_name, tool_args))
        except ToolError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(2)
    elif cmd == "ssh-since":
        cursor = datetime.fromisoformat(sys.argv[2])
        found = ssh_events_since(cursor)
        if found is None:
            sys.exit(3)
        for ev in found:
            print(json.dumps({"ts": ev["ts"].isoformat(), "user": ev["user"], "ip": ev["ip"],
                              "port": ev["port"], "method": ev["method"], "key": ev.get("key", "")}))
    elif cmd == "ssh-lookup":
        lookup_user, lookup_ip, lookup_port = sys.argv[2], sys.argv[3], int(sys.argv[4])
        recent = accepted_logins(_now() - timedelta(days=1))
        if recent is None:
            sys.exit(3)
        match = None
        for ev in recent:
            if ev["user"] == lookup_user and ev["ip"] == lookup_ip and ev["port"] == lookup_port:
                match = ev
        if match is None:
            print("{}")
        else:
            print(json.dumps({"method": match["method"],
                              "key": key_comments().get(match.get("fingerprint") or "", "")}))
    else:
        print(f"uso: {sys.argv[0]} tool <name> [json] | ssh-since <iso> | ssh-lookup <user> <ip> <port>",
              file=sys.stderr)
        sys.exit(2)
