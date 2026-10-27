#!/bin/bash
# ============================================================
# 🕸️ HORNET — Guardiana de Hallownest
# Server security monitor with push alerts via Telegram and/or ntfy
# ============================================================

set -uo pipefail

export TZ=America/Bogota

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.json"
STATE_FILE="${HORNET_STATE_FILE:-/tmp/.hornet-state}"
TELEGRAM_API_BASE="${TELEGRAM_API_BASE:-https://api.telegram.org}"
HOSTNAME=$(hostname)
NOW=$(date '+%Y-%m-%d %H:%M')

# --- Load credentials ---
# Priority: 1) already set in environment, 2) ~/.config/hornet/credentials, 3) legacy .hornet.env
CREDENTIALS_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/hornet/credentials"
CREDENTIAL_VARS="NTFY_TOKEN TELEGRAM_BOT_TOKEN AI_API_KEY"
declare -A _ENV_CREDS=()
for _var in $CREDENTIAL_VARS; do _ENV_CREDS[$_var]="${!_var:-}"; done
if [[ -f "$CREDENTIALS_FILE" ]]; then
    source "$CREDENTIALS_FILE"
elif [[ -f "$SCRIPT_DIR/.hornet.env" ]]; then
    source "$SCRIPT_DIR/.hornet.env"
fi
for _var in $CREDENTIAL_VARS; do
    [[ -n "${_ENV_CREDS[$_var]}" ]] && printf -v "$_var" '%s' "${_ENV_CREDS[$_var]}"
    printf -v "$_var" '%s' "${!_var:-}"   # always defined (nounset)
done
unset _var _ENV_CREDS

# --- Load JSON config ---
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: $CONFIG_FILE not found. Run 'hornet init' to create it."
    exit 1
fi
_jq() { jq -r "$1" "$CONFIG_FILE"; }

# Notification settings (tokens come from the environment or credentials file)
NTFY_URL=$(_jq '.notifications.url // ""')
NTFY_TOPIC=$(_jq '.notifications.topic // ""')
NTFY_ICON=$(_jq '.notifications.icon // ""')
TELEGRAM_CHAT_ID=$(_jq '.notifications.telegram_chat_id // ""')
AI_EXPLAIN=$(_jq '.ai.explain_alerts // false')
HEALTHCHECK_URL=$(_jq '.healthcheck_url // ""')

# Baseline values
BASELINE_USERS=$(_jq '.baseline.users | join(" ")')
BASELINE_SSH_KEYS=$(_jq '.baseline.ssh_keys | join(" ")')
BASELINE_CRONTABS=$(_jq '.baseline.crontabs | join(" ")')
BASELINE_PUBLIC_PORTS=$(_jq '.whitelist.ports | join(" ")')

# Whitelist values
WHITELIST_HIGH_CPU_PROCS=$(_jq '.whitelist.processes | join(" ")')
WHITELIST_CONTAINER_TMP=$(_jq '.whitelist.containers | join(" ")')
WHITELIST_CONTAINER_TMP_EXT=$(_jq '.whitelist.extensions | join(" ")')

# --- State management (avoid duplicate alerts) ---
load_state() {
    if [[ -f "$STATE_FILE" ]]; then
        cat "$STATE_FILE"
    else
        echo ""
    fi
}

save_state() {
    echo "$1" > "$STATE_FILE"
}

log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR $*" >&2; }
DELIVERY_FAILED=0

# --- Escape text for Telegram HTML parse mode ---
html_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    printf '%s' "$s"
}

# --- Send push notification via Telegram ---
# Usage: send_telegram level title message. Returns 0 on delivery.
send_telegram() {
    local level="$1" title="$2" message="$3"
    local emoji
    case "$level" in
        alert)     emoji="🚨" ;;
        warning)   emoji="⚠️" ;;
        recovered) emoji="✅" ;;
        info)      emoji="🔑" ;;
        *)         emoji="🕸️" ;;
    esac
    # Telegram caps messages at 4096 chars: truncate before escaping
    if ((${#message} > 3500)); then
        message="${message:0:3500}"$'\n…'
    fi
    local text
    text="<b>$(html_escape "$emoji $title")</b>

$(html_escape "$message")"
    local tmpfile errfile http_code curl_rc
    tmpfile=$(mktemp)
    errfile=$(mktemp)
    http_code=$(curl -sS --max-time 15 \
        --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
        --data-urlencode "parse_mode=HTML" \
        --data-urlencode "disable_web_page_preview=true" \
        --data-urlencode "text=${text}" \
        "${TELEGRAM_API_BASE}/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -o "$tmpfile" -w '%{http_code}' 2>"$errfile")
    curl_rc=$?
    if [[ "$curl_rc" -ne 0 ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR telegram: $(cat "$errfile")" >&2
        rm -f "$tmpfile" "$errfile"
        return 1
    fi
    if [[ "$http_code" != 2* ]]; then
        local desc
        desc=$(jq -r '.description // empty' "$tmpfile" 2>/dev/null || true)
        [[ -z "$desc" ]] && desc="request failed"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR telegram: HTTP ${http_code} — ${desc}" >&2
        rm -f "$tmpfile" "$errfile"
        return 1
    fi
    rm -f "$tmpfile" "$errfile"
    return 0
}

# --- Send push notification via ntfy ---
# Usage: send_ntfy level title message. Returns 0 on delivery.
send_ntfy() {
    local level="$1" title="$2" message="$3"
    local priority tags
    case "$level" in
        alert)     priority="urgent";  tags="rotating_light,skull" ;;
        warning)   priority="high";    tags="warning" ;;
        recovered) priority="default"; tags="white_check_mark,shield" ;;
        info)      priority="default"; tags="key" ;;
        *)         priority="default"; tags="" ;;
    esac
    local auth_args=()
    [[ -n "$NTFY_TOKEN" ]] && auth_args=(-H "Authorization: Bearer ${NTFY_TOKEN}")
    local tmpfile errfile http_code curl_rc
    tmpfile=$(mktemp)
    errfile=$(mktemp)
    http_code=$(curl -sS --max-time 10 \
        "${auth_args[@]}" \
        -H "Title: ${title}" \
        -H "Priority: ${priority}" \
        -H "Tags: ${tags}" \
        -H "Icon: ${NTFY_ICON}" \
        -d "$message" \
        "${NTFY_URL}/${NTFY_TOPIC}" \
        -o "$tmpfile" -w '%{http_code}' 2>"$errfile")
    curl_rc=$?
    if [[ "$curl_rc" -ne 0 ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR ntfy: $(cat "$errfile")" >&2
        rm -f "$tmpfile" "$errfile"
        return 1
    fi
    if [[ "$http_code" != 2* ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR ntfy: HTTP ${http_code}" >&2
        rm -f "$tmpfile" "$errfile"
        return 1
    fi
    rm -f "$tmpfile" "$errfile"
    return 0
}

# --- Notify every enabled channel ---
# Usage: notify level title message. Returns 0 if at least one channel delivered.
notify() {
    local level="$1" title="$2" message="$3"
    local telegram_on=false ntfy_on=false
    [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]] && telegram_on=true
    [[ -n "$NTFY_URL" && -n "$NTFY_TOPIC" ]] && ntfy_on=true
    if ! $telegram_on && ! $ntfy_on; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: no notification channel configured (set telegram_chat_id + TELEGRAM_BOT_TOKEN, or ntfy url + topic) — alert NOT sent" >&2
        DELIVERY_FAILED=1
        return 1
    fi
    local delivered=0
    if $telegram_on; then
        send_telegram "$level" "$title" "$message" && delivered=1
    fi
    if $ntfy_on; then
        send_ntfy "$level" "$title" "$message" && delivered=1
    fi
    if [[ "$delivered" -eq 1 ]]; then
        return 0
    fi
    DELIVERY_FAILED=1
    return 1
}

# --- AI analysis for alerts (never blocks delivery) ---
# Usage: explain_alert level title message. Prints the analysis or nothing.
explain_alert() {
    [[ "$AI_EXPLAIN" == "true" && -n "$AI_API_KEY" ]] || return 0
    if ! command -v python3 &>/dev/null; then
        log_error "explain: python3 not found"
        return 0
    fi
    local input analysis rc
    input=$(jq -nc --arg level "$1" --arg title "$2" --arg message "$3" \
        '{level: $level, title: $title, message: $message}')
    analysis=$(printf '%s' "$input" | AI_API_KEY="$AI_API_KEY" HORNET_DIR="$SCRIPT_DIR" \
        timeout 35 python3 "$SCRIPT_DIR/ai/explain.py")
    rc=$?
    [[ "$rc" -eq 124 ]] && log_error "explain: timeout"
    [[ "$rc" -eq 0 ]] && printf '%s' "$analysis"
    return 0
}

# --- Alert history for the chat (last 500) ---
record_alert() {
    local file="$SCRIPT_DIR/alerts.jsonl"
    jq -nc --arg ts "$(date --iso-8601=seconds)" --arg level "$1" --arg title "$2" \
        --arg issues "$3" --arg message "$4" --arg analysis "$5" \
        '{ts: $ts, level: $level, title: $title, issues: $issues, message: $message, analysis: $analysis}' >> "$file"
    if [[ $(wc -l < "$file") -gt 500 ]]; then
        tail -n 500 "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    fi
}

# --- Explain + notify + record ---
# Usage: deliver level title message issues. Returns notify's status.
deliver() {
    local level="$1" title="$2" message="$3" issues="$4" analysis=""
    if [[ "$level" == "alert" || "$level" == "warning" ]]; then
        analysis=$(explain_alert "$level" "$title" "$message")
    fi
    local full="$message"
    [[ -n "$analysis" ]] && full="${message}"$'\n\n'"🧠 Análisis (IA): ${analysis}"
    notify "$level" "$title" "$full" || return 1
    record_alert "$level" "$title" "$issues" "$message" "$analysis"
}

# --- External dead-man switch (healthchecks.io) ---
healthcheck_ping() {
    [[ -n "$HEALTHCHECK_URL" ]] || return 0
    local url="$HEALTHCHECK_URL"
    [[ "$1" == "fail" ]] && url="${url%/}/fail"
    curl -fsS -m 10 --retry 2 -o /dev/null "$url" 2>/dev/null || log_error "healthcheck: ping failed"
}

# --- Test mode: send a test notification and exit ---
if [[ "${1:-}" == "--test" ]]; then
    if notify recovered "HORNET — Prueba" "Los hilos vibran con fuerza. Esta es una prueba de Hornet: si lees esto, las alertas de tu servidor llegan a su destino. 🕸️

Servidor: ${HOSTNAME} | ${NOW}"; then
        echo "Test notification sent."
        if [[ "$AI_EXPLAIN" == "true" && -n "$AI_API_KEY" ]]; then
            analysis=$(explain_alert warning "HORNET — Prueba" "MEMORIA — RAM al 91% (21Gi/23Gi). Prueba del análisis de Hornet.")
            if [[ -n "$analysis" ]]; then echo "Análisis de prueba: $analysis"; else echo "Análisis de prueba: sin respuesta (revisa el log)"; fi
        fi
        exit 0
    else
        exit 1
    fi
fi

# --- SSH login mode (called from ~/.ssh/rc): instant access alert ---
if [[ "${1:-}" == "--ssh-login" ]]; then
    read -r ssh_ip ssh_port _ <<< "${SSH_CONNECTION:-}"
    [[ -z "${ssh_ip:-}" ]] && exit 0
    ssh_user=$(id -un)
    exec 9>"$SCRIPT_DIR/.ssh-login.lock"
    flock -w 20 9 || exit 0
    last_file="$SCRIPT_DIR/ssh-last-notified"
    known_file="$SCRIPT_DIR/ssh-known-ips"
    now_epoch=$(date +%s)
    if [[ -f "$last_file" ]]; then
        read -r last_ip last_epoch < "$last_file"
        if [[ "${last_ip:-}" == "$ssh_ip" && $((now_epoch - ${last_epoch:-0})) -lt 600 ]]; then
            exit 0
        fi
    fi
    ssh_method="" ssh_key=""
    if command -v python3 &>/dev/null; then
        for _ in 1 2 3; do
            info=$(python3 "$SCRIPT_DIR/ai/hornet_tools.py" ssh-lookup "$ssh_user" "$ssh_ip" "$ssh_port" 2>/dev/null) || break
            ssh_method=$(jq -r '.method // empty' <<< "$info")
            ssh_key=$(jq -r '.key // empty' <<< "$info")
            [[ -n "$ssh_method" ]] && break
            sleep 1
        done
    fi
    ip_known=false
    grep -qxF "$ssh_ip" "$known_file" 2>/dev/null && ip_known=true
    case "$ssh_method" in
        publickey) how="key ${ssh_key:-sin comentario}" ;;
        password|keyboard-interactive*) how="con contraseña" ;;
        *) how="método desconocido" ;;
    esac
    level="info"
    if [[ "$how" == "con contraseña" || "$ip_known" == false ]]; then level="warning"; fi
    where="IP conocida"; $ip_known || where="IP nueva"
    if notify "$level" "HORNET — Acceso SSH" "${ssh_user} desde ${ssh_ip} (${where}) · ${how} · $(date '+%H:%M')
Servidor: ${HOSTNAME}"; then
        echo "$ssh_ip $now_epoch" > "$last_file"
        $ip_known || echo "$ssh_ip" >> "$known_file"
    fi
    exit 0
fi

# ============================================================
# CHECKS
# ============================================================

ALERTS=""
WARNINGS=""
RECOVERED=""
PREVIOUS_STATE=$(load_state)
CURRENT_ISSUES=""

# --- 1. Exposed DB/cache ports (0.0.0.0) ---
check_exposed_ports() {
    local line
    while IFS=$'\t' read -r name ports; do
        if echo "$ports" | grep -qE '0\.0\.0\.0:(5432|3306|27017|6379)->' 2>/dev/null; then
            local port service=""
            port=$(echo "$ports" | grep -oE '0\.0\.0\.0:(5432|3306|27017|6379)' | head -1 | cut -d: -f2)
            case "$port" in
                5432) service="PostgreSQL" ;;
                3306) service="MySQL" ;;
                27017) service="MongoDB" ;;
                6379) service="Redis" ;;
            esac
            ALERTS="${ALERTS}⚔️ PUERTO EXPUESTO — Puerto ${port} (${service}) abierto a internet en contenedor \"${name}\". Cualquier infectado puede entrar por fuerza bruta. Ciérralo YA.\n\n"
            CURRENT_ISSUES="${CURRENT_ISSUES}exposed_port_${name}|"
        fi
    done < <(docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null)
}

# --- 2. Suspicious processes in shady directories ---
check_shady_processes() {
    local line
    while IFS='|' read -r proc cpu pid; do
        [[ -z "$proc" ]] && continue
        ALERTS="${ALERTS}⚔️ PARÁSITO — Proceso ${proc} (PID ${pid}) consumiendo ${cpu}% CPU. Un binario ejecutándose desde un directorio temporal es casi siempre malware. Investiga y mata el proceso.\n\n"
        CURRENT_ISSUES="${CURRENT_ISSUES}shady_proc_${pid}|"
    done < <(ps aux 2>/dev/null | awk '$11 ~ /^\/(tmp|dev\/shm|var\/tmp|run\/user)/ {printf "%s|%s|%s\n", $11, $3, $2}')
}

# --- 3. Suspicious binaries inside containers ---
check_container_tmp() {
    # Build extension exclusion pattern from whitelist
    local ext_pattern='\.py$|\.sh$|\.so(\.[0-9]+)*$'
    if [[ -n "${WHITELIST_CONTAINER_TMP_EXT:-}" ]]; then
        for ext in $WHITELIST_CONTAINER_TMP_EXT; do
            ext="${ext#.}"  # strip leading dot if present
            ext_pattern="${ext_pattern}|\.${ext}$"
        done
    fi

    local cid name suspicious_files
    for cid in $(docker ps -q 2>/dev/null); do
        name=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's/^\///')

        # Skip whitelisted containers
        if [[ -n "${WHITELIST_CONTAINER_TMP:-}" ]]; then
            local skip=false
            for wl_container in $WHITELIST_CONTAINER_TMP; do
                [[ "$name" == "$wl_container" ]] && skip=true && break
            done
            [[ "$skip" == true ]] && continue
        fi

        suspicious_files=$(timeout 5 docker exec "$cid" sh -c 'find /tmp /dev/shm /var/tmp -type f -executable 2>/dev/null' 2>/dev/null | grep -vE "$ext_pattern" || true)

        if [[ -n "$suspicious_files" ]]; then
            local files_list
            files_list=$(echo "$suspicious_files" | head -5 | tr '\n' ', ' | sed 's/,$//')
            ALERTS="${ALERTS}⚔️ INFECCIÓN EN CONTENEDOR — Binarios ejecutables sospechosos dentro de \"${name}\": ${files_list}. Los parásitos se esconden ahí. Revísalo.\n\n"
            CURRENT_ISSUES="${CURRENT_ISSUES}container_tmp_${name}|"
        fi
    done
}

# --- 4. High CPU processes (>150% sustained, running >1 min) ---
check_high_cpu() {
    # Build process exclusion pattern: system defaults + user whitelist
    local cpu_exclude='docker|containerd|Xorg|gnome|code-server|vscode|chromium|chrome|cc1|gcc|g\+\+|rustc|cargo|npm|yarn|webpack|esbuild|tsc'
    if [[ -n "${WHITELIST_HIGH_CPU_PROCS:-}" ]]; then
        for proc_name in $WHITELIST_HIGH_CPU_PROCS; do
            cpu_exclude="${cpu_exclude}|${proc_name}"
        done
    fi

    local line
    while IFS='|' read -r proc cpu pid etime; do
        [[ -z "$proc" ]] && continue
        # Skip processes running less than 1 minute (ephemeral)
        if echo "$etime" | grep -qE '^[0-9]+:[0-9]+:|^[0-9]+-' 2>/dev/null; then
            # Has hours or days — definitely sustained
            true
        elif echo "$etime" | grep -qE '^00:' 2>/dev/null; then
            # Less than 1 minute, skip
            continue
        fi
        local user cmdline
        user=$(ps -o user= -p "$pid" 2>/dev/null || echo "?")
        cmdline=$(ps -o args= -p "$pid" 2>/dev/null | head -c 120 || echo "?")
        ALERTS="${ALERTS}⚔️ CPU DEVORADA — ${proc} (PID ${pid}, user: ${user}) consumiendo ${cpu}% CPU.\n   Comando: ${cmdline}\n   Podría ser un minero disfrazado. Verifica su origen.\n\n"
        CURRENT_ISSUES="${CURRENT_ISSUES}high_cpu_${pid}|"
    done < <(ps -eo pcpu,pid,etimes,comm --no-headers 2>/dev/null | awk '$1 > 150.0 && $3 > 60 {printf "%s|%s|%s|%s\n", $4, $1, $2, $3}' | grep -vE "$cpu_exclude" || true)
}

# --- 5. RAM usage ---
check_ram() {
    local ram_pct ram_used ram_total
    ram_pct=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}')
    ram_used=$(free -h | awk '/^Mem:/ {print $3}')
    ram_total=$(free -h | awk '/^Mem:/ {print $2}')

    if [[ "$ram_pct" -gt 80 ]]; then
        # Build top RAM consumers list
        local top_procs
        top_procs=$(ps -eo pid,user,%mem,rss,comm --no-headers --sort=-rss 2>/dev/null \
            | awk '$3 > 1.0 {printf "   • %s (%s) — %.0fMB (%.1f%%)\n", $5, $2, $4/1024, $3}' \
            | head -8)

        if [[ "$ram_pct" -gt 90 ]]; then
            ALERTS="${ALERTS}⚔️ MEMORIA CRÍTICA — RAM al ${ram_pct}% (${ram_used}/${ram_total}). El reino se ahoga.\n\nProcesos que más consumen:\n${top_procs}\n\n"
            CURRENT_ISSUES="${CURRENT_ISSUES}ram_critical|"
        else
            WARNINGS="${WARNINGS}🟡 MEMORIA — RAM al ${ram_pct}% (${ram_used}/${ram_total}). Vigila de cerca.\n\nProcesos que más consumen:\n${top_procs}\n\n"
            CURRENT_ISSUES="${CURRENT_ISSUES}ram_warning|"
        fi
    fi
}

# --- 6. Disk usage ---
check_disk() {
    local disk_pct disk_used disk_total
    disk_pct=$(df / | awk 'NR==2 {gsub(/%/,""); print $5}')
    disk_used=$(df -h / | awk 'NR==2 {print $3}')
    disk_total=$(df -h / | awk 'NR==2 {print $2}')

    if [[ "$disk_pct" -gt 85 ]]; then
        # Find largest directories consuming disk
        local top_dirs
        top_dirs=$(du -xh --max-depth=2 / 2>/dev/null | sort -rh | head -8 \
            | awk '{printf "   • %s — %s\n", $2, $1}')
        # Docker disk usage
        local docker_size
        docker_size=$(docker system df --format '{{.Type}}\t{{.Size}}' 2>/dev/null \
            | awk -F'\t' '{printf "   • Docker %s — %s\n", $1, $2}' || echo "   • Docker — no disponible")

        if [[ "$disk_pct" -gt 90 ]]; then
            ALERTS="${ALERTS}⚔️ DISCO CRÍTICO — Disco al ${disk_pct}% (${disk_used}/${disk_total}). No queda espacio en Hallownest.\n\nMayores consumidores:\n${top_dirs}\n\n${docker_size}\n\n"
            CURRENT_ISSUES="${CURRENT_ISSUES}disk_critical|"
        else
            WARNINGS="${WARNINGS}🟡 DISCO — El reino se llena. ${disk_pct}% (${disk_used}/${disk_total}).\n\nMayores consumidores:\n${top_dirs}\n\n${docker_size}\n\n"
            CURRENT_ISSUES="${CURRENT_ISSUES}disk_warning|"
        fi
    fi
}

# --- 7. fail2ban status ---
check_fail2ban() {
    if ! systemctl is-active --quiet fail2ban 2>/dev/null; then
        ALERTS="${ALERTS}⚔️ FAIL2BAN CAÍDO — La protección contra fuerza bruta SSH está muerta. El servidor queda sin trampas de seda. Repáralo con: sudo systemctl restart fail2ban\n\n"
        CURRENT_ISSUES="${CURRENT_ISSUES}fail2ban_down|"
    fi
}

# --- 8. Containers in restart loop or died ---
check_containers() {
    local restarting dead names
    restarting=$(docker ps -a --filter "status=restarting" --format '{{.Names}}' 2>/dev/null || true)
    dead=$(docker ps -a --filter "status=dead" --format '{{.Names}}' 2>/dev/null || true)

    if [[ -n "$restarting" ]]; then
        names=$(echo "$restarting" | tr '\n' ', ' | sed 's/,$//')
        WARNINGS="${WARNINGS}🟡 CONTENEDORES EN LOOP — Reiniciándose sin parar: ${names}. Algo los mata.\n\n"
        CURRENT_ISSUES="${CURRENT_ISSUES}containers_restarting|"
    fi

    if [[ -n "$dead" ]]; then
        names=$(echo "$dead" | tr '\n' ', ' | sed 's/,$//')
        WARNINGS="${WARNINGS}🟡 CONTENEDORES MUERTOS — ${names}. Revisa los logs.\n\n"
        CURRENT_ISSUES="${CURRENT_ISSUES}containers_dead|"
    fi
}

# --- 9. Modified crontabs (persistence detection) ---
check_crontabs() {
    [[ -z "${BASELINE_CRONTABS:-}" ]] && return
    local entry user expected_hash current_hash
    for entry in $BASELINE_CRONTABS; do
        user="${entry%%:*}"
        expected_hash="${entry##*:}"
        current_hash=$(crontab -l -u "$user" 2>/dev/null | md5sum | cut -d' ' -f1)
        if [[ "$current_hash" != "$expected_hash" ]]; then
            ALERTS="${ALERTS}⚔️ CRONTAB MODIFICADO — El crontab de \"${user}\" fue alterado. Los parásitos usan cron para sobrevivir reinicios. Revisa con: crontab -l -u ${user}\n\n"
            CURRENT_ISSUES="${CURRENT_ISSUES}crontab_${user}|"
        fi
    done
    # Check for crontabs in users that shouldn't have any
    local known_users
    known_users=$(echo "$BASELINE_CRONTABS" | tr ' ' '\n' | cut -d: -f1)
    for user in $(cut -f1 -d: /etc/passwd); do
        if crontab -l -u "$user" 2>/dev/null | grep -qv '^#' && ! echo "$known_users" | grep -q "^${user}$"; then
            ALERTS="${ALERTS}⚔️ CRONTAB NUEVO — El usuario \"${user}\" tiene un crontab que no existía antes. Podría ser persistencia de malware. Revisa: crontab -l -u ${user}\n\n"
            CURRENT_ISSUES="${CURRENT_ISSUES}crontab_new_${user}|"
        fi
    done
}

# --- 10. New users or SSH keys (backdoor detection) ---
check_users_and_keys() {
    [[ -z "${BASELINE_USERS:-}" ]] && return
    # Check for new users with login shells
    local current_users
    current_users=$(awk -F: '$7 ~ /bash|sh|zsh/ {print $1":"$7}' /etc/passwd)
    local user_entry
    while IFS= read -r user_entry; do
        [[ -z "$user_entry" ]] && continue
        if ! echo "$BASELINE_USERS" | grep -qF "$user_entry"; then
            local uname="${user_entry%%:*}"
            ALERTS="${ALERTS}⚔️ USUARIO NUEVO — \"${uname}\" tiene shell de login (${user_entry##*:}). Si no lo creaste tú, es una backdoor. Revisa: id ${uname}\n\n"
            CURRENT_ISSUES="${CURRENT_ISSUES}new_user_${uname}|"
        fi
    done <<< "$current_users"

    # Check authorized_keys changes
    [[ -z "${BASELINE_SSH_KEYS:-}" ]] && return
    local entry file expected_count current_count
    for entry in $BASELINE_SSH_KEYS; do
        file="${entry%%:*}"
        expected_count="${entry##*:}"
        if [[ -f "$file" ]]; then
            current_count=$(wc -l < "$file")
            if [[ "$current_count" -gt "$expected_count" ]]; then
                ALERTS="${ALERTS}⚔️ SSH KEYS INYECTADAS — ${file} tenía ${expected_count} keys, ahora tiene ${current_count}. Alguien añadió acceso SSH. Revisa el archivo.\n\n"
                CURRENT_ISSUES="${CURRENT_ISSUES}ssh_keys_${file}|"
            fi
        fi
    done
    # Check for new authorized_keys files
    local new_keys
    # Only the paths sshd actually reads (default AuthorizedKeysFile). A recursive
    # find over /home walked node_modules/worktrees and loaded the server every run.
    new_keys=$(ls -1 /root/.ssh/authorized_keys{,2} /home/*/.ssh/authorized_keys{,2} 2>/dev/null || true)
    while IFS= read -r keyfile; do
        [[ -z "$keyfile" ]] && continue
        if ! echo "$BASELINE_SSH_KEYS" | grep -qF "$keyfile"; then
            ALERTS="${ALERTS}⚔️ SSH KEYS NUEVAS — Archivo ${keyfile} no existía antes. Backdoor SSH detectada.\n\n"
            CURRENT_ISSUES="${CURRENT_ISSUES}ssh_keys_new_${keyfile}|"
        fi
    done <<< "$new_keys"
}

# --- 11. Suspicious outbound connections (mining pools, C2) ---
check_outbound() {
    local suspicious
    # Common mining pool ports: 3333, 4444, 5555, 8888, 9999, 14444, 45560
    # Also detect stratum+tcp connections and known mining domains
    suspicious=$(ss -tnp 2>/dev/null | awk '$1 == "ESTAB" {print $0}' | grep -E ':(3333|4444|5555|8888|9999|14444|45560|14433|13333) ' || true)
    if [[ -n "$suspicious" ]]; then
        local details
        details=$(echo "$suspicious" | awk '{print $5}' | head -5 | tr '\n' ', ' | sed 's/,$//')
        ALERTS="${ALERTS}⚔️ CONEXIÓN A POOL DE MINERÍA — Conexiones salientes a puertos de minería detectadas: ${details}. Un minero está enviando hashes. Investiga los procesos.\n\n"
        CURRENT_ISSUES="${CURRENT_ISSUES}mining_outbound|"
    fi
    # Detect high volume of outbound connections from a single process (C2 or botnet)
    local high_conn_proc
    high_conn_proc=$(ss -tnp 2>/dev/null | awk '$1 == "ESTAB"' | grep -oP 'users:\(\("\K[^"]+' | sort | uniq -c | sort -rn | awk '$1 > 50 {print $1":"$2}' | head -3 || true)
    if [[ -n "$high_conn_proc" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local count="${line%%:*}"
            local proc="${line##*:}"
            # Skip known high-connection processes
            echo "$proc" | grep -qE 'docker|traefik|node|nginx|postgres' && continue
            WARNINGS="${WARNINGS}🟡 CONEXIONES MASIVAS — Proceso \"${proc}\" tiene ${count} conexiones activas. Podría ser C2 o botnet.\n\n"
            CURRENT_ISSUES="${CURRENT_ISSUES}high_conn_${proc}|"
        done <<< "$high_conn_proc"
    fi
}

# --- 12. New listening ports (unauthorized services) ---
check_new_ports() {
    [[ -z "${BASELINE_PUBLIC_PORTS:-}" ]] && return
    local current_ports
    current_ports=$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | grep -E '^0\.0\.0\.0:' | grep -oE ':[0-9]+$' | tr -d ':' | sort -un || true)
    while IFS= read -r port; do
        [[ -z "$port" ]] && continue
        if ! echo "$BASELINE_PUBLIC_PORTS" | grep -qw "$port"; then
            local proc_info
            proc_info=$(ss -tlnp 2>/dev/null | grep "0.0.0.0:${port} " | grep -oP 'users:\(\("\K[^"]+' | head -1 || echo "desconocido")
            ALERTS="${ALERTS}⚔️ PUERTO NUEVO — Puerto ${port} abierto a internet (proceso: ${proc_info}). No estaba en la línea base. Si no lo abriste tú, investiga.\n\n"
            CURRENT_ISSUES="${CURRENT_ISSUES}new_port_${port}|"
        fi
    done <<< "$current_ports"
}

# --- 13. SUID/SGID binaries (privilege escalation) ---
check_suid() {
    local suspicious_suid
    # Look for SUID binaries in unusual locations (not /usr/bin, /usr/sbin, /usr/lib, /snap)
    suspicious_suid=$(find / -perm -4000 -type f 2>/dev/null | grep -vE '^/(usr/(bin|sbin|lib)|snap|proc|sys|opt/google)/' || true)
    if [[ -n "$suspicious_suid" ]]; then
        local files_list
        files_list=$(echo "$suspicious_suid" | head -5 | tr '\n' ', ' | sed 's/,$//')
        ALERTS="${ALERTS}⚔️ SUID SOSPECHOSO — Binarios con bit SUID en ubicaciones inusuales: ${files_list}. Podrían usarse para escalar privilegios.\n\n"
        CURRENT_ISSUES="${CURRENT_ISSUES}suid_suspicious|"
    fi
}

# --- 14. SSH logins by other users (events, not issues) ---
check_ssh_logins() {
    command -v python3 &>/dev/null || return 0
    local cursor_file="$SCRIPT_DIR/ssh-scan.cursor" now cursor events owner lines
    now=$(date '+%Y-%m-%dT%H:%M:%S.%6N%:z')
    if [[ ! -f "$cursor_file" ]]; then
        echo "$now" > "$cursor_file"
        return 0
    fi
    cursor=$(cat "$cursor_file")
    if ! events=$(python3 "$SCRIPT_DIR/ai/hornet_tools.py" ssh-since "$cursor"); then
        log_error "ssh logins: no log source readable (auth.log / wtmp)"
        return 0
    fi
    # Next cursor: the later of scan start and newest login seen, compared as epoch
    # microseconds, so a login in the same second as the scan is never reported twice
    local next="$now" next_us ts ts_us
    next_us=$(date -d "$now" +%s%6N)
    while IFS= read -r ts; do
        [[ -z "$ts" ]] && continue
        ts_us=$(date -d "$ts" +%s%6N 2>/dev/null) || continue
        if (( ts_us > next_us )); then
            next="$ts"
            next_us="$ts_us"
        fi
    done < <(printf '%s\n' "$events" | jq -r 'select(type == "object") | .ts' 2>/dev/null)
    owner=$(id -un)
    lines=$(printf '%s\n' "$events" | jq -r --arg owner "$owner" \
        'select(type == "object" and .user != $owner) | "   • \(.ts[11:16]) — \(.user) desde \(.ip) (\(.method))"' 2>/dev/null)
    if [[ -z "$lines" ]]; then
        echo "$next" > "$cursor_file"
        return 0
    fi
    local message="Alguien cruzó la puerta de Hallownest y no eres tú.\n\n${lines}\n\nSi no reconoces estos accesos, revisa: last -i y /var/log/auth.log\n\nHornet vigila. Hallownest no caerá.\nServidor: ${HOSTNAME} | ${NOW}"
    if notify alert "HORNET — Intruso en la puerta" "$(echo -e "$message")"; then
        echo "$next" > "$cursor_file"
    else
        log_error "ssh logins: notification failed — cursor kept, will retry"
    fi
}

# ============================================================
# CHECK FOR RECOVERED ISSUES
# ============================================================

check_recovered() {
    if [[ -z "$PREVIOUS_STATE" ]]; then
        return
    fi

    local prev
    IFS='|' read -ra PREV_ISSUES <<< "$PREVIOUS_STATE"
    for prev in "${PREV_ISSUES[@]}"; do
        [[ -z "$prev" ]] && continue
        if ! echo "$CURRENT_ISSUES" | grep -q "$prev" 2>/dev/null; then
            local desc=""
            case "$prev" in
                exposed_port_*) desc="Puerto expuesto cerrado (${prev#exposed_port_})" ;;
                shady_proc_*) desc="Proceso sospechoso eliminado (PID ${prev#shady_proc_})" ;;
                container_tmp_*) desc="Binarios sospechosos limpiados (${prev#container_tmp_})" ;;
                high_cpu_*) desc="CPU normalizada (PID ${prev#high_cpu_})" ;;
                ram_*) desc="Memoria estabilizada" ;;
                disk_*) desc="Espacio en disco recuperado" ;;
                fail2ban_down) desc="fail2ban restaurado" ;;
                containers_*) desc="Contenedores estabilizados" ;;
                crontab_*) desc="Crontab verificado (${prev#crontab_})" ;;
                new_user_*) desc="Usuario sospechoso resuelto (${prev#new_user_})" ;;
                ssh_keys_*) desc="SSH keys verificadas" ;;
                mining_outbound) desc="Conexiones a pools de minería cerradas" ;;
                high_conn_*) desc="Conexiones masivas normalizadas (${prev#high_conn_})" ;;
                new_port_*) desc="Puerto no autorizado cerrado (${prev#new_port_})" ;;
                suid_suspicious) desc="Binarios SUID sospechosos resueltos" ;;
                *) desc="Problema resuelto: $prev" ;;
            esac
            RECOVERED="${RECOVERED}✅ ${desc}\n"
        fi
    done
}

# ============================================================
# RUN ALL CHECKS
# ============================================================

ALL_CHECKS="check_exposed_ports check_shady_processes check_container_tmp check_high_cpu check_ram check_disk check_fail2ban check_containers check_crontabs check_users_and_keys check_outbound check_new_ports check_suid check_ssh_logins"
for check in ${HORNET_CHECKS:-$ALL_CHECKS}; do
    if [[ " $ALL_CHECKS " == *" $check "* ]]; then
        "$check"
    else
        log_error "unknown check in HORNET_CHECKS: $check"
    fi
done
check_recovered

# ============================================================
# BUILD AND SEND MESSAGE
# ============================================================

# Nothing changed: log the heartbeat and exit without sending
if [[ "$CURRENT_ISSUES" == "$PREVIOUS_STATE" && -z "$RECOVERED" ]]; then
    if [[ "$DELIVERY_FAILED" -eq 1 ]]; then healthcheck_ping fail; else healthcheck_ping ok; fi
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Hornet scan complete. Issues: ${CURRENT_ISSUES:-none}"
    exit 0
fi

# Only send if there are new alerts, warnings, or recoveries
# Don't re-alert if issues haven't changed
NOTIFY_LEVEL=""
NOTIFY_TITLE=""
if [[ -n "$ALERTS" ]]; then
    MESSAGE="He detectado intrusos en Hallownest.\n\n"
    MESSAGE+="$ALERTS"

    if [[ -n "$WARNINGS" ]]; then
        MESSAGE+="$WARNINGS"
    fi

    MESSAGE+="No subestimes estas grietas. Actúa antes de que la infección se propague.\n\n"
    MESSAGE+="Hornet vigila. Hallownest no caerá.\n"
    MESSAGE+="Servidor: ${HOSTNAME} | ${NOW}"

    NOTIFY_LEVEL="alert"
    NOTIFY_TITLE="HORNET — Shaw!"

elif [[ -n "$WARNINGS" ]]; then
    MESSAGE="He encontrado grietas en las defensas de Hallownest.\n\n"
    MESSAGE+="$WARNINGS"
    MESSAGE+="No son amenazas inmediatas, pero no bajes la guardia.\n\n"
    MESSAGE+="Hornet vigila. Siempre.\n"
    MESSAGE+="Servidor: ${HOSTNAME} | ${NOW}"

    NOTIFY_LEVEL="warning"
    NOTIFY_TITLE="HORNET — Hegale!"

elif [[ -n "$RECOVERED" ]]; then
    MESSAGE="La amenaza ha sido contenida.\n\n"
    MESSAGE+="$RECOVERED\n"
    MESSAGE+="No bajes la guardia. Yo no lo haré.\n\n"
    MESSAGE+="Hallownest permanece protegido.\n"
    MESSAGE+="Servidor: ${HOSTNAME} | ${NOW}"

    NOTIFY_LEVEL="recovered"
    NOTIFY_TITLE="HORNET — Adurá!"
fi

# Send first, save state only on delivery — a failed send keeps the
# previous state so the next run retries instead of losing the alert
if [[ -z "$NOTIFY_LEVEL" ]]; then
    save_state "$CURRENT_ISSUES"
elif deliver "$NOTIFY_LEVEL" "$NOTIFY_TITLE" "$(echo -e "$MESSAGE")" "$CURRENT_ISSUES"; then
    save_state "$CURRENT_ISSUES"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: notification failed — state NOT saved, will retry on next run" >&2
fi

if [[ "$DELIVERY_FAILED" -eq 1 ]]; then healthcheck_ping fail; else healthcheck_ping ok; fi
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Hornet scan complete. Issues: ${CURRENT_ISSUES:-none}"
