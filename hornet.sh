#!/bin/bash
# ============================================================
# 🕸️ HORNET — Guardiana de Hallownest
# Server security monitor with push alerts via ntfy
# ============================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.json"
STATE_FILE="/tmp/.hornet-state"
HOSTNAME=$(hostname)
NOW=$(date '+%Y-%m-%d %H:%M')

# --- Load NTFY_TOKEN ---
# Priority: 1) already set in environment, 2) ~/.config/hornet/credentials, 3) legacy .hornet.env
CREDENTIALS_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/hornet/credentials"
if [[ -z "${NTFY_TOKEN:-}" ]]; then
    if [[ -f "$CREDENTIALS_FILE" ]]; then
        source "$CREDENTIALS_FILE"
    elif [[ -f "$SCRIPT_DIR/.hornet.env" ]]; then
        source "$SCRIPT_DIR/.hornet.env"
    fi
fi
# Always define NTFY_TOKEN (even empty) to avoid nounset errors
NTFY_TOKEN="${NTFY_TOKEN:-}"

# --- Load JSON config ---
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: $CONFIG_FILE not found. Run 'hornet init' to create it."
    exit 1
fi
_jq() { jq -r "$1" "$CONFIG_FILE"; }

# Notification settings (token comes from .hornet.env)
NTFY_URL=$(_jq '.notifications.url')
NTFY_TOPIC=$(_jq '.notifications.topic')
NTFY_ICON=$(_jq '.notifications.icon')

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

# --- Send push notification via ntfy ---
send_ntfy() {
    local title="$1"
    local message="$2"
    local priority="${3:-default}"
    local tags="${4:-}"
    curl -s --max-time 10 \
        -H "Authorization: Bearer ${NTFY_TOKEN}" \
        -H "Title: ${title}" \
        -H "Priority: ${priority}" \
        -H "Tags: ${tags}" \
        -H "Icon: ${NTFY_ICON}" \
        -d "$message" \
        "${NTFY_URL}/${NTFY_TOPIC}" > /dev/null 2>&1 || true
}

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
    new_keys=$(find /home /root -name authorized_keys 2>/dev/null || true)
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

check_exposed_ports
check_shady_processes
check_container_tmp
check_high_cpu
check_ram
check_disk
check_fail2ban
check_containers
check_crontabs
check_users_and_keys
check_outbound
check_new_ports
check_suid
check_recovered

# ============================================================
# BUILD AND SEND MESSAGE
# ============================================================

# Save current state
save_state "$CURRENT_ISSUES"

# Only send if there are new alerts, warnings, or recoveries
# Don't re-alert if issues haven't changed
if [[ "$CURRENT_ISSUES" == "$PREVIOUS_STATE" && -z "$RECOVERED" ]]; then
    exit 0
fi

if [[ -n "$ALERTS" ]]; then
    MESSAGE="He detectado intrusos en Hallownest.\n\n"
    MESSAGE+="$ALERTS"

    if [[ -n "$WARNINGS" ]]; then
        MESSAGE+="$WARNINGS"
    fi

    MESSAGE+="No subestimes estas grietas. Actúa antes de que la infección se propague.\n\n"
    MESSAGE+="Hornet vigila. Hallownest no caerá.\n"
    MESSAGE+="Servidor: ${HOSTNAME} | ${NOW}"

    send_ntfy "HORNET — Shaw!" "$(echo -e "$MESSAGE")" "urgent" "rotating_light,skull"

elif [[ -n "$WARNINGS" ]]; then
    MESSAGE="He encontrado grietas en las defensas de Hallownest.\n\n"
    MESSAGE+="$WARNINGS"
    MESSAGE+="No son amenazas inmediatas, pero no bajes la guardia.\n\n"
    MESSAGE+="Hornet vigila. Siempre.\n"
    MESSAGE+="Servidor: ${HOSTNAME} | ${NOW}"

    send_ntfy "HORNET — Hegale!" "$(echo -e "$MESSAGE")" "high" "warning"

elif [[ -n "$RECOVERED" ]]; then
    MESSAGE="La amenaza ha sido contenida.\n\n"
    MESSAGE+="$RECOVERED\n"
    MESSAGE+="No bajes la guardia. Yo no lo haré.\n\n"
    MESSAGE+="Hallownest permanece protegido.\n"
    MESSAGE+="Servidor: ${HOSTNAME} | ${NOW}"

    send_ntfy "HORNET — Adurá!" "$(echo -e "$MESSAGE")" "default" "white_check_mark,shield"
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Hornet scan complete. Issues: ${CURRENT_ISSUES:-none}"
