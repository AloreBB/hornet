# 🕸️ Hornet

[🇬🇧 English](README.en.md)

> *Hornet vigila. Hallownest no caerá.*

Monitor de seguridad ligero para servidores Linux. Corre cada 15 minutos, detecta amenazas y envía alertas push via [ntfy](https://ntfy.sh).

![Hornet CLI](https://raw.githubusercontent.com/AloreBB/hornet/main/static/hornet-head.png)

## ¿Qué detecta?

| Check | Qué dispara la alerta |
|-------|----------------------|
| 🔌 Puertos de BD expuestos | PostgreSQL, MySQL, MongoDB, Redis abiertos a `0.0.0.0` |
| 🦠 Procesos sospechosos | Ejecutables corriendo desde `/tmp`, `/dev/shm`, `/var/tmp` |
| 🐳 Infección en contenedores | Binarios sospechosos dentro del `/tmp` de un contenedor |
| 🔥 CPU disparada | Procesos consumiendo >150% CPU por más de 1 minuto |
| 💾 RAM / Disco | Uso por encima de los umbrales configurados |
| 🛡️ fail2ban caído | Detecta si la protección anti fuerza bruta se apaga |
| 🔄 Estado de contenedores | Loops de reinicio y contenedores muertos |
| ⏰ Cambios en crontab | Cron jobs nuevos o modificados (detección de persistencia) |
| 👤 Nuevos usuarios / SSH keys | Detección de backdoors |
| 📡 Conexiones a pools de minería | Tráfico saliente a puertos de minería de criptomonedas |
| 🚪 Puertos nuevos abiertos | Puertos que no estaban en tu línea base |
| 🔐 Binarios SUID sospechosos | Detección de escalada de privilegios |

## Requisitos

- `bash`, `jq`, `docker`
- [`gum`](https://github.com/charmbracelet/gum) — se instala automáticamente con `install.sh`
- Servidor [ntfy](https://ntfy.sh) (instancia pública gratuita o self-hosted)

## Instalación

```bash
curl -fsSL https://raw.githubusercontent.com/AloreBB/hornet/main/install.sh | bash
```

El instalador:
1. Instala `jq` y `gum` si no están presentes
2. Copia Hornet a `~/.hornet/`
3. Agrega `hornet` a tu `PATH`
4. Lanza el wizard de configuración interactivo

## Configuración

```bash
hornet init     # crea hornet.json desde cero
hornet setup    # wizard interactivo (ntfy, listas blancas)
```

El repo ya incluye `config.json` con valores de ejemplo. Solo edítalo con tus datos:

```bash
hornet setup    # recomendado: wizard interactivo
# o edita config.json directamente
```

El token de ntfy va en `.hornet.env` (se crea automáticamente, está en `.gitignore`):

```bash
NTFY_TOKEN=tu_token_aqui
```

## Uso

```bash
# Ejecutar un scan ahora
hornet run

# Ver historial de scans
hornet status

# Gestionar lista blanca (interactivo)
hornet whitelist

# Gestionar lista blanca (comandos directos)
hornet whitelist list
hornet whitelist add port 25565        # servidor de Minecraft
hornet whitelist add process java      # apps JVM
hornet whitelist add container miapp   # saltar check de /tmp para un contenedor
hornet whitelist add ext dylib         # extensión segura adicional

hornet whitelist remove port 8080
```

## Estructura de `hornet.json`

```json
{
  "notifications": {
    "url": "https://ntfy.sh",
    "topic": "mis-alertas",
    "icon": ""
  },
  "baseline": {
    "users": ["root:/bin/bash", "miusuario:/bin/bash"],
    "ssh_keys": ["/home/miusuario/.ssh/authorized_keys:1"],
    "crontabs": ["miusuario:HASH_MD5"]
  },
  "whitelist": {
    "ports": [22, 80, 443],
    "processes": [],
    "containers": [],
    "extensions": ["so", "py", "sh"]
  }
}
```

### `baseline` — línea base del sistema

Define el estado **conocido y legítimo** de tu servidor. Si algo cambia respecto a estos valores, Hornet alerta.

| Campo | Qué monitorea |
|-------|--------------|
| `users` | Usuarios con shell de login (`user:shell`). Alerta si aparece uno nuevo. |
| `ssh_keys` | Número de claves en `authorized_keys` (`archivo:cantidad`). Alerta si se agregan claves. |
| `crontabs` | Hash MD5 del crontab de cada usuario. Alerta si alguien lo modifica. |

Para obtener el hash de tu crontab actual:

```bash
crontab -l | md5sum | cut -d' ' -f1
```

### `whitelist` — excepciones conocidas

| Campo | Qué ignora |
|-------|-----------|
| `ports` | Puertos abiertos a internet que son legítimos |
| `processes` | Procesos que pueden consumir mucha CPU sin ser malware |
| `containers` | Contenedores que extraen binarios a `/tmp` legítimamente |
| `extensions` | Extensiones de archivo a ignorar en checks de `/tmp` |

## Scans automáticos (cron)

Agrega a tu crontab (`crontab -e`):

```cron
*/15 * * * * /ruta/a/hornet/hornet.sh >> /ruta/a/hornet/hornet.log 2>&1
```

El instalador configura esto automáticamente.

## Actualizando la línea base

Cuando hagas un cambio legítimo en tu servidor (abrir un nuevo puerto, editar el cron, agregar una SSH key), actualiza la línea base para que Hornet deje de alertar:

```bash
# Recalcular hash del crontab después de editarlo
crontab -l | md5sum | cut -d' ' -f1
# Luego actualiza hornet.json → baseline.crontabs

# O simplemente vuelve a correr el setup
hornet setup
```

## Las alertas se ven así (via ntfy)

**🔴 Alerta crítica:**
> ⚔️ PUERTO EXPUESTO — Puerto 5432 (PostgreSQL) abierto a internet en contenedor "mydb". Ciérralo YA.

**🟡 Advertencia:**
> 🟡 MEMORIA — RAM al 87% (20G/23G). Mayores consumidores: node (2.1GB), postgres (1.4GB)...

**✅ Recuperado:**
> ✅ Puerto expuesto cerrado (mydb)

## Licencia

MIT — ver [LICENSE](LICENSE)

---

*El nombre es un homenaje a Hornet de [Hollow Knight](https://www.hollowknight.com/) — la guardiana de Hallownest.*
