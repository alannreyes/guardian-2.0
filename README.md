# 🛡️ Luxia Guardian 2.0

Sistema de seguridad y monitoreo proactivo para infraestructura VPS con IA.

## ✨ Características

- **🔭 Sentinel**: Daemon 24/7 de monitoreo en tiempo real
- **🧠 IOC Manager**: Base de datos de indicadores de compromiso (21,500+ IOCs)
- **🤖 LLM Analyzer**: Análisis inteligente con Claude
- **⚡ Auto-Remediation**: Respuesta automática a amenazas
- **📱 Telegram Assistant**: Gestión por lenguaje natural
- **📧 Multi-channel Alerts**: Telegram, Email, Webhook

## Instalación Rápida

```bash
# En el servidor
cd /tmp
git clone https://github.com/luxia-us/guardian.git
cd guardian
sudo ./scripts/install.sh --server-name "mi-servidor"
```

## Configuración

1. Editar `/opt/luxia/guardian/config.yaml`
2. Agregar API keys en `/opt/luxia/guardian/secrets/keys.yaml`:

```yaml
anthropic_api_key: "sk-ant-..."
sendgrid_api_key: "SG...."
telegram_bot_token: "123456:ABC..."
```

3. Configurar chat de Telegram en config.yaml

## Uso

```bash
# Verificación rápida de seguridad
guardian check

# Iniciar daemon de monitoreo
guardian sentinel

# Actualizar IOCs
guardian update-iocs

# Ver estado
guardian status

# Probar notificaciones
guardian test-notify
```

## Servicio Systemd

```bash
# Iniciar daemon
sudo systemctl start guardian-sentinel

# Habilitar al inicio
sudo systemctl enable guardian-sentinel

# Ver logs
journalctl -u guardian-sentinel -f
```

## Arquitectura

```
/opt/luxia/guardian/
├── guardian.py          # Script principal
├── config.yaml          # Configuración
├── core/                # Módulos core
│   ├── config.py        # Manejo de config
│   └── logger.py        # Sistema de logging
├── modules/             # Módulos de funcionalidad
│   ├── ioc_manager.py   # Gestión de IOCs
│   ├── llm_analyzer.py  # Análisis con Claude
│   ├── notifier.py      # Notificaciones
│   ├── remediator.py    # Auto-remediación
│   └── sentinel.py      # Daemon de monitoreo
├── data/                # Datos persistentes
│   └── iocs.db          # Base de datos SQLite
├── logs/                # Logs
├── secrets/             # API keys (permisos 600)
└── quarantine/          # Archivos en cuarentena
```

## Características

### Detección
- Procesos sospechosos (cryptominers, backdoors)
- Conexiones a pools de minería
- Archivos ejecutables en /tmp
- Anomalías en contenedores Docker
- Picos de CPU/memoria

### Respuesta
- Kill de procesos maliciosos
- Detención de contenedores comprometidos
- Bloqueo de IPs maliciosas
- Cuarentena de archivos
- Alertas inmediatas

### Inteligencia
- ThreatFox (abuse.ch)
- AbuseIPDB
- Blocklist.de
- Feodo Tracker
- Patrones locales personalizados

## 🤖 Telegram AI Assistant

Gestiona tu infraestructura con lenguaje natural:

```
Tú: ¿Cómo están los servidores?
Guardian: 🖥️ VMI2959779 - 🛡️ 95/100 EXCELENTE
         💻 CPU 12% 🧠 RAM 45% 💾 Disk 52%
         ¿Quieres ver los contenedores o un scan de seguridad?

Tú: Lista los contenedores
Guardian: 🐳 12 running, 2 stopped
         [lista visual]
         ¿Reviso los logs de alguno?

Tú: Desbloquea la IP 192.168.1.100
Guardian: ✅ IP desbloqueada de fail2ban
         ¿La agrego a la whitelist permanente?
```

### Capacidades del Assistant

| Categoría | Comandos |
|-----------|----------|
| **Status** | Estado servidores, recursos, uptime |
| **Docker** | Listar, stats, logs, start/stop, backup/restore |
| **Seguridad** | Scan, ban/unban IPs, whitelist, reportes |
| **Mantenimiento** | Prune, actualizar imágenes, docker-compose |

### Iniciar Assistant

```bash
sudo systemctl start guardian-assistant
sudo systemctl enable guardian-assistant
```

## 📊 Dashboard Visual

Los reportes incluyen:
- Progress bars visuales para CPU/RAM/Disco
- Score de salud del servidor (0-100)
- Alertas con código de colores (🟢🟡🔴)
- Resumen ejecutivo generado por IA

## Licencia

MIT - Luxia.us 2026
