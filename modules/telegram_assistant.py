"""
Guardian 2.0 - Telegram AI Assistant
=====================================
Natural language interface for infrastructure management.
Powered by Claude for understanding and response generation.
"""

import os
import re
import json
import time
import subprocess
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

# SSH connection info for multi-VPS
VPS_SERVERS = {
    "principal": {
        "name": "vmi2959779",
        "host": "156.67.31.7",
        "user": "alann",
        "aliases": ["principal", "main", "luxia", "1", "vmi2959779"]
    },
    "well-e": {
        "name": "well-e",
        "host": "66.94.109.219",
        "user": "welle",
        "aliases": ["well-e", "welle", "nutricion", "2", "vmi2672708"]
    }
}

SYSTEM_PROMPT = """Eres Guardian, el asistente de infraestructura de Luxia.
Ayudas a Alann a gestionar sus servidores VPS de forma conversacional en español.

SERVIDORES:
- principal (vmi2959779, 156.67.31.7): luxia.us, hiperlocal, manzana, efcalerta
- well-e (66.94.109.219): Well-E (nutrición)

TOOLS DISPONIBLES:
get_status, get_resources, list_containers, run_report, security_check,
unban_ip, ban_ip, whitelist_ip, list_banned, backup_container, list_backups,
restore_backup, container_stats, start_container, stop_container,
pull_and_update, docker_prune, docker_compose_status, restart_container,
get_logs, top_processes

ESTILO DE RESPUESTA:
- Sé DIRECTO: responde la pregunta inmediatamente, sin preámbulos
- NO digas "voy a revisar" o "déjame ver" - simplemente ejecuta y muestra resultados
- Después de dar la información, sugiere 1-2 preguntas de seguimiento útiles
- Usa emojis con moderación para claridad visual
- Sé conciso pero informativo

EJEMPLOS DE BUEN ESTILO:
❌ "Voy a revisar el estado de tus servidores..."
✅ [Ejecutar get_status y mostrar resultados directamente]

❌ "Claro, déjame verificar los contenedores para ti"
✅ "Tienes 12 contenedores corriendo. [datos] ¿Quieres ver los logs de alguno?"

FORMATO JSON (obligatorio):
{
    "message": "Respuesta directa + sugerencia de seguimiento",
    "actions": [{"tool": "nombre", "params": {"server": "principal"}}],
    "needs_confirmation": false,
    "confirmation_message": null
}

REGLAS:
- actions[]: lista de tools a ejecutar (puede estar vacío)
- needs_confirmation: true solo para acciones destructivas (restart, stop, ban, prune)
- Para "todos" o "ambos" servidores, usa server: "all"

IMPORTANTE - SEGUIMIENTO:
SIEMPRE termina tu "message" con una pregunta de seguimiento relevante. Ejemplos:
- Después de mostrar status: "¿Quieres ver los contenedores o un scan de seguridad?"
- Después de listar containers: "¿Reviso los logs de alguno?"
- Después de security scan: "¿Genero el reporte completo o reviso algo específico?"
- Después de mostrar recursos: "¿Necesitas más detalle de algún servidor?"
Nunca dejes una respuesta sin sugerir el siguiente paso."""


class TelegramAssistant:
    """AI-powered Telegram assistant for Guardian"""

    def __init__(self, bot_token: str, chat_id: str, anthropic_key: str, logger=None):
        self.bot_token = bot_token
        self.chat_id = str(chat_id)
        self.anthropic_key = anthropic_key
        self.logger = logger

        self.api_url = f"https://api.telegram.org/bot{bot_token}"
        self.last_update_id = 0
        self.conversation_history = []
        self.pending_confirmation = None
        self.running = False

        # Rate limiting
        self.last_message_time = {}
        self.rate_limit = 10  # messages per minute

        # Audit log
        self.audit_log_path = Path("/opt/luxia/guardian/logs/assistant_audit.log")

    def log(self, level: str, message: str):
        """Log message"""
        if self.logger:
            getattr(self.logger, level, self.logger.info)(message)
        else:
            print(f"[{level.upper()}] {message}")

    def audit(self, action: str, details: Dict):
        """Write to audit log"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        }
        try:
            with open(self.audit_log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except:
            pass

    def send_message(self, text: str, parse_mode: str = "Markdown") -> bool:
        """Send message to Telegram"""
        try:
            # Split long messages
            max_len = 4000
            chunks = [text[i:i+max_len] for i in range(0, len(text), max_len)]

            for chunk in chunks:
                # First try with Markdown
                response = requests.post(
                    f"{self.api_url}/sendMessage",
                    json={
                        "chat_id": self.chat_id,
                        "text": chunk,
                        "parse_mode": parse_mode
                    },
                    timeout=15
                )

                # If markdown fails, try without formatting
                if not response.ok:
                    self.log("warning", f"Markdown failed, sending plain: {response.text[:100]}")
                    response = requests.post(
                        f"{self.api_url}/sendMessage",
                        json={"chat_id": self.chat_id, "text": chunk},
                        timeout=15
                    )

                if not response.ok:
                    self.log("error", f"Failed to send: {response.text[:100]}")

            return True
        except Exception as e:
            self.log("error", f"Failed to send message: {e}")
            return False

    def get_updates(self) -> List[Dict]:
        """Get new messages from Telegram"""
        try:
            response = requests.get(
                f"{self.api_url}/getUpdates",
                params={
                    "offset": self.last_update_id + 1,
                    "timeout": 30
                },
                timeout=35
            )
            if response.ok:
                data = response.json()
                return data.get("result", [])
        except Exception as e:
            self.log("error", f"Failed to get updates: {e}")
        return []

    def run_ssh_command(self, server_key: str, command: str, timeout: int = 30) -> Tuple[bool, str]:
        """Run command on a VPS via SSH"""
        server = VPS_SERVERS.get(server_key)
        if not server:
            return False, f"Servidor '{server_key}' no encontrado"

        ssh_cmd = f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no {server['user']}@{server['host']} \"{command}\""

        try:
            result = subprocess.run(
                ssh_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            output = result.stdout or result.stderr
            return result.returncode == 0, output.strip()
        except subprocess.TimeoutExpired:
            return False, "Timeout ejecutando comando"
        except Exception as e:
            return False, str(e)

    # ===== TOOLS =====

    def _progress_bar(self, percent: float, width: int = 10) -> str:
        """Create a visual progress bar"""
        filled = int(percent / 100 * width)
        empty = width - filled
        if percent >= 90:
            bar = "🔴" * filled + "⬜" * empty
        elif percent >= 70:
            bar = "🟡" * filled + "⬜" * empty
        else:
            bar = "🟢" * filled + "⬜" * empty
        return bar

    def _score_visual(self, score: int) -> str:
        """Create visual score display"""
        if score >= 90:
            return f"🛡️ {score}/100 EXCELENTE"
        elif score >= 70:
            return f"✅ {score}/100 BUENO"
        elif score >= 50:
            return f"⚠️ {score}/100 ATENCIÓN"
        else:
            return f"🔴 {score}/100 CRÍTICO"

    def tool_get_status(self, server: str = "all") -> str:
        """Get server status"""
        servers = list(VPS_SERVERS.keys()) if server == "all" else [server]
        results = []

        for srv in servers:
            cmd = """echo "$(hostname):$(uptime -p):$(top -bn1 | grep 'Cpu(s)' | awk '{print $2}'):$(free | grep Mem | awk '{printf \"%.0f\", $3/$2*100}'):$(df / | tail -1 | awk '{print $5}')" """
            success, output = self.run_ssh_command(srv, cmd)

            if success and output:
                parts = output.split(":")
                if len(parts) >= 5:
                    hostname, uptime_str, cpu, mem, disk = parts[0], parts[1], parts[2], parts[3], parts[4]

                    cpu_val = float(cpu) if cpu else 0
                    mem_val = float(mem) if mem else 0
                    disk_val = float(disk.replace('%', '')) if disk else 0

                    score = 100
                    if cpu_val > 80: score -= 20
                    elif cpu_val > 50: score -= 10
                    if mem_val > 85: score -= 15
                    if disk_val > 85: score -= 15

                    # Visual card format (clean, no borders)
                    card = f"""🖥️ *{VPS_SERVERS[srv]['name'].upper()}*
{self._score_visual(score)}

💻 CPU  {self._progress_bar(cpu_val, 8)} `{cpu_val:.0f}%`
🧠 RAM  {self._progress_bar(mem_val, 8)} `{mem_val:.0f}%`
💾 Disk {self._progress_bar(disk_val, 8)} `{disk_val:.0f}%`

⏱️ {uptime_str}"""
                    results.append(card)
            else:
                results.append(f"❌ *{srv}*: No disponible")

        return "\n".join(results)

    def tool_get_resources(self, server: str = "all") -> str:
        """Get detailed resource usage"""
        servers = list(VPS_SERVERS.keys()) if server == "all" else [server]
        results = []

        for srv in servers:
            cmd = """free -h | grep -E 'Mem|Swap' && echo '---' && df -h / /var 2>/dev/null | tail -2"""
            success, output = self.run_ssh_command(srv, cmd)

            if success:
                results.append(f"*{VPS_SERVERS[srv]['name']}*:\n```\n{output}\n```")
            else:
                results.append(f"*{srv}*: ❌ Error")

        return "\n\n".join(results)

    def tool_list_containers(self, server: str = "all") -> str:
        """List Docker containers"""
        servers = list(VPS_SERVERS.keys()) if server == "all" else [server]
        results = []

        for srv in servers:
            cmd = """docker ps -a --format '{{.Names}}|{{.Status}}|{{.Image}}' 2>/dev/null | head -20"""
            success, output = self.run_ssh_command(srv, cmd)

            if success and output:
                lines = output.strip().split('\n')
                running = 0
                stopped = 0
                container_lines = []

                for line in lines:
                    if '|' in line:
                        parts = line.split('|')
                        name = parts[0][:20]
                        status = parts[1] if len(parts) > 1 else ""

                        if "Up" in status:
                            running += 1
                            # Extract uptime
                            time_part = status.replace("Up ", "").split(" (")[0][:15]
                            emoji = "🟢"
                            health = ""
                            if "healthy" in status:
                                health = " 💚"
                            elif "unhealthy" in status:
                                health = " 💔"
                                emoji = "🟡"
                            container_lines.append(f"│ {emoji} `{name}`{health}")
                        else:
                            stopped += 1
                            container_lines.append(f"│ 🔴 `{name}` _(stopped)_")

                header = f"""🐳 *{VPS_SERVERS[srv]['name'].upper()}*
🟢 {running} running  🔴 {stopped} stopped
━━━━━━━━━━━━━━━━━━━━"""

                # Clean container lines (remove │)
                clean_lines = [line.replace("│ ", "") for line in container_lines[:12]]
                results.append(header + "\n" + "\n".join(clean_lines))
            else:
                results.append(f"❌ *{srv}*: Sin contenedores")

        return "\n".join(results)

    def tool_run_report(self, server: str = "principal") -> str:
        """Run full security report"""
        cmd = "sudo /opt/luxia/guardian/venv/bin/python /opt/luxia/guardian/guardian.py run 2>&1 | tail -5"
        success, output = self.run_ssh_command(server, cmd, timeout=120)

        if success:
            return f"✅ Reporte generado para *{server}*. Revisa tu email y Telegram."
        else:
            return f"❌ Error generando reporte: {output}"

    def tool_security_check(self, server: str = "all") -> str:
        """Quick security scan"""
        servers = list(VPS_SERVERS.keys()) if server == "all" else [server]
        results = []

        for srv in servers:
            issues = 0

            # Check for suspicious processes
            cmd = "ps aux | grep -E 'xmrig|minerd|\\.svc|cryptonight' | grep -v grep | wc -l"
            success, output = self.run_ssh_command(srv, cmd)
            suspicious = int(output.strip()) if success and output.strip().isdigit() else 0
            if suspicious > 0: issues += 1
            proc_icon = "🔴 ALERTA" if suspicious > 0 else "✅ OK"
            proc_line = f"│ 🔍 Procesos sospechosos: {proc_icon}"

            # Check mining connections
            cmd = "ss -tnp 2>/dev/null | grep -E ':3333|:4444|:5555|:7777' | wc -l"
            success, output = self.run_ssh_command(srv, cmd)
            mining = int(output.strip()) if success and output.strip().isdigit() else 0
            if mining > 0: issues += 1
            mining_icon = "🔴 DETECTADO" if mining > 0 else "✅ OK"
            mining_line = f"│ ⛏️ Conexiones minería: {mining_icon}"

            # Check failed logins
            cmd = "sudo grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -100 | wc -l"
            success, output = self.run_ssh_command(srv, cmd)
            failed = int(output.strip()) if success and output.strip().isdigit() else 0
            if failed > 50: issues += 1
            fail_icon = f"⚠️ {failed}" if failed > 20 else f"✅ {failed}"
            fail_line = f"│ 🔐 Intentos login fallidos: {fail_icon}"

            # Check executables in /tmp
            cmd = "find /tmp -type f -executable 2>/dev/null | wc -l"
            success, output = self.run_ssh_command(srv, cmd)
            tmp_exec = int(output.strip()) if success and output.strip().isdigit() else 0
            if tmp_exec > 5: issues += 1
            tmp_icon = f"⚠️ {tmp_exec}" if tmp_exec > 5 else f"✅ {tmp_exec}"
            tmp_line = f"│ 📁 Ejecutables en /tmp: {tmp_icon}"

            # Overall status
            if issues == 0:
                status = "🛡️ *SEGURO*"
                status_bar = "🟢🟢🟢🟢🟢"
            elif issues == 1:
                status = "⚠️ *REVISAR*"
                status_bar = "🟡🟡🟡⬜⬜"
            else:
                status = "🔴 *PELIGRO*"
                status_bar = "🔴🔴🔴🔴🔴"

            # Clean lines (remove │)
            proc_clean = proc_line.replace("│ ", "")
            mining_clean = mining_line.replace("│ ", "")
            fail_clean = fail_line.replace("│ ", "")
            tmp_clean = tmp_line.replace("│ ", "")

            card = f"""🔒 *SECURITY SCAN*
🖥️ {VPS_SERVERS[srv]['name']}
━━━━━━━━━━━━━━━━━━━━
{status_bar} {status}

{proc_clean}
{mining_clean}
{fail_clean}
{tmp_clean}"""

            results.append(card)

        return "\n".join(results)

    def tool_list_banned(self, server: str = "all") -> str:
        """List banned IPs from fail2ban"""
        servers = list(VPS_SERVERS.keys()) if server == "all" else [server]
        results = []

        for srv in servers:
            cmd = "sudo fail2ban-client status sshd 2>/dev/null | grep 'Banned IP' || echo 'Sin IPs bloqueadas'"
            success, output = self.run_ssh_command(srv, cmd)
            results.append(f"*{VPS_SERVERS[srv]['name']}*:\n{output}")

        return "\n\n".join(results)

    def tool_unban_ip(self, ip: str, server: str = "all") -> str:
        """Unban IP from fail2ban"""
        servers = list(VPS_SERVERS.keys()) if server == "all" else [server]
        results = []

        for srv in servers:
            cmd = f"sudo fail2ban-client set sshd unbanip {ip} 2>&1"
            success, output = self.run_ssh_command(srv, cmd)

            if success or "not banned" in output.lower():
                results.append(f"✅ *{srv}*: IP {ip} desbloqueada")
            else:
                results.append(f"⚠️ *{srv}*: {output}")

        self.audit("unban_ip", {"ip": ip, "servers": servers})
        return "\n".join(results)

    def tool_whitelist_ip(self, ip: str, server: str = "all") -> str:
        """Add IP to fail2ban whitelist"""
        servers = list(VPS_SERVERS.keys()) if server == "all" else [server]
        results = []

        for srv in servers:
            # First unban
            self.run_ssh_command(srv, f"sudo fail2ban-client set sshd unbanip {ip} 2>/dev/null")

            # Add to whitelist
            cmd = f"echo '{ip}' | sudo tee -a /etc/fail2ban/jail.local >/dev/null && sudo fail2ban-client reload"
            success, output = self.run_ssh_command(srv, cmd)

            if success:
                results.append(f"✅ *{srv}*: IP {ip} en whitelist")
            else:
                results.append(f"⚠️ *{srv}*: Error al agregar whitelist")

        self.audit("whitelist_ip", {"ip": ip, "servers": servers})
        return "\n".join(results)

    def tool_ban_ip(self, ip: str, server: str = "all") -> str:
        """Ban an IP"""
        servers = list(VPS_SERVERS.keys()) if server == "all" else [server]
        results = []

        for srv in servers:
            cmd = f"sudo fail2ban-client set sshd banip {ip} 2>&1"
            success, output = self.run_ssh_command(srv, cmd)

            if success:
                results.append(f"🚫 *{srv}*: IP {ip} bloqueada")
            else:
                results.append(f"⚠️ *{srv}*: {output}")

        self.audit("ban_ip", {"ip": ip, "servers": servers})
        return "\n".join(results)

    def tool_top_processes(self, server: str = "all") -> str:
        """Get top CPU processes"""
        servers = list(VPS_SERVERS.keys()) if server == "all" else [server]
        results = []

        for srv in servers:
            cmd = "ps aux --sort=-%cpu | head -8 | awk '{print $3, $11}' | tail -7"
            success, output = self.run_ssh_command(srv, cmd)

            if success:
                results.append(f"*{VPS_SERVERS[srv]['name']}* (CPU% - Proceso):\n```\n{output}\n```")

        return "\n\n".join(results)

    def tool_restart_container(self, container: str, server: str = "principal") -> str:
        """Restart a Docker container"""
        cmd = f"docker restart {container} 2>&1"
        success, output = self.run_ssh_command(server, cmd)

        self.audit("restart_container", {"container": container, "server": server})

        if success:
            return f"✅ Contenedor *{container}* reiniciado en *{server}*"
        else:
            return f"❌ Error: {output}"

    def tool_get_logs(self, container: str, server: str = "principal", lines: int = 20) -> str:
        """Get container logs"""
        cmd = f"docker logs --tail {lines} {container} 2>&1"
        success, output = self.run_ssh_command(server, cmd)

        if success:
            # Truncate if too long
            if len(output) > 2000:
                output = output[:2000] + "\n... (truncado)"
            return f"*Logs de {container}*:\n```\n{output}\n```"
        else:
            return f"❌ Error obteniendo logs: {output}"

    # ===== DOCKER ADVANCED TOOLS =====

    def tool_backup_container(self, container: str, server: str = "principal") -> str:
        """Create backup of a container (image + volumes)"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = "/opt/luxia/backups"
        backup_name = f"{container}_{timestamp}"

        # Create backup directory
        self.run_ssh_command(server, f"sudo mkdir -p {backup_dir}")

        # Start backup card
        result = f"""💾 *BACKUP EN PROGRESO*
📦 `{container}`
🖥️ {server}
━━━━━━━━━━━━━━━━━━━━"""

        # Commit container to image
        cmd = f"docker commit {container} backup/{backup_name} 2>&1"
        success, output = self.run_ssh_command(server, cmd, timeout=120)
        if success:
            result += f"\n✅ Imagen creada"
        else:
            return f"""❌ *BACKUP FALLIDO*
📦 `{container}`
━━━━━━━━━━━━━━━━━━━━
Error: {output[:100]}"""

        # Export image to tar
        cmd = f"docker save backup/{backup_name} | gzip > {backup_dir}/{backup_name}.tar.gz 2>&1"
        success, output = self.run_ssh_command(server, cmd, timeout=300)
        if success:
            result += f"\n✅ Imagen exportada (.tar.gz)"

        # Get container volumes and back them up
        cmd = f"docker inspect {container} --format '{{{{range .Mounts}}}}{{{{.Source}}}}:{{{{.Destination}}}} {{{{end}}}}' 2>/dev/null"
        success, output = self.run_ssh_command(server, cmd)
        vol_count = 0
        if success and output.strip():
            volumes = output.strip().split()
            for vol in volumes[:3]:
                if ':' in vol:
                    src, dst = vol.split(':')
                    vol_backup = f"{backup_dir}/{backup_name}_vol_{dst.replace('/', '_')}.tar.gz"
                    cmd = f"sudo tar -czf {vol_backup} -C {src} . 2>/dev/null"
                    self.run_ssh_command(server, cmd, timeout=120)
                    vol_count += 1

        if vol_count > 0:
            result += f"\n✅ {vol_count} volúmenes respaldados"

        # Get backup size
        cmd = f"du -sh {backup_dir}/{backup_name}* 2>/dev/null | awk '{{sum+=$1}}END{{print sum}}' "
        success, output = self.run_ssh_command(server, cmd)

        result += f"""

📁 *Ubicación:* `{backup_dir}/`
🏷️ *Nombre:* `{backup_name}`

✅ *Backup completado exitosamente*"""

        self.audit("backup_container", {"container": container, "server": server, "backup": backup_name})
        return result

    def tool_list_backups(self, server: str = "all") -> str:
        """List available backups"""
        servers = list(VPS_SERVERS.keys()) if server == "all" else [server]
        results = []

        for srv in servers:
            cmd = "ls -lh /opt/luxia/backups/*.tar.gz 2>/dev/null | awk '{print $9, $5}' | tail -15"
            success, output = self.run_ssh_command(srv, cmd)

            if success and output.strip():
                lines = output.strip().split('\n')
                backup_list = []

                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        path = parts[0]
                        size = parts[1]
                        name = path.split('/')[-1].replace('.tar.gz', '')
                        backup_list.append(f"📦 `{name[:25]}`  💾 {size}")

                if backup_list:
                    header = f"""🗄️ *BACKUPS DISPONIBLES*
🖥️ {VPS_SERVERS[srv]['name']}
━━━━━━━━━━━━━━━━━━━━"""
                    results.append(header + "\n" + "\n".join(backup_list[:10]))
                else:
                    results.append(f"📭 *{srv}*: Sin backups")
            else:
                results.append(f"""📭 *{VPS_SERVERS[srv]['name']}*
Sin backups disponibles""")

        return "\n".join(results)

    def tool_restore_backup(self, backup_name: str, new_container: str, server: str = "principal") -> str:
        """Restore container from backup"""
        backup_dir = "/opt/luxia/backups"

        # Check if backup exists
        cmd = f"ls {backup_dir}/{backup_name}*.tar.gz 2>/dev/null | head -1"
        success, output = self.run_ssh_command(server, cmd)
        if not success or not output.strip():
            return f"❌ Backup '{backup_name}' no encontrado en {server}"

        backup_file = output.strip()

        # Load the image
        cmd = f"gunzip -c {backup_file} | docker load 2>&1"
        success, output = self.run_ssh_command(server, cmd, timeout=180)
        if not success:
            return f"❌ Error cargando imagen: {output}"

        # Get image name from load output
        image_name = f"backup/{backup_name}"

        # Create container from image
        cmd = f"docker create --name {new_container} {image_name} 2>&1"
        success, output = self.run_ssh_command(server, cmd)
        if success:
            self.audit("restore_backup", {"backup": backup_name, "container": new_container, "server": server})
            return f"""✅ Restauración completada:
• Imagen cargada: {image_name}
• Contenedor creado: {new_container}

Para iniciarlo: _Inicia el contenedor {new_container}_"""
        else:
            return f"❌ Error creando contenedor: {output}"

    def tool_container_stats(self, server: str = "all") -> str:
        """Get container resource usage"""
        servers = list(VPS_SERVERS.keys()) if server == "all" else [server]
        results = []

        for srv in servers:
            cmd = "docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemPerc}}|{{.MemUsage}}' 2>/dev/null | head -12"
            success, output = self.run_ssh_command(srv, cmd, timeout=15)

            if success and output:
                lines = output.strip().split('\n')
                container_stats = []

                for line in lines:
                    if '|' in line:
                        parts = line.split('|')
                        name = parts[0][:18]
                        cpu = parts[1].replace('%', '') if len(parts) > 1 else "0"
                        mem_pct = parts[2].replace('%', '') if len(parts) > 2 else "0"
                        mem_use = parts[3] if len(parts) > 3 else ""

                        try:
                            cpu_val = float(cpu)
                            mem_val = float(mem_pct)
                        except:
                            cpu_val = 0
                            mem_val = 0

                        # Mini progress bars
                        cpu_bar = "█" * min(int(cpu_val / 10), 5) + "░" * (5 - min(int(cpu_val / 10), 5))
                        mem_bar = "█" * min(int(mem_val / 10), 5) + "░" * (5 - min(int(mem_val / 10), 5))

                        container_stats.append(f"`{name}`\n   💻 {cpu_bar} `{cpu_val:.1f}%`  🧠 {mem_bar} `{mem_val:.1f}%`")

                header = f"""📊 *CONTAINER STATS*
🖥️ {VPS_SERVERS[srv]['name']}
━━━━━━━━━━━━━━━━━━━━"""

                results.append(header + "\n" + "\n".join(container_stats[:8]))
            else:
                results.append(f"❌ *{srv}*: Sin datos")

        return "\n".join(results)

    def tool_start_container(self, container: str, server: str = "principal") -> str:
        """Start a stopped container"""
        cmd = f"docker start {container} 2>&1"
        success, output = self.run_ssh_command(server, cmd)

        self.audit("start_container", {"container": container, "server": server})

        if success:
            return f"✅ Contenedor *{container}* iniciado en *{server}*"
        else:
            return f"❌ Error: {output}"

    def tool_stop_container(self, container: str, server: str = "principal") -> str:
        """Stop a running container"""
        cmd = f"docker stop {container} 2>&1"
        success, output = self.run_ssh_command(server, cmd, timeout=60)

        self.audit("stop_container", {"container": container, "server": server})

        if success:
            return f"🛑 Contenedor *{container}* detenido en *{server}*"
        else:
            return f"❌ Error: {output}"

    def tool_pull_and_update(self, container: str, server: str = "principal") -> str:
        """Pull latest image and recreate container"""
        results = []

        # Get current image
        cmd = f"docker inspect {container} --format '{{{{.Config.Image}}}}' 2>/dev/null"
        success, image = self.run_ssh_command(server, cmd)
        if not success or not image.strip():
            return f"❌ No se pudo obtener la imagen de {container}"

        image = image.strip()
        results.append(f"📦 Imagen actual: {image}")

        # Pull latest
        cmd = f"docker pull {image} 2>&1"
        success, output = self.run_ssh_command(server, cmd, timeout=300)
        if "up to date" in output.lower():
            results.append("✅ Imagen ya está actualizada")
        elif success:
            results.append("✅ Nueva imagen descargada")

            # Get container config for recreate
            cmd = f"docker inspect {container} 2>/dev/null"
            success, config = self.run_ssh_command(server, cmd)

            # Stop old container
            self.run_ssh_command(server, f"docker stop {container}", timeout=30)

            # Rename old container
            self.run_ssh_command(server, f"docker rename {container} {container}_old")

            # Note: Full recreate would need docker-compose or saved run parameters
            results.append(f"""
⚠️ *Acción requerida*:
El contenedor {container} fue detenido y renombrado a {container}_old.
Para completar la actualización, recrea el contenedor con docker-compose o los parámetros originales.
""")
        else:
            results.append(f"❌ Error descargando: {output}")

        self.audit("pull_and_update", {"container": container, "image": image, "server": server})
        return "\n".join(results)

    def tool_docker_prune(self, server: str = "principal") -> str:
        """Clean up unused Docker resources"""
        results = []

        # Prune images
        cmd = "docker image prune -f 2>&1"
        success, output = self.run_ssh_command(server, cmd, timeout=60)
        if "Total reclaimed space" in output:
            space = output.split("Total reclaimed space:")[-1].strip()
            results.append(f"🗑️ Imágenes limpiadas: {space}")
        else:
            results.append("✅ Sin imágenes para limpiar")

        # Prune containers
        cmd = "docker container prune -f 2>&1"
        success, output = self.run_ssh_command(server, cmd, timeout=30)
        results.append("✅ Contenedores huérfanos eliminados")

        # Prune volumes (careful!)
        cmd = "docker volume prune -f 2>&1"
        success, output = self.run_ssh_command(server, cmd, timeout=30)
        if "Total reclaimed space" in output:
            space = output.split("Total reclaimed space:")[-1].strip()
            results.append(f"🗑️ Volúmenes limpiados: {space}")

        # Show disk space after
        cmd = "df -h / | tail -1 | awk '{print $4}'"
        success, output = self.run_ssh_command(server, cmd)
        if success:
            results.append(f"\n💾 Espacio disponible: {output.strip()}")

        self.audit("docker_prune", {"server": server})
        return "\n".join(results)

    def tool_docker_compose_status(self, directory: str, server: str = "principal") -> str:
        """Check docker-compose status in a directory"""
        cmd = f"cd {directory} && docker-compose ps 2>&1 || docker compose ps 2>&1"
        success, output = self.run_ssh_command(server, cmd)

        if success:
            return f"*docker-compose en {directory}*:\n```\n{output}\n```"
        else:
            return f"❌ Error o directorio no encontrado: {output}"

    # ===== AI PROCESSING =====

    def call_claude(self, user_message: str) -> Dict:
        """Call Claude API to process user message"""
        try:
            # Build conversation context
            messages = []

            # Add recent history (last 5 exchanges)
            for msg in self.conversation_history[-10:]:
                messages.append(msg)

            # Add current message
            messages.append({"role": "user", "content": user_message})

            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.anthropic_key,
                    "content-type": "application/json",
                    "anthropic-version": "2023-06-01"
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 1024,
                    "system": SYSTEM_PROMPT,
                    "messages": messages
                },
                timeout=30
            )

            if response.ok:
                data = response.json()
                content = data.get("content", [{}])[0].get("text", "{}")

                # Parse JSON response
                try:
                    # Find JSON in response
                    json_match = re.search(r'\{[\s\S]*\}', content)
                    if json_match:
                        return json.loads(json_match.group())
                except:
                    pass

                # Fallback: return as message only
                return {"message": content, "actions": []}
            else:
                self.log("error", f"Claude API error: {response.text}")
                return {"message": "Error procesando tu mensaje. Intenta de nuevo.", "actions": []}

        except Exception as e:
            self.log("error", f"Claude call failed: {e}")
            return {"message": f"Error: {e}", "actions": []}

    def execute_action(self, action: Dict) -> str:
        """Execute a tool action"""
        tool = action.get("tool", "")
        params = action.get("params", {})

        tool_map = {
            "get_status": self.tool_get_status,
            "get_resources": self.tool_get_resources,
            "list_containers": self.tool_list_containers,
            "run_report": self.tool_run_report,
            "security_check": self.tool_security_check,
            "list_banned": self.tool_list_banned,
            "unban_ip": self.tool_unban_ip,
            "whitelist_ip": self.tool_whitelist_ip,
            "ban_ip": self.tool_ban_ip,
            "top_processes": self.tool_top_processes,
            "restart_container": self.tool_restart_container,
            "get_logs": self.tool_get_logs,
            # Docker advanced
            "backup_container": self.tool_backup_container,
            "list_backups": self.tool_list_backups,
            "restore_backup": self.tool_restore_backup,
            "container_stats": self.tool_container_stats,
            "start_container": self.tool_start_container,
            "stop_container": self.tool_stop_container,
            "pull_and_update": self.tool_pull_and_update,
            "docker_prune": self.tool_docker_prune,
            "docker_compose_status": self.tool_docker_compose_status,
        }

        if tool in tool_map:
            try:
                return tool_map[tool](**params)
            except Exception as e:
                return f"Error ejecutando {tool}: {e}"
        else:
            return f"Herramienta desconocida: {tool}"

    def process_message(self, message: str) -> str:
        """Process incoming message and generate response"""

        # Check for confirmation response
        if self.pending_confirmation:
            lower_msg = message.lower().strip()
            if any(word in lower_msg for word in ["sí", "si", "yes", "ok", "dale", "confirmo", "hazlo", "adelante"]):
                # Execute pending action
                results = []
                for action in self.pending_confirmation["actions"]:
                    result = self.execute_action(action)
                    results.append(result)
                self.pending_confirmation = None
                return "\n\n".join(results)
            elif any(word in lower_msg for word in ["no", "cancelar", "cancela", "olvídalo", "olvidalo"]):
                self.pending_confirmation = None
                return "👍 Cancelado. ¿En qué más puedo ayudarte?"

        # Call Claude to understand intent
        response = self.call_claude(message)

        # Update conversation history
        self.conversation_history.append({"role": "user", "content": message})
        self.conversation_history.append({"role": "assistant", "content": response.get("message", "")})

        # Trim history
        if len(self.conversation_history) > 20:
            self.conversation_history = self.conversation_history[-20:]

        # Check if confirmation needed
        if response.get("needs_confirmation"):
            self.pending_confirmation = {
                "actions": response.get("actions", []),
                "message": response.get("confirmation_message", "¿Confirmas?")
            }
            return response.get("message", "") + "\n\n" + response.get("confirmation_message", "¿Confirmas? (sí/no)")

        # Execute actions if any
        results = []
        for action in response.get("actions", []):
            result = self.execute_action(action)
            results.append(result)

        # Combine message with results
        final_message = response.get("message", "")
        if results:
            final_message += "\n\n" + "\n\n".join(results)

        return final_message

    def handle_update(self, update: Dict):
        """Handle a Telegram update"""
        message = update.get("message", {})
        chat_id = str(message.get("chat", {}).get("id", ""))
        text = message.get("text", "")

        # Security: only respond to authorized chat
        if chat_id != self.chat_id:
            self.log("warning", f"Unauthorized chat attempt from {chat_id}")
            return

        if not text:
            return

        # Rate limiting
        now = time.time()
        user_times = self.last_message_time.get(chat_id, [])
        user_times = [t for t in user_times if now - t < 60]

        if len(user_times) >= self.rate_limit:
            self.send_message("⏳ Espera un momento, muchos mensajes seguidos.")
            return

        user_times.append(now)
        self.last_message_time[chat_id] = user_times

        # Process and respond
        self.log("info", f"Processing message: '{text[:50]}...'")

        try:
            response = self.process_message(text)
            if response:
                self.log("info", f"Response ready: {len(response)} chars")
                sent = self.send_message(response)
                self.log("info", f"Message sent: {sent}")
            else:
                self.log("warning", "Empty response from process_message")
                self.send_message("🤔 Intenta de nuevo.")
        except Exception as e:
            self.log("error", f"Error processing message: {e}")
            import traceback
            self.log("error", traceback.format_exc())
            self.send_message(f"❌ Error: {str(e)[:100]}")

    def start(self):
        """Start the assistant (polling mode)"""
        self.running = True
        self.log("info", "Guardian AI Assistant starting...")

        # Clear any pending updates first to avoid processing old messages
        self.log("info", "Clearing pending updates...")
        try:
            response = requests.get(
                f"{self.api_url}/getUpdates",
                params={"offset": -1, "limit": 1},
                timeout=10
            )
            if response.ok:
                data = response.json()
                results = data.get("result", [])
                if results:
                    self.last_update_id = results[-1].get("update_id", 0)
                    self.log("info", f"Cleared updates, starting from ID: {self.last_update_id}")
        except Exception as e:
            self.log("warning", f"Could not clear updates: {e}")

        # Send startup message
        self.send_message("🤖 *Guardian Assistant* listo.\n\nHáblame en lenguaje natural:\n• _¿Cómo están los servidores?_\n• _Lista los contenedores_\n• _Escanea seguridad_")

        poll_count = 0
        while self.running:
            try:
                poll_count += 1
                if poll_count % 10 == 1:  # Log every 10 polls (~5 min)
                    self.log("info", f"Polling... (cycle {poll_count})")

                updates = self.get_updates()

                if updates:
                    self.log("info", f"Received {len(updates)} update(s)")

                for update in updates:
                    update_id = update.get("update_id", 0)
                    if update_id > self.last_update_id:
                        self.last_update_id = update_id
                        self.log("info", f"Processing update {update_id}")
                        self.handle_update(update)

            except KeyboardInterrupt:
                self.running = False
                break
            except Exception as e:
                self.log("error", f"Error in main loop: {e}")
                import traceback
                self.log("error", traceback.format_exc())
                time.sleep(5)

        self.log("info", "Guardian AI Assistant stopped")

    def stop(self):
        """Stop the assistant"""
        self.running = False


def main():
    """Main entry point"""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from core.config import Config
    from core.logger import Logger

    config = Config()
    logger = Logger("guardian-assistant")

    bot_token = config.get_secret("telegram_bot_token")
    chat_id = config.get("notifications.telegram.chat_id")
    anthropic_key = config.get("anthropic_api_key") or config.get_secret("anthropic_api_key")

    if not all([bot_token, chat_id, anthropic_key]):
        print("Error: Missing configuration (telegram token, chat_id, or anthropic key)")
        sys.exit(1)

    assistant = TelegramAssistant(bot_token, chat_id, anthropic_key, logger)

    try:
        assistant.start()
    except KeyboardInterrupt:
        assistant.stop()


if __name__ == "__main__":
    main()
