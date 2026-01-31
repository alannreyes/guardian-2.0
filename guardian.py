#!/usr/bin/env python3
"""
Luxia Guardian 2.0 - Proactive Security Monitor
==============================================
Main entry point for Guardian 2.0.

Usage:
    guardian.py run              - Run full report (same as v1)
    guardian.py sentinel         - Start real-time monitoring daemon
    guardian.py check            - Run a single security check
    guardian.py update-iocs      - Update IOC feeds
    guardian.py status           - Show current status
    guardian.py test-notify      - Send test notification
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.config import Config
from core.logger import Logger
from modules.ioc_manager import IOCManager
from modules.llm_analyzer import LLMAnalyzer
from modules.notifier import Notifier
from modules.remediator import Remediator
from modules.sentinel import Sentinel


class Guardian:
    """Main Guardian 2.0 class"""

    VERSION = "2.0.0"

    def __init__(self, config_path: str = None):
        self.config = Config(config_path)
        self.logger = Logger("guardian")

        # Initialize modules
        self.ioc_manager = IOCManager(self.config, self.logger)
        self.llm_analyzer = LLMAnalyzer(self.config, self.logger)
        self.notifier = Notifier(self.config, self.logger)
        self.remediator = Remediator(self.config, self.logger)

        # Sentinel (real-time monitor)
        self.sentinel = Sentinel(
            self.config,
            self.logger,
            self.ioc_manager,
            self.llm_analyzer,
            self.notifier,
            self.remediator
        )

    def run_report(self):
        """Run full security report with email + Telegram"""
        import subprocess
        import requests

        self.logger.info("=" * 60)
        self.logger.info(f"LUXIA GUARDIAN {self.VERSION} - Daily Security Report")
        self.logger.info("=" * 60)

        # Collect system data
        self.logger.info("Collecting system data...")
        report_data = self._collect_system_data()

        # Generate summary with LLM
        self.logger.info("Generating executive summary...")
        summary = self.llm_analyzer.generate_summary(report_data)
        report_data["summary"] = summary

        # Calculate health score
        score = self._calculate_health_score(report_data)
        report_data["health_score"] = score

        # Determine status
        if score >= 90:
            status = "excelente"
            level = "info"
        elif score >= 70:
            status = "bueno"
            level = "info"
        elif score >= 50:
            status = "atención"
            level = "warning"
        else:
            status = "crítico"
            level = "critical"

        # Send Telegram summary (brief)
        self.logger.info("Sending Telegram notification...")
        telegram_msg = f"""📊 *Reporte Diario* | `{self.config.server.name}`

{summary}

🎯 Score: {score}/100 - {status.upper()}"""

        self._send_telegram(telegram_msg)

        # Send email with details
        self.logger.info("Sending email report...")
        self._send_email_report(report_data, score, status)

        self.logger.info(f"Report complete - Score: {score}/100")

    def _collect_system_data(self):
        """Collect system metrics"""
        import subprocess

        data = {
            "hostname": self.config.server.name,
            "timestamp": datetime.now().isoformat(),
            "pending_actions": []
        }

        # CPU
        try:
            result = subprocess.run(
                "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'",
                shell=True, capture_output=True, text=True, timeout=10
            )
            data["cpu"] = float(result.stdout.strip() or 0)
        except:
            data["cpu"] = 0

        # Memory
        try:
            result = subprocess.run(
                "free | grep Mem | awk '{print ($3/$2) * 100}'",
                shell=True, capture_output=True, text=True, timeout=10
            )
            data["memory"] = float(result.stdout.strip() or 0)
        except:
            data["memory"] = 0

        # Disk
        try:
            result = subprocess.run(
                "df / | tail -1 | awk '{print $5}' | tr -d '%'",
                shell=True, capture_output=True, text=True, timeout=10
            )
            data["disk"] = float(result.stdout.strip() or 0)
        except:
            data["disk"] = 0

        # Suspicious processes
        try:
            result = subprocess.run(
                "ps aux | grep -E 'xmrig|minerd|\\.svc|cryptonight' | grep -v grep",
                shell=True, capture_output=True, text=True, timeout=10
            )
            data["suspicious_processes"] = [p for p in result.stdout.strip().split('\n') if p]
        except:
            data["suspicious_processes"] = []

        # Mining connections
        try:
            result = subprocess.run(
                "ss -tnp 2>/dev/null | grep -E ':3333|:4444|:5555|:7777'",
                shell=True, capture_output=True, text=True, timeout=10
            )
            data["mining_connections"] = [c for c in result.stdout.strip().split('\n') if c]
        except:
            data["mining_connections"] = []

        # Docker containers
        try:
            result = subprocess.run(
                "docker ps --format '{{.Names}}:{{.Status}}' 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=10
            )
            containers = []
            for line in result.stdout.strip().split('\n'):
                if ':' in line:
                    name, status = line.split(':', 1)
                    health = "healthy" if "Up" in status else "stopped"
                    if "unhealthy" in status.lower():
                        health = "unhealthy"
                    containers.append({"name": name, "status": status, "health": health})
            data["containers"] = containers
        except:
            data["containers"] = []

        # Add pending actions if issues found
        if data["suspicious_processes"]:
            data["pending_actions"].append({
                "severity": "critical",
                "description": f"{len(data['suspicious_processes'])} procesos sospechosos detectados",
                "command": "ps aux --sort=-%cpu | head -20",
                "impact": "Posible cryptominer activo"
            })

        if data["mining_connections"]:
            data["pending_actions"].append({
                "severity": "critical",
                "description": "Conexiones a pools de minería detectadas",
                "command": "ss -tnp | grep -E ':3333|:4444|:5555'",
                "impact": "Cryptominer comunicándose con pool"
            })

        if data["cpu"] > 90:
            data["pending_actions"].append({
                "severity": "high",
                "description": f"CPU al {data['cpu']:.0f}%",
                "command": "top -bn1 | head -20",
                "impact": "Rendimiento degradado"
            })

        return data

    def _calculate_health_score(self, data):
        """Calculate health score 0-100"""
        score = 100

        # Resource deductions
        if data.get("cpu", 0) > 90:
            score -= 20
        elif data.get("cpu", 0) > 70:
            score -= 10

        if data.get("memory", 0) > 90:
            score -= 15
        elif data.get("memory", 0) > 80:
            score -= 5

        if data.get("disk", 0) > 90:
            score -= 15
        elif data.get("disk", 0) > 80:
            score -= 5

        # Security deductions
        if data.get("suspicious_processes"):
            score -= 30
        if data.get("mining_connections"):
            score -= 25

        # Container issues
        unhealthy = len([c for c in data.get("containers", []) if c.get("health") != "healthy"])
        score -= unhealthy * 5

        return max(0, min(100, score))

    def _send_telegram(self, message):
        """Send Telegram message"""
        import requests

        token = self.config.get_secret("telegram_bot_token")
        chat_id = self.config.get("notifications.telegram.chat_id")

        if not token or not chat_id:
            self.logger.warning("Telegram not configured")
            return False

        try:
            response = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": message,
                    "parse_mode": "Markdown"
                },
                timeout=10
            )
            return response.ok
        except Exception as e:
            self.logger.error(f"Telegram send failed: {e}")
            return False

    def _send_email_report(self, data, score, status):
        """Send email report"""
        import requests

        api_key = self.config.get("sendgrid_api_key") or self.config.get_secret("sendgrid_api_key")
        to_email = self.config.get("email_to") or self.config.get("notifications.email.to", ["alann@luxia.us"])
        from_email = self.config.get("email_from") or "guardian@luxia.us"

        if isinstance(to_email, list):
            to_email = to_email[0]

        if not api_key:
            self.logger.warning("SendGrid not configured")
            return False

        # Build HTML
        containers_html = "".join([
            f"<tr><td>{c['name']}</td><td>{c['status'][:40]}</td></tr>"
            for c in data.get("containers", [])[:10]
        ])

        actions_html = ""
        if data.get("pending_actions"):
            actions_html = "<h3 style='color:#dc3545'>⚠️ Acciones Pendientes</h3><ul>"
            for action in data["pending_actions"]:
                actions_html += f"<li><strong>{action['severity'].upper()}</strong>: {action['description']}</li>"
            actions_html += "</ul>"
        else:
            actions_html = "<p style='color:#22c55e'>✅ Sin acciones pendientes</p>"

        html_body = f"""
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
            <div style="background:linear-gradient(135deg,#1a1a2e,#6366f1);color:white;padding:20px;text-align:center;border-radius:10px 10px 0 0;">
                <h1 style="margin:0;">🛡️ LUXIA GUARDIAN</h1>
                <p style="margin:5px 0 0 0;opacity:0.9;">Reporte Diario de Seguridad</p>
            </div>

            <div style="padding:20px;background:#f8f9fa;border-left:4px solid {'#22c55e' if score >= 70 else '#f59e0b' if score >= 50 else '#dc3545'};">
                <h2 style="margin:0;color:{'#22c55e' if score >= 70 else '#f59e0b' if score >= 50 else '#dc3545'};">
                    Score: {score}/100 - {status.upper()}
                </h2>
            </div>

            <div style="padding:20px;">
                <h3>📊 Resumen Ejecutivo</h3>
                <pre style="background:#f5f5f5;padding:15px;border-radius:5px;white-space:pre-wrap;">{data.get('summary', 'No disponible')}</pre>

                <h3>💻 Recursos</h3>
                <table style="width:100%;border-collapse:collapse;">
                    <tr><td>CPU</td><td><strong>{data.get('cpu', 0):.1f}%</strong></td></tr>
                    <tr><td>Memoria</td><td><strong>{data.get('memory', 0):.1f}%</strong></td></tr>
                    <tr><td>Disco</td><td><strong>{data.get('disk', 0):.1f}%</strong></td></tr>
                </table>

                {actions_html}

                <h3>🐳 Contenedores</h3>
                <table style="width:100%;border-collapse:collapse;font-size:12px;">
                    {containers_html if containers_html else '<tr><td>Sin contenedores</td></tr>'}
                </table>
            </div>

            <div style="padding:15px;background:#f1f5f9;text-align:center;color:#64748b;font-size:12px;border-radius:0 0 10px 10px;">
                <p style="margin:0;">Luxia Guardian v{self.VERSION} | {data.get('hostname', 'unknown')}</p>
                <p style="margin:5px 0 0 0;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>
        """

        try:
            response = requests.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "personalizations": [{"to": [{"email": to_email}]}],
                    "from": {"email": from_email, "name": "Luxia Guardian"},
                    "subject": f"[Guardian] Reporte Diario - {data.get('hostname', 'unknown')} ({score}/100)",
                    "content": [{"type": "text/html", "value": html_body}]
                },
                timeout=30
            )
            return response.status_code in [200, 201, 202]
        except Exception as e:
            self.logger.error(f"Email send failed: {e}")
            return False

    def start_sentinel(self):
        """Start real-time monitoring daemon"""
        self.logger.info("=" * 60)
        self.logger.info(f"LUXIA GUARDIAN {self.VERSION} - Sentinel Mode")
        self.logger.info("=" * 60)
        self.logger.info(f"Server: {self.config.server.name}")
        self.logger.info(f"Check interval: {self.config.check_interval}s")
        self.logger.info(f"Maintenance window: {self.config.get('sentinel.maintenance_window.start_hour')}:00 - {self.config.get('sentinel.maintenance_window.end_hour')}:00")
        self.logger.info("-" * 60)

        self.sentinel.start()

    def run_single_check(self):
        """Run a single security check"""
        self.logger.info("Running single security check...")
        self.sentinel.run_once()
        self.logger.info("Check complete")

    def update_iocs(self):
        """Update IOC feeds"""
        self.logger.info("Updating IOC feeds...")
        results = self.ioc_manager.update_all_feeds()

        for feed, result in results.items():
            if result.get("status") == "success":
                self.logger.info(f"  ✓ {feed}: {result.get('count', 0)} entries")
            else:
                self.logger.error(f"  ✗ {feed}: {result.get('error', 'Unknown error')}")

        stats = self.ioc_manager.get_stats()
        self.logger.info(f"Total IOCs in database: {stats['total_iocs']}")

    def show_status(self):
        """Show current status"""
        print(f"\n{'=' * 60}")
        print(f"LUXIA GUARDIAN {self.VERSION}")
        print(f"{'=' * 60}")
        print(f"\nServer: {self.config.server.name}")
        print(f"Environment: {self.config.server.environment}")
        print(f"Timezone: {self.config.server.timezone}")

        # IOC Stats
        ioc_stats = self.ioc_manager.get_stats()
        print(f"\nIOC Database:")
        print(f"  Total IOCs: {ioc_stats['total_iocs']}")
        for source, count in ioc_stats.get('by_source', {}).items():
            print(f"  - {source}: {count}")

        # Recent alerts
        alerts = self.logger.get_recent_alerts(hours=24)
        print(f"\nRecent Alerts (24h): {len(alerts)}")
        for alert in alerts[-5:]:
            print(f"  [{alert['level']}] {alert['type']}: {alert['description'][:50]}...")

        print(f"\n{'=' * 60}\n")

    def test_notification(self):
        """Send test notification"""
        self.logger.info("Sending test notification...")
        results = self.notifier.send_test_notification()

        for channel, success in results.items():
            if success:
                self.logger.info(f"  ✓ {channel}: sent successfully")
            else:
                self.logger.warning(f"  ✗ {channel}: failed")


def main():
    parser = argparse.ArgumentParser(
        description="Luxia Guardian 2.0 - Proactive Security Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  run           Run full security report and generate PDF
  sentinel      Start real-time monitoring daemon (24/7)
  check         Run a single security check
  update-iocs   Update threat intelligence feeds
  status        Show current status and statistics
  test-notify   Send test notification to all channels

Examples:
  guardian.py sentinel          # Start monitoring daemon
  guardian.py check             # Quick security scan
  guardian.py update-iocs       # Update IOC database
        """
    )

    parser.add_argument("command", nargs="?", default="run",
                        choices=["run", "sentinel", "check", "update-iocs", "status", "test-notify"],
                        help="Command to execute")
    parser.add_argument("-c", "--config", help="Path to config file")
    parser.add_argument("-v", "--version", action="version", version=f"Guardian {Guardian.VERSION}")

    args = parser.parse_args()

    try:
        guardian = Guardian(args.config)

        if args.command == "run":
            guardian.run_report()
        elif args.command == "sentinel":
            guardian.start_sentinel()
        elif args.command == "check":
            guardian.run_single_check()
        elif args.command == "update-iocs":
            guardian.update_iocs()
        elif args.command == "status":
            guardian.show_status()
        elif args.command == "test-notify":
            guardian.test_notification()

    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
