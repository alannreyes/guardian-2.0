"""
Guardian 2.0 - Report Generator
===============================
Generates security reports in multiple formats:
- PDF: Complete detailed report with all findings
- Telegram: Brief 3-4 line summary with key points
- Email: HTML version with moderate detail
"""

import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import base64
import json

from core.config import Config
from core.logger import Logger
from modules.llm_analyzer import LLMAnalyzer
from modules.notifier import Notifier, AlertLevel


@dataclass
class SecurityCheck:
    """Individual security check result"""
    name: str
    status: str  # pass, warning, fail, info
    value: str
    importance: str


@dataclass
class ReportSection:
    """Report section with checks"""
    name: str
    icon: str
    status: str  # ok, warning, critical
    checks: List[SecurityCheck]
    containers: Optional[List[Dict]] = None


@dataclass
class PendingAction:
    """Action that needs attention"""
    severity: str  # critical, high, medium, low
    description: str
    command: str
    impact: str


@dataclass
class SecurityReport:
    """Complete security report data"""
    hostname: str
    generated_at: str
    health_score: int
    summary: str  # Bullet format, max 3 lines
    sections: Dict[str, ReportSection]
    pending_actions: List[PendingAction]


class ReportGenerator:
    """Generates security reports in multiple formats"""

    def __init__(
        self,
        config: Config,
        logger: Logger,
        llm_analyzer: LLMAnalyzer,
        notifier: Notifier
    ):
        self.config = config
        self.logger = logger
        self.llm = llm_analyzer
        self.notifier = notifier

        self.output_dir = Path(config.get("output_dir", "/opt/luxia/guardian/output"))
        self.template_dir = Path("/opt/luxia/guardian/templates")
        self.assets_dir = Path("/opt/luxia/guardian/assets")

    def generate(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate all report formats.

        Returns dict with paths/status for each format:
        - pdf_path: Path to generated PDF
        - telegram_sent: Whether Telegram was sent
        - email_sent: Whether email was sent
        """
        results = {}

        # Build report structure
        report = self._build_report(report_data)

        # Generate executive summary (bullets, max 3 lines)
        report.summary = self.llm.generate_summary(asdict(report))

        # 1. Generate PDF (complete)
        pdf_path = self._generate_pdf(report)
        results["pdf_path"] = str(pdf_path) if pdf_path else None

        # 2. Send Telegram (brief)
        telegram_sent = self._send_telegram_summary(report)
        results["telegram_sent"] = telegram_sent

        # 3. Send Email with PDF attachment
        email_sent = self._send_email_report(report, pdf_path)
        results["email_sent"] = email_sent

        return results

    def _build_report(self, data: Dict[str, Any]) -> SecurityReport:
        """Build SecurityReport from raw data"""

        # Calculate health score
        score = self._calculate_health_score(data)

        # Build sections
        sections = {}

        # System Resources
        sections["resources"] = ReportSection(
            name="Recursos del Sistema",
            icon="💻",
            status=self._get_section_status(data.get("resources", {})),
            checks=[
                SecurityCheck(
                    name="CPU Usage",
                    status="pass" if data.get("cpu", 0) < 80 else "warning" if data.get("cpu", 0) < 95 else "fail",
                    value=f"{data.get('cpu', 0):.1f}%",
                    importance="Alto uso puede indicar cryptominer"
                ),
                SecurityCheck(
                    name="Memory Usage",
                    status="pass" if data.get("memory", 0) < 85 else "warning",
                    value=f"{data.get('memory', 0):.1f}%",
                    importance="Monitorear fugas de memoria"
                ),
                SecurityCheck(
                    name="Disk Usage",
                    status="pass" if data.get("disk", 0) < 80 else "warning",
                    value=f"{data.get('disk', 0):.1f}%",
                    importance="Espacio para logs y operación"
                ),
            ]
        )

        # Security Checks
        security_checks = []
        if data.get("suspicious_processes"):
            security_checks.append(SecurityCheck(
                name="Procesos Sospechosos",
                status="fail",
                value=f"{len(data['suspicious_processes'])} detectados",
                importance="Revisar inmediatamente"
            ))
        else:
            security_checks.append(SecurityCheck(
                name="Procesos Sospechosos",
                status="pass",
                value="Ninguno",
                importance="Sin amenazas detectadas"
            ))

        if data.get("mining_connections"):
            security_checks.append(SecurityCheck(
                name="Conexiones a Pools",
                status="fail",
                value=f"{len(data['mining_connections'])} conexiones",
                importance="Cryptominer activo"
            ))
        else:
            security_checks.append(SecurityCheck(
                name="Conexiones a Pools",
                status="pass",
                value="Ninguna",
                importance="Sin minería detectada"
            ))

        sections["security"] = ReportSection(
            name="Seguridad",
            icon="🔒",
            status="critical" if data.get("suspicious_processes") else "ok",
            checks=security_checks
        )

        # Docker Containers
        containers = data.get("containers", [])
        sections["containers"] = ReportSection(
            name="Contenedores Docker",
            icon="🐳",
            status=self._get_containers_status(containers),
            checks=[],
            containers=containers
        )

        # Build pending actions
        pending_actions = []
        for action in data.get("pending_actions", []):
            pending_actions.append(PendingAction(
                severity=action.get("severity", "medium"),
                description=action.get("description", ""),
                command=action.get("command", ""),
                impact=action.get("impact", "")
            ))

        return SecurityReport(
            hostname=self.config.server.name,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            health_score=score,
            summary="",  # Will be filled by LLM
            sections=sections,
            pending_actions=pending_actions
        )

    def _calculate_health_score(self, data: Dict) -> int:
        """Calculate health score 0-100"""
        score = 100

        # Resource deductions
        cpu = data.get("cpu", 0)
        if cpu > 90:
            score -= 20
        elif cpu > 70:
            score -= 10

        memory = data.get("memory", 0)
        if memory > 90:
            score -= 15
        elif memory > 80:
            score -= 5

        # Security deductions
        if data.get("suspicious_processes"):
            score -= 30
        if data.get("mining_connections"):
            score -= 25
        if data.get("new_executables_tmp"):
            score -= 10

        # Container issues
        unhealthy = len([c for c in data.get("containers", []) if c.get("health") != "healthy"])
        score -= unhealthy * 5

        return max(0, min(100, score))

    def _get_section_status(self, data: Dict) -> str:
        """Determine section status"""
        if data.get("critical"):
            return "critical"
        if data.get("warning"):
            return "warning"
        return "ok"

    def _get_containers_status(self, containers: List[Dict]) -> str:
        """Determine containers section status"""
        unhealthy = [c for c in containers if c.get("health") in ["unhealthy", "stopped"]]
        if any(c.get("health") == "stopped" for c in unhealthy):
            return "critical"
        if unhealthy:
            return "warning"
        return "ok"

    def _generate_pdf(self, report: SecurityReport) -> Optional[Path]:
        """Generate PDF report using HTML template"""
        try:
            from jinja2 import Environment, FileSystemLoader

            # Load template
            env = Environment(loader=FileSystemLoader(str(self.template_dir)))
            template = env.get_template("report.html")

            # Load logo
            logo_base64 = ""
            logo_path = self.assets_dir / "logo.png"
            if logo_path.exists():
                with open(logo_path, "rb") as f:
                    logo_base64 = base64.b64encode(f.read()).decode()

            # Convert sections to dict format for template
            sections_dict = {}
            for key, section in report.sections.items():
                sections_dict[key] = {
                    "name": section.name,
                    "icon": section.icon,
                    "status": section.status,
                    "checks": [asdict(c) for c in section.checks],
                    "containers": section.containers
                }

            # Render HTML
            html_content = template.render(
                report={
                    "hostname": report.hostname,
                    "health_score": report.health_score,
                    "summary": report.summary,
                    "sections": sections_dict,
                    "pending_actions": [asdict(a) for a in report.pending_actions]
                },
                generated_at=report.generated_at,
                logo_base64=logo_base64,
                year=datetime.now().year
            )

            # Save HTML
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            html_path = self.output_dir / f"report_{timestamp}.html"
            pdf_path = self.output_dir / f"proactive_review_{timestamp}.pdf"

            self.output_dir.mkdir(parents=True, exist_ok=True)

            with open(html_path, "w") as f:
                f.write(html_content)

            # Convert to PDF using weasyprint
            try:
                from weasyprint import HTML
                HTML(filename=str(html_path)).write_pdf(str(pdf_path))
                self.logger.info(f"PDF report generated: {pdf_path}")

                # Clean up HTML
                html_path.unlink()

                return pdf_path
            except ImportError:
                self.logger.warning("weasyprint not installed, HTML only")
                return html_path

        except Exception as e:
            self.logger.error(f"Failed to generate PDF: {e}")
            return None

    def _send_telegram_summary(self, report: SecurityReport) -> bool:
        """
        Send brief Telegram summary.
        Format: 3-4 lines max, bullet points, key info only.
        """
        # Determine alert level
        if report.health_score < 50:
            level = "critical"
        elif report.health_score < 70:
            level = "warning"
        else:
            level = "info"

        # Build brief description (key findings only)
        critical_actions = [a for a in report.pending_actions if a.severity == "critical"]

        if critical_actions:
            description = f"{len(critical_actions)} problemas criticos requieren atencion"
        elif report.health_score >= 90:
            description = "Todos los sistemas operando correctamente"
        else:
            description = "Revision de rutina completada"

        # Key details (1-2 items max)
        details = {
            "Score": f"{report.health_score}/100"
        }

        if critical_actions:
            details["Accion"] = critical_actions[0].description[:50]

        return bool(self.notifier.send_alert(
            level=level,
            title="Reporte Diario",
            description=description,
            details=details,
            requires_attention=len(critical_actions) > 0
        ).get("telegram"))

    def _send_email_report(self, report: SecurityReport, pdf_path: Optional[Path]) -> bool:
        """Send email with PDF attachment"""
        if not pdf_path or not pdf_path.exists():
            return False

        try:
            # Use the SmartEmail module if available
            from smart_email import SmartEmail

            sendgrid_key = self.config.get_secret("sendgrid_api_key")
            if not sendgrid_key:
                return False

            email = SmartEmail(
                sendgrid_api_key=sendgrid_key,
                default_from=self.config.get("notifications.email.from", "guardian@luxia.us")
            )

            # Build email body with summary
            body = f"""
            <h2>Guardian Security Report</h2>
            <p><strong>Server:</strong> {report.hostname}</p>
            <p><strong>Health Score:</strong> {report.health_score}/100</p>

            <h3>Resumen Ejecutivo</h3>
            <pre style="background: #f5f5f5; padding: 10px; border-radius: 5px;">{report.summary}</pre>

            <p>Ver el reporte completo en el PDF adjunto.</p>

            <hr>
            <p style="color: #666; font-size: 12px;">
                Luxia Guardian - Proactive Security Monitoring
            </p>
            """

            to_emails = self.config.get("notifications.email.to", [])

            result = email.send_with_attachment(
                to=to_emails,
                subject=f"[Guardian] Reporte de Seguridad - {report.hostname} ({report.health_score}/100)",
                body=body,
                attachment_path=str(pdf_path)
            )

            return result.get("success", False)

        except ImportError:
            self.logger.warning("SmartEmail not available for email reports")
            return False
        except Exception as e:
            self.logger.error(f"Failed to send email report: {e}")
            return False
