"""
Guardian 2.0 - Notification System
===================================
Multi-channel notification system:
- Email via SendGrid
- Telegram
- Webhook (future)
"""

import json
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from core.config import Config
from core.logger import Logger


class AlertLevel(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class Alert:
    """Alert data structure"""
    level: AlertLevel
    title: str
    description: str
    server: str
    timestamp: datetime
    details: Dict[str, Any]
    action_taken: Optional[str] = None
    requires_attention: bool = True


class TelegramNotifier:
    """Send notifications via Telegram"""

    API_URL = "https://api.telegram.org/bot{token}/sendMessage"

    def __init__(self, bot_token: str, chat_id: str, logger: Logger):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.logger = logger
        self.enabled = bool(bot_token and chat_id)

    def send(self, alert: Alert) -> bool:
        """Send alert to Telegram - BRIEF format (max 3-4 lines)"""
        if not self.enabled:
            self.logger.warning("Telegram not configured, skipping notification")
            return False

        # Format message with emoji based on level - COMPACT
        emoji = {
            AlertLevel.INFO: "ℹ️",
            AlertLevel.WARNING: "⚠️",
            AlertLevel.CRITICAL: "🚨",
            AlertLevel.EMERGENCY: "🔴"
        }.get(alert.level, "📢")

        # Truncate description to max 100 chars
        short_desc = alert.description[:100] + "..." if len(alert.description) > 100 else alert.description

        # COMPACT Telegram format - bullets, max 3 lines
        message = f"""{emoji} *{alert.level.value.upper()}* | `{alert.server}`

• {alert.title}
• {short_desc}"""

        if alert.action_taken:
            message += f"\n✅ {alert.action_taken}"
        elif alert.requires_attention:
            message += f"\n⏰ Requiere atención"

        # Add one key detail if available (most relevant)
        if alert.details:
            key_detail = list(alert.details.items())[0]
            message += f"\n📍 {key_detail[0]}: `{str(key_detail[1])[:50]}`"

        try:
            response = requests.post(
                self.API_URL.format(token=self.bot_token),
                json={
                    "chat_id": self.chat_id,
                    "text": message,
                    "parse_mode": "Markdown",
                    "disable_web_page_preview": True
                },
                timeout=10
            )
            response.raise_for_status()
            self.logger.info(f"Telegram notification sent: {alert.title}")
            return True
        except Exception as e:
            self.logger.error(f"Telegram notification failed: {e}")
            return False


class EmailNotifier:
    """Send notifications via SendGrid"""

    def __init__(self, api_key: str, from_email: str, to_emails: List[str], logger: Logger):
        self.api_key = api_key
        self.from_email = from_email
        self.to_emails = to_emails
        self.logger = logger
        self.enabled = bool(api_key and from_email and to_emails)

    def send(self, alert: Alert) -> bool:
        """Send alert via email"""
        if not self.enabled:
            self.logger.warning("Email not configured, skipping notification")
            return False

        try:
            from sendgrid import SendGridAPIClient
            from sendgrid.helpers.mail import Mail, Email, To, Content

            # Create HTML content
            emoji = {
                AlertLevel.INFO: "ℹ️",
                AlertLevel.WARNING: "⚠️",
                AlertLevel.CRITICAL: "🚨",
                AlertLevel.EMERGENCY: "🔴"
            }.get(alert.level, "📢")

            html_content = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: {'#dc3545' if alert.level in [AlertLevel.CRITICAL, AlertLevel.EMERGENCY] else '#ffc107' if alert.level == AlertLevel.WARNING else '#17a2b8'};
                            color: white; padding: 20px; text-align: center;">
                    <h1>{emoji} Guardian Alert</h1>
                    <p style="font-size: 18px;">{alert.level.value.upper()}</p>
                </div>

                <div style="padding: 20px; background: #f8f9fa;">
                    <p><strong>Server:</strong> {alert.server}</p>
                    <p><strong>Time:</strong> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>

                <div style="padding: 20px;">
                    <h2>{alert.title}</h2>
                    <p>{alert.description}</p>

                    {'<p style="color: green;"><strong>✅ Action Taken:</strong> ' + alert.action_taken + '</p>' if alert.action_taken else ''}

                    <h3>Details</h3>
                    <table style="width: 100%; border-collapse: collapse;">
                        {''.join(f'<tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>{k}</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;"><code>{v}</code></td></tr>' for k, v in alert.details.items())}
                    </table>
                </div>

                <div style="padding: 20px; background: #f8f9fa; text-align: center; font-size: 12px;">
                    <p>Luxia Guardian - Proactive Security Monitoring</p>
                </div>
            </div>
            """

            subject = f"[{alert.level.value.upper()}] Guardian: {alert.title} ({alert.server})"

            message = Mail(
                from_email=Email(self.from_email),
                to_emails=[To(email) for email in self.to_emails],
                subject=subject,
                html_content=Content("text/html", html_content)
            )

            sg = SendGridAPIClient(self.api_key)
            response = sg.send(message)

            self.logger.info(f"Email notification sent: {alert.title} (status: {response.status_code})")
            return response.status_code in [200, 201, 202]

        except ImportError:
            self.logger.error("sendgrid package not installed")
            return False
        except Exception as e:
            self.logger.error(f"Email notification failed: {e}")
            return False


class WebhookNotifier:
    """Send notifications via webhook"""

    def __init__(self, url: str, headers: Dict[str, str], logger: Logger):
        self.url = url
        self.headers = headers
        self.logger = logger
        self.enabled = bool(url)

    def send(self, alert: Alert) -> bool:
        """Send alert via webhook"""
        if not self.enabled:
            return False

        payload = {
            "level": alert.level.value,
            "title": alert.title,
            "description": alert.description,
            "server": alert.server,
            "timestamp": alert.timestamp.isoformat(),
            "details": alert.details,
            "action_taken": alert.action_taken,
            "requires_attention": alert.requires_attention
        }

        try:
            response = requests.post(
                self.url,
                json=payload,
                headers=self.headers,
                timeout=10
            )
            response.raise_for_status()
            self.logger.info(f"Webhook notification sent: {alert.title}")
            return True
        except Exception as e:
            self.logger.error(f"Webhook notification failed: {e}")
            return False


class Notifier:
    """Main notification orchestrator"""

    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.server_name = config.server.name

        # Initialize notifiers
        self.telegram = TelegramNotifier(
            bot_token=config.get_secret("telegram_bot_token") or config.get("notifications.telegram.bot_token", ""),
            chat_id=config.get("notifications.telegram.chat_id", ""),
            logger=logger
        )

        self.email = EmailNotifier(
            api_key=config.get_secret("sendgrid_api_key") or "",
            from_email=config.get("notifications.email.from", "guardian@luxia.us"),
            to_emails=config.get("notifications.email.to", ["alann@luxia.us"]),
            logger=logger
        )

        self.webhook = WebhookNotifier(
            url=config.get("notifications.webhook.url", ""),
            headers=config.get("notifications.webhook.headers", {}),
            logger=logger
        )

        # Level configurations
        self.telegram_levels = [
            AlertLevel(l) for l in config.get("notifications.telegram.levels", ["warning", "critical", "emergency"])
        ]
        self.email_levels = [
            AlertLevel(l) for l in config.get("notifications.email.levels", ["critical", "emergency"])
        ]
        self.webhook_levels = [
            AlertLevel(l) for l in config.get("notifications.webhook.levels", ["critical", "emergency"])
        ]

    def send_alert(
        self,
        level: str,
        title: str,
        description: str,
        details: Dict[str, Any],
        action_taken: Optional[str] = None,
        requires_attention: bool = True
    ) -> Dict[str, bool]:
        """Send alert through configured channels"""

        alert = Alert(
            level=AlertLevel(level),
            title=title,
            description=description,
            server=self.server_name,
            timestamp=datetime.now(),
            details=details,
            action_taken=action_taken,
            requires_attention=requires_attention
        )

        results = {}

        # Send to Telegram if level matches
        if alert.level in self.telegram_levels:
            results["telegram"] = self.telegram.send(alert)

        # Send to Email if level matches
        if alert.level in self.email_levels:
            results["email"] = self.email.send(alert)

        # Send to Webhook if level matches
        if alert.level in self.webhook_levels:
            results["webhook"] = self.webhook.send(alert)

        return results

    def send_test_notification(self) -> Dict[str, bool]:
        """Send test notification to all channels"""
        return self.send_alert(
            level="info",
            title="Guardian Test Notification",
            description="This is a test notification from Guardian 2.0. If you receive this, notifications are working correctly.",
            details={
                "server": self.server_name,
                "test": True,
                "timestamp": datetime.now().isoformat()
            },
            requires_attention=False
        )
