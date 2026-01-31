"""
Guardian 2.0 - Logging System
==============================
Structured logging with support for:
- Console output (colored)
- File rotation
- JSON format for log aggregation
- Alert-specific logging
"""

import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from logging.handlers import RotatingFileHandler


class ColoredFormatter(logging.Formatter):
    """Colored console formatter"""

    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'
    }

    ICONS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️ ',
        'ERROR': '❌',
        'CRITICAL': '🚨'
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        icon = self.ICONS.get(record.levelname, '')
        reset = self.COLORS['RESET']

        # Format timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')

        # Build message
        message = f"{color}{timestamp} {icon} [{record.levelname:8}]{reset} {record.getMessage()}"

        if record.exc_info:
            message += f"\n{self.formatException(record.exc_info)}"

        return message


class JSONFormatter(logging.Formatter):
    """JSON formatter for log aggregation (Loki, ELK, etc.)"""

    def format(self, record):
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }

        # Add extra fields
        if hasattr(record, 'extra_data'):
            log_data.update(record.extra_data)

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


class AlertLogger:
    """Specialized logger for security alerts"""

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.alerts_file = log_dir / "alerts.jsonl"
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def log_alert(
        self,
        level: str,
        alert_type: str,
        description: str,
        details: Dict[str, Any],
        action_taken: Optional[str] = None
    ) -> Dict[str, Any]:
        """Log a security alert"""
        alert = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": level,
            "type": alert_type,
            "description": description,
            "details": details,
            "action_taken": action_taken
        }

        # Append to alerts file
        with open(self.alerts_file, "a") as f:
            f.write(json.dumps(alert) + "\n")

        return alert

    def get_recent_alerts(self, hours: int = 24, level: Optional[str] = None) -> list:
        """Get alerts from the last N hours"""
        if not self.alerts_file.exists():
            return []

        alerts = []
        cutoff = datetime.utcnow().timestamp() - (hours * 3600)

        with open(self.alerts_file) as f:
            for line in f:
                try:
                    alert = json.loads(line.strip())
                    alert_time = datetime.fromisoformat(
                        alert["timestamp"].replace("Z", "+00:00")
                    ).timestamp()

                    if alert_time >= cutoff:
                        if level is None or alert["level"] == level:
                            alerts.append(alert)
                except:
                    continue

        return alerts


class Logger:
    """Guardian 2.0 Logger"""

    LOG_DIR = Path("/opt/luxia/guardian/logs")

    def __init__(self, name: str = "guardian", log_dir: Optional[Path] = None):
        self.log_dir = log_dir or self.LOG_DIR
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()

        self.alert_logger = AlertLogger(self.log_dir)

    def _setup_handlers(self):
        """Setup logging handlers"""
        # Console handler (colored)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(ColoredFormatter())
        self.logger.addHandler(console_handler)

        # File handler (rotating, plain text)
        file_handler = RotatingFileHandler(
            self.log_dir / "guardian.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        ))
        self.logger.addHandler(file_handler)

        # JSON handler for log aggregation
        json_handler = RotatingFileHandler(
            self.log_dir / "guardian.jsonl",
            maxBytes=10 * 1024 * 1024,
            backupCount=5
        )
        json_handler.setLevel(logging.INFO)
        json_handler.setFormatter(JSONFormatter())
        self.logger.addHandler(json_handler)

    def debug(self, msg: str, **kwargs):
        self.logger.debug(msg, extra={'extra_data': kwargs} if kwargs else {})

    def info(self, msg: str, **kwargs):
        self.logger.info(msg, extra={'extra_data': kwargs} if kwargs else {})

    def warning(self, msg: str, **kwargs):
        self.logger.warning(msg, extra={'extra_data': kwargs} if kwargs else {})

    def error(self, msg: str, **kwargs):
        self.logger.error(msg, extra={'extra_data': kwargs} if kwargs else {})

    def critical(self, msg: str, **kwargs):
        self.logger.critical(msg, extra={'extra_data': kwargs} if kwargs else {})

    def alert(
        self,
        level: str,
        alert_type: str,
        description: str,
        details: Dict[str, Any],
        action_taken: Optional[str] = None
    ) -> Dict[str, Any]:
        """Log a security alert"""
        # Log to standard logger
        log_method = getattr(self.logger, level.lower(), self.logger.warning)
        log_method(f"[ALERT:{alert_type}] {description}")

        # Log to alerts file
        return self.alert_logger.log_alert(
            level, alert_type, description, details, action_taken
        )

    def get_recent_alerts(self, hours: int = 24, level: Optional[str] = None) -> list:
        """Get recent alerts"""
        return self.alert_logger.get_recent_alerts(hours, level)
