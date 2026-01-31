"""
Guardian 2.0 - Configuration Manager
=====================================
Handles loading, validation, and access to configuration.
Supports encrypted secrets file for sensitive data.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass


@dataclass
class ThresholdConfig:
    warning: int
    critical: int


@dataclass
class ServerConfig:
    name: str
    environment: str
    timezone: str
    critical_services: list


class Config:
    """Configuration manager for Guardian 2.0"""

    DEFAULT_CONFIG_PATH = "/opt/luxia/guardian/config.yaml"
    DEFAULT_SECRETS_PATH = "/opt/luxia/guardian/secrets/keys.yaml"

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = Path(config_path or os.environ.get(
            "GUARDIAN_CONFIG", self.DEFAULT_CONFIG_PATH
        ))
        self._config: Dict[str, Any] = {}
        self._secrets: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

        with open(self.config_path) as f:
            self._config = yaml.safe_load(f) or {}

        # Load secrets if specified
        secrets_file = self._config.get("secrets_file", self.DEFAULT_SECRETS_PATH)
        if Path(secrets_file).exists():
            self._load_secrets(secrets_file)

        # Also check for inline secrets (backward compatibility)
        self._merge_inline_secrets()

    def _load_secrets(self, path: str) -> None:
        """Load secrets from separate file"""
        try:
            with open(path) as f:
                self._secrets = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Warning: Could not load secrets file: {e}")

    def _merge_inline_secrets(self) -> None:
        """Merge inline secrets from config (backward compatibility)"""
        inline_keys = [
            "anthropic_api_key",
            "sendgrid_api_key",
            "telegram_bot_token",
            "abuseipdb_api_key"
        ]
        for key in inline_keys:
            if key in self._config and self._config[key]:
                self._secrets[key] = self._config[key]

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation (e.g., 'sentinel.enabled')"""
        keys = key.split(".")
        value = self._config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default

        return value

    def get_secret(self, key: str) -> Optional[str]:
        """Get a secret value"""
        return self._secrets.get(key) or os.environ.get(key.upper())

    @property
    def server(self) -> ServerConfig:
        """Get server configuration"""
        srv = self._config.get("server", {})
        return ServerConfig(
            name=srv.get("name", "unknown"),
            environment=srv.get("environment", "production"),
            timezone=srv.get("timezone", "UTC"),
            critical_services=srv.get("critical_services", [])
        )

    @property
    def thresholds(self) -> Dict[str, ThresholdConfig]:
        """Get threshold configurations"""
        th = self._config.get("thresholds", {})
        return {
            "cpu": ThresholdConfig(
                warning=th.get("cpu", {}).get("warning", 70),
                critical=th.get("cpu", {}).get("critical", 90)
            ),
            "memory": ThresholdConfig(
                warning=th.get("memory", {}).get("warning", 75),
                critical=th.get("memory", {}).get("critical", 90)
            ),
            "disk": ThresholdConfig(
                warning=th.get("disk", {}).get("warning", 70),
                critical=th.get("disk", {}).get("critical", 85)
            )
        }

    @property
    def is_maintenance_window(self) -> bool:
        """Check if current time is within maintenance window"""
        from datetime import datetime
        import pytz

        tz = pytz.timezone(self.server.timezone)
        now = datetime.now(tz)

        start = self.get("sentinel.maintenance_window.start_hour", 1)
        end = self.get("sentinel.maintenance_window.end_hour", 5)

        return start <= now.hour < end

    @property
    def check_interval(self) -> int:
        """Get current check interval based on maintenance window"""
        if self.is_maintenance_window:
            return self.get("sentinel.maintenance_window.check_interval_seconds", 60)
        return self.get("sentinel.check_interval_seconds", 300)

    @property
    def mining_ports(self) -> list:
        """Get list of known mining ports"""
        return self.get("ioc.mining_ports", [3333, 4444, 5555, 7777, 9999])

    @property
    def suspicious_patterns(self) -> list:
        """Get suspicious process patterns"""
        return self.get("ioc.suspicious_process_patterns", [])

    @property
    def protected_containers(self) -> list:
        """Get list of containers that should never be auto-stopped"""
        return self.get("remediation.protected_containers", [])

    def to_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary (without secrets)"""
        return self._config.copy()
