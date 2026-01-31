"""
Guardian 2.0 - Auto-Remediation Engine
=======================================
Automated threat response:
- Kill malicious processes
- Stop compromised containers
- Block malicious IPs
- Quarantine suspicious files
"""

import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

from core.config import Config
from core.logger import Logger


@dataclass
class RemediationResult:
    """Result of a remediation action"""
    success: bool
    action: str
    target: str
    command: str
    output: str
    error: Optional[str] = None
    rollback_command: Optional[str] = None


class Remediator:
    """Automated threat remediation engine"""

    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.enabled = config.get("remediation.enabled", True)

        # Action permissions
        self.can_kill_process = config.get("remediation.allowed_actions.kill_process", True)
        self.can_stop_container = config.get("remediation.allowed_actions.stop_container", True)
        self.can_block_ip = config.get("remediation.allowed_actions.block_ip", True)

        # Protected resources
        self.protected_containers = set(config.protected_containers)

        # Quarantine path
        self.quarantine_path = Path(
            config.get("remediation.quarantine_path", "/opt/luxia/guardian/quarantine")
        )
        self.quarantine_path.mkdir(parents=True, exist_ok=True)

        # Track actions for potential rollback
        self.action_history: List[RemediationResult] = []

    def _run_command(self, cmd: str, timeout: int = 30) -> Tuple[int, str, str]:
        """Run a shell command and return (exit_code, stdout, stderr)"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def kill_process(self, pid: int, process_name: str = "") -> RemediationResult:
        """Kill a malicious process"""
        if not self.enabled or not self.can_kill_process:
            return RemediationResult(
                success=False,
                action="kill_process",
                target=f"PID {pid}",
                command="",
                output="",
                error="Process killing is disabled"
            )

        self.logger.warning(f"Killing process: PID {pid} ({process_name})")

        # First try graceful termination
        cmd = f"kill -15 {pid}"
        code, out, err = self._run_command(cmd)

        if code != 0:
            # Force kill
            cmd = f"kill -9 {pid}"
            code, out, err = self._run_command(cmd)

        result = RemediationResult(
            success=code == 0,
            action="kill_process",
            target=f"PID {pid} ({process_name})",
            command=cmd,
            output=out,
            error=err if code != 0 else None
        )

        self.action_history.append(result)

        if result.success:
            self.logger.info(f"Successfully killed process {pid}")
        else:
            self.logger.error(f"Failed to kill process {pid}: {err}")

        return result

    def stop_container(self, container_name: str, force: bool = False) -> RemediationResult:
        """Stop a compromised Docker container"""

        # Check if container is protected
        if container_name in self.protected_containers:
            self.logger.warning(f"Container {container_name} is protected, cannot auto-stop")
            return RemediationResult(
                success=False,
                action="stop_container",
                target=container_name,
                command="",
                output="",
                error=f"Container {container_name} is in protected list"
            )

        if not self.enabled or not self.can_stop_container:
            return RemediationResult(
                success=False,
                action="stop_container",
                target=container_name,
                command="",
                output="",
                error="Container stopping is disabled"
            )

        self.logger.warning(f"Stopping container: {container_name}")

        if force:
            cmd = f"docker kill {container_name}"
        else:
            cmd = f"docker stop {container_name}"

        code, out, err = self._run_command(cmd, timeout=60)

        result = RemediationResult(
            success=code == 0,
            action="stop_container",
            target=container_name,
            command=cmd,
            output=out,
            error=err if code != 0 else None,
            rollback_command=f"docker start {container_name}"
        )

        self.action_history.append(result)

        if result.success:
            self.logger.info(f"Successfully stopped container {container_name}")
        else:
            self.logger.error(f"Failed to stop container {container_name}: {err}")

        return result

    def block_ip(self, ip: str, reason: str = "") -> RemediationResult:
        """Block an IP address using iptables"""
        if not self.enabled or not self.can_block_ip:
            return RemediationResult(
                success=False,
                action="block_ip",
                target=ip,
                command="",
                output="",
                error="IP blocking is disabled"
            )

        self.logger.warning(f"Blocking IP: {ip} (reason: {reason})")

        # Check if already blocked
        check_cmd = f"iptables -C INPUT -s {ip} -j DROP 2>/dev/null"
        code, _, _ = self._run_command(check_cmd)

        if code == 0:
            return RemediationResult(
                success=True,
                action="block_ip",
                target=ip,
                command=check_cmd,
                output="IP already blocked",
                rollback_command=f"iptables -D INPUT -s {ip} -j DROP"
            )

        # Block the IP
        cmd = f"iptables -I INPUT -s {ip} -j DROP"
        code, out, err = self._run_command(cmd)

        result = RemediationResult(
            success=code == 0,
            action="block_ip",
            target=ip,
            command=cmd,
            output=out,
            error=err if code != 0 else None,
            rollback_command=f"iptables -D INPUT -s {ip} -j DROP"
        )

        self.action_history.append(result)

        if result.success:
            self.logger.info(f"Successfully blocked IP {ip}")
        else:
            self.logger.error(f"Failed to block IP {ip}: {err}")

        return result

    def quarantine_file(self, file_path: str) -> RemediationResult:
        """Move a suspicious file to quarantine"""
        src = Path(file_path)

        if not src.exists():
            return RemediationResult(
                success=False,
                action="quarantine_file",
                target=file_path,
                command="",
                output="",
                error="File does not exist"
            )

        # Create quarantine destination
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = self.quarantine_path / f"{timestamp}_{src.name}"

        try:
            # Copy file metadata for forensics
            metadata = {
                "original_path": str(src),
                "quarantined_at": datetime.now().isoformat(),
                "size": src.stat().st_size,
                "mode": oct(src.stat().st_mode),
                "uid": src.stat().st_uid,
                "gid": src.stat().st_gid
            }

            # Move file
            shutil.move(str(src), str(dest))

            # Save metadata
            with open(f"{dest}.meta.json", "w") as f:
                import json
                json.dump(metadata, f, indent=2)

            result = RemediationResult(
                success=True,
                action="quarantine_file",
                target=file_path,
                command=f"mv {src} {dest}",
                output=f"File quarantined to {dest}",
                rollback_command=f"mv {dest} {src}"
            )

            self.action_history.append(result)
            self.logger.info(f"Quarantined file: {src} -> {dest}")
            return result

        except Exception as e:
            return RemediationResult(
                success=False,
                action="quarantine_file",
                target=file_path,
                command="",
                output="",
                error=str(e)
            )

    def kill_container_process(
        self,
        container_name: str,
        pid_in_container: int,
        process_name: str = ""
    ) -> RemediationResult:
        """Kill a process inside a container"""
        if not self.enabled or not self.can_kill_process:
            return RemediationResult(
                success=False,
                action="kill_container_process",
                target=f"{container_name}:PID {pid_in_container}",
                command="",
                output="",
                error="Process killing is disabled"
            )

        self.logger.warning(
            f"Killing process in container: {container_name}:PID {pid_in_container} ({process_name})"
        )

        cmd = f"docker exec {container_name} kill -9 {pid_in_container}"
        code, out, err = self._run_command(cmd)

        result = RemediationResult(
            success=code == 0,
            action="kill_container_process",
            target=f"{container_name}:PID {pid_in_container} ({process_name})",
            command=cmd,
            output=out,
            error=err if code != 0 else None
        )

        self.action_history.append(result)
        return result

    def execute_remediation(
        self,
        action: str,
        target: str,
        custom_command: Optional[str] = None,
        **kwargs
    ) -> RemediationResult:
        """Execute a remediation action"""

        if action == "kill_process":
            return self.kill_process(int(target), kwargs.get("process_name", ""))

        elif action == "stop_container":
            return self.stop_container(target, kwargs.get("force", False))

        elif action == "block_ip":
            return self.block_ip(target, kwargs.get("reason", ""))

        elif action == "quarantine_file":
            return self.quarantine_file(target)

        elif action == "kill_container_process":
            return self.kill_container_process(
                kwargs.get("container_name", ""),
                int(target),
                kwargs.get("process_name", "")
            )

        elif action == "custom" and custom_command:
            self.logger.warning(f"Executing custom remediation: {custom_command}")
            code, out, err = self._run_command(custom_command)
            result = RemediationResult(
                success=code == 0,
                action="custom",
                target=target,
                command=custom_command,
                output=out,
                error=err if code != 0 else None,
                rollback_command=kwargs.get("rollback_command")
            )
            self.action_history.append(result)
            return result

        else:
            return RemediationResult(
                success=False,
                action=action,
                target=target,
                command="",
                output="",
                error=f"Unknown action: {action}"
            )

    def rollback_last_action(self) -> Optional[RemediationResult]:
        """Rollback the last remediation action"""
        if not self.action_history:
            self.logger.warning("No actions to rollback")
            return None

        last_action = self.action_history[-1]

        if not last_action.rollback_command:
            self.logger.warning(f"No rollback command for action: {last_action.action}")
            return None

        self.logger.info(f"Rolling back: {last_action.action} on {last_action.target}")

        code, out, err = self._run_command(last_action.rollback_command)

        return RemediationResult(
            success=code == 0,
            action=f"rollback_{last_action.action}",
            target=last_action.target,
            command=last_action.rollback_command,
            output=out,
            error=err if code != 0 else None
        )

    def get_action_history(self) -> List[Dict[str, Any]]:
        """Get history of remediation actions"""
        return [
            {
                "success": r.success,
                "action": r.action,
                "target": r.target,
                "command": r.command,
                "output": r.output,
                "error": r.error,
                "rollback_command": r.rollback_command
            }
            for r in self.action_history
        ]
