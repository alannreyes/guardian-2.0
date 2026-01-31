"""
Guardian 2.0 - Sentinel (Real-time Monitoring Daemon)
======================================================
Continuous monitoring daemon that:
- Runs 24/7 in background
- Checks for threats every 5 minutes (1 minute during maintenance window)
- Correlates signals to detect coordinated attacks
- Triggers auto-remediation when confidence is high
- Sends immediate alerts for critical threats
"""

import os
import re
import time
import signal
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
from dataclasses import dataclass, field
from collections import deque
import threading
import json

from core.config import Config
from core.logger import Logger
from modules.ioc_manager import IOCManager, IOCMatch
from modules.llm_analyzer import LLMAnalyzer, ThreatAnalysis
from modules.notifier import Notifier
from modules.remediator import Remediator


@dataclass
class Signal:
    """A security signal/event"""
    timestamp: datetime
    signal_type: str
    source: str
    description: str
    data: Dict[str, Any]
    severity: str = "low"  # low, medium, high, critical


@dataclass
class ProcessInfo:
    """Information about a running process"""
    pid: int
    user: str
    cpu: float
    mem: float
    command: str
    container: Optional[str] = None


class Sentinel:
    """Real-time monitoring daemon"""

    def __init__(
        self,
        config: Config,
        logger: Logger,
        ioc_manager: IOCManager,
        llm_analyzer: LLMAnalyzer,
        notifier: Notifier,
        remediator: Remediator
    ):
        self.config = config
        self.logger = logger
        self.ioc_manager = ioc_manager
        self.llm_analyzer = llm_analyzer
        self.notifier = notifier
        self.remediator = remediator

        # State
        self.running = False
        self.signals: deque = deque(maxlen=1000)  # Last 1000 signals
        self.known_processes: Set[str] = set()
        self.baseline_established = False

        # Monitoring settings
        self.monitors = config.get("sentinel.monitors", {})

        # State file for persistence
        self.state_file = Path("/opt/luxia/guardian/data/sentinel_state.json")

    def _run_command(self, cmd: str, timeout: int = 30) -> tuple:
        """Run shell command"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"
        except Exception as e:
            return -1, "", str(e)

    def _add_signal(self, signal: Signal):
        """Add a signal to the queue"""
        self.signals.append(signal)
        self.logger.debug(f"Signal: [{signal.severity}] {signal.signal_type}: {signal.description}")

    def check_cpu_spike(self) -> List[Signal]:
        """Check for CPU spikes"""
        signals = []
        threshold = self.config.thresholds["cpu"].critical

        code, out, _ = self._run_command(
            "top -bn1 | grep 'Cpu(s)' | awk '{print 100 - $8}'"
        )

        if code == 0 and out.strip():
            try:
                cpu = float(out.strip())
                if cpu > threshold:
                    signals.append(Signal(
                        timestamp=datetime.now(),
                        signal_type="cpu_spike",
                        source="system",
                        description=f"CPU usage at {cpu:.1f}% (threshold: {threshold}%)",
                        data={"cpu_percent": cpu, "threshold": threshold},
                        severity="high" if cpu > 95 else "medium"
                    ))
            except ValueError:
                pass

        return signals

    def check_suspicious_processes(self) -> List[Signal]:
        """Check for suspicious processes"""
        signals = []

        # Get top CPU consumers
        code, out, _ = self._run_command(
            "ps aux --sort=-%cpu | head -20"
        )

        if code != 0:
            return signals

        suspicious_patterns = [
            r'^\.',           # Hidden files
            r'xmrig',
            r'xmr-?stak',
            r'minerd',
            r'kswapd0',       # Common miner disguise
            r'/tmp/',
            r'/dev/shm/',
            r'\.svc_',
        ]

        for line in out.strip().split('\n')[1:]:  # Skip header
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue

            user, pid, cpu, mem = parts[0], parts[1], float(parts[2]), float(parts[3])
            command = parts[10]

            # Check against patterns
            for pattern in suspicious_patterns:
                if re.search(pattern, command, re.I):
                    # Verify with IOC lookup
                    process_name = command.split()[0].split('/')[-1]
                    ioc_matches = self.ioc_manager.check_process(process_name, command)

                    signals.append(Signal(
                        timestamp=datetime.now(),
                        signal_type="suspicious_process",
                        source="process_monitor",
                        description=f"Suspicious process detected: {process_name}",
                        data={
                            "pid": int(pid),
                            "user": user,
                            "cpu": cpu,
                            "mem": mem,
                            "command": command,
                            "pattern_matched": pattern,
                            "ioc_matches": [m.__dict__ for m in ioc_matches] if ioc_matches else []
                        },
                        severity="critical" if ioc_matches else "high"
                    ))
                    break

            # Also flag high CPU processes not in baseline
            if cpu > 50 and command not in self.known_processes:
                if not any(s.data.get("pid") == int(pid) for s in signals):
                    signals.append(Signal(
                        timestamp=datetime.now(),
                        signal_type="unknown_high_cpu",
                        source="process_monitor",
                        description=f"Unknown process with high CPU: {command[:50]}",
                        data={
                            "pid": int(pid),
                            "user": user,
                            "cpu": cpu,
                            "command": command
                        },
                        severity="medium"
                    ))

        return signals

    def check_mining_connections(self) -> List[Signal]:
        """Check for connections to mining pools"""
        signals = []
        mining_ports = self.config.mining_ports

        # Get established connections
        code, out, _ = self._run_command("ss -tnp 2>/dev/null | grep ESTAB")

        if code != 0:
            return signals

        for line in out.strip().split('\n'):
            if not line:
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            # Parse remote address
            remote = parts[4]
            if ':' in remote:
                ip, port = remote.rsplit(':', 1)
                try:
                    port = int(port)
                except ValueError:
                    continue

                # Check if port is mining-related
                if port in mining_ports:
                    # Check IP against IOCs
                    ioc_matches = self.ioc_manager.check_ip(ip)

                    signals.append(Signal(
                        timestamp=datetime.now(),
                        signal_type="mining_connection",
                        source="network_monitor",
                        description=f"Connection to mining port detected: {ip}:{port}",
                        data={
                            "remote_ip": ip,
                            "remote_port": port,
                            "connection_line": line,
                            "ioc_matches": [m.__dict__ for m in ioc_matches] if ioc_matches else []
                        },
                        severity="critical"
                    ))

        return signals

    def check_container_anomalies(self) -> List[Signal]:
        """Check for anomalies in Docker containers"""
        signals = []

        # Get container processes
        code, out, _ = self._run_command(
            "docker ps -q 2>/dev/null | head -30"
        )

        if code != 0 or not out.strip():
            return signals

        for container_id in out.strip().split('\n'):
            if not container_id:
                continue

            # Get container name
            code, name_out, _ = self._run_command(
                f"docker inspect --format '{{{{.Name}}}}' {container_id}"
            )
            container_name = name_out.strip().lstrip('/') if code == 0 else container_id

            # Get processes in container
            code, procs_out, _ = self._run_command(
                f"docker top {container_id} aux 2>/dev/null"
            )

            if code != 0:
                continue

            for line in procs_out.strip().split('\n')[1:]:  # Skip header
                parts = line.split(None, 10)
                if len(parts) < 11:
                    continue

                command = parts[10]

                # Check for suspicious patterns in container processes
                suspicious_patterns = [r'xmrig', r'\.svc_', r'/tmp/sw', r'minerd']

                for pattern in suspicious_patterns:
                    if re.search(pattern, command, re.I):
                        signals.append(Signal(
                            timestamp=datetime.now(),
                            signal_type="container_suspicious_process",
                            source="container_monitor",
                            description=f"Suspicious process in container {container_name}",
                            data={
                                "container_id": container_id,
                                "container_name": container_name,
                                "command": command,
                                "pattern_matched": pattern,
                                "process_line": line
                            },
                            severity="critical"
                        ))
                        break

        return signals

    def check_new_executables(self) -> List[Signal]:
        """Check for new executable files in /tmp"""
        signals = []

        code, out, _ = self._run_command(
            "find /tmp /var/tmp /dev/shm -type f -executable -mmin -15 2>/dev/null"
        )

        if code == 0 and out.strip():
            for file_path in out.strip().split('\n'):
                if file_path:
                    signals.append(Signal(
                        timestamp=datetime.now(),
                        signal_type="new_executable",
                        source="file_monitor",
                        description=f"New executable in temp directory: {file_path}",
                        data={"file_path": file_path},
                        severity="high"
                    ))

        return signals

    def run_all_checks(self) -> List[Signal]:
        """Run all monitoring checks"""
        all_signals = []

        checks = [
            ("cpu_spike", self.check_cpu_spike),
            ("suspicious_processes", self.check_suspicious_processes),
            ("mining_connections", self.check_mining_connections),
            ("container_anomalies", self.check_container_anomalies),
            ("new_executables", self.check_new_executables),
        ]

        for check_name, check_func in checks:
            if self.monitors.get(check_name, True):
                try:
                    signals = check_func()
                    all_signals.extend(signals)
                except Exception as e:
                    self.logger.error(f"Check {check_name} failed: {e}")

        return all_signals

    def analyze_and_respond(self, signals: List[Signal]):
        """Analyze signals and take appropriate action"""
        if not signals:
            return

        # Add all signals to queue
        for signal in signals:
            self._add_signal(signal)

        # Get critical signals
        critical_signals = [s for s in signals if s.severity in ["critical", "high"]]

        if not critical_signals:
            return

        self.logger.warning(f"Found {len(critical_signals)} critical/high signals")

        # For each critical signal, analyze with LLM and potentially remediate
        for signal in critical_signals:
            # Build context
            context = {
                "hostname": self.config.server.name,
                "environment": self.config.server.environment,
                "critical_services": self.config.server.critical_services,
                "baseline_cpu": 10,  # TODO: from actual baseline
                "is_maintenance_window": self.config.is_maintenance_window
            }

            # Get IOC results
            ioc_results = []
            if "ioc_matches" in signal.data:
                ioc_results = signal.data["ioc_matches"]

            # Analyze with LLM
            analysis = self.llm_analyzer.analyze_threat(
                anomaly={
                    "type": signal.signal_type,
                    "description": signal.description,
                    **signal.data
                },
                ioc_results=ioc_results,
                context=context
            )

            self.logger.info(
                f"LLM Analysis: {analysis.threat_level} ({analysis.confidence:.0%}) - "
                f"{analysis.threat_type}: {analysis.analysis[:100]}..."
            )

            # Take action based on analysis
            if analysis.auto_remediate and analysis.remediation_command:
                self.logger.warning(f"Auto-remediation triggered: {analysis.remediation_command}")

                # Execute remediation
                if "docker stop" in analysis.remediation_command:
                    container = analysis.remediation_command.split()[-1]
                    result = self.remediator.stop_container(container)
                elif "kill" in analysis.remediation_command:
                    pid = int(re.search(r'\d+', analysis.remediation_command).group())
                    result = self.remediator.kill_process(pid)
                else:
                    result = self.remediator.execute_remediation(
                        "custom",
                        signal.signal_type,
                        custom_command=analysis.remediation_command,
                        rollback_command=analysis.rollback_command
                    )

                action_taken = f"Remediation {'succeeded' if result.success else 'failed'}: {result.command}"
            else:
                action_taken = None

            # Send notification
            self.notifier.send_alert(
                level=analysis.threat_level,
                title=f"{analysis.threat_type.upper()}: {signal.description[:50]}",
                description=analysis.analysis,
                details={
                    "signal_type": signal.signal_type,
                    "confidence": f"{analysis.confidence:.0%}",
                    "threat_type": analysis.threat_type,
                    **{k: str(v)[:100] for k, v in signal.data.items() if k != "ioc_matches"}
                },
                action_taken=action_taken,
                requires_attention=not analysis.auto_remediate
            )

    def run_once(self):
        """Run a single monitoring cycle"""
        self.logger.debug("Running monitoring cycle...")

        signals = self.run_all_checks()

        if signals:
            self.logger.info(f"Detected {len(signals)} signals")
            self.analyze_and_respond(signals)
        else:
            self.logger.debug("No signals detected")

    def start(self):
        """Start the sentinel daemon"""
        self.running = True
        self.logger.info("Sentinel daemon starting...")

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

        while self.running:
            try:
                self.run_once()

                # Sleep until next check
                interval = self.config.check_interval
                self.logger.debug(f"Sleeping for {interval} seconds...")
                time.sleep(interval)

            except Exception as e:
                self.logger.error(f"Error in monitoring cycle: {e}")
                time.sleep(60)  # Wait a minute before retrying

        self.logger.info("Sentinel daemon stopped")

    def stop(self):
        """Stop the sentinel daemon"""
        self.running = False
        self.logger.info("Sentinel daemon stopping...")

    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()

    def get_recent_signals(self, minutes: int = 60) -> List[Dict]:
        """Get signals from the last N minutes"""
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return [
            {
                "timestamp": s.timestamp.isoformat(),
                "type": s.signal_type,
                "severity": s.severity,
                "description": s.description,
                "data": s.data
            }
            for s in self.signals
            if s.timestamp >= cutoff
        ]
