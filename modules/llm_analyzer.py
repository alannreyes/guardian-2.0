"""
Guardian 2.0 - LLM Analyzer
============================
Intelligent analysis engine powered by Claude.
Uses LLM for:
- Anomaly analysis and triage
- Signal correlation
- IOC enrichment
- Remediation decisions
- Executive summaries
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

from core.config import Config
from core.logger import Logger


@dataclass
class ThreatAnalysis:
    """Result of threat analysis"""
    threat_level: str           # critical, high, medium, low, info
    confidence: float           # 0.0 to 1.0
    threat_type: str            # cryptominer, backdoor, botnet, etc.
    analysis: str               # Human-readable explanation
    recommended_action: str     # none, monitor, alert, contain, kill
    auto_remediate: bool        # Should we auto-remediate?
    remediation_command: Optional[str] = None
    rollback_command: Optional[str] = None
    ioc_matches: Optional[List[Dict]] = None


@dataclass
class CorrelationResult:
    """Result of signal correlation"""
    correlated: bool
    threat_type: str
    confidence: float
    explanation: str
    signals_used: List[str]
    recommended_action: str


class LLMAnalyzer:
    """LLM-powered threat analysis engine"""

    SYSTEM_PROMPT = """You are Guardian, an advanced security analysis AI for Linux servers.
Your role is to analyze security anomalies and make intelligent decisions about threats.

CRITICAL RULES:
1. You protect production servers - false negatives are worse than false positives
2. Always explain your reasoning clearly
3. Consider the FULL context before recommending actions
4. Be especially vigilant about cryptominers, backdoors, and C2 communications
5. Never recommend stopping critical services without very high confidence

KNOWN ATTACK PATTERNS:
- Cryptominers: Processes in /tmp, connections to ports 3333/5555/7777, high CPU
- Backdoors: Unexpected listeners, reverse shells, unusual outbound connections
- C2: Periodic beaconing, encoded communications, connections to known bad IPs
- Webshells: PHP/JSP files in web directories, unusual web server child processes

When analyzing, consider:
- Time of day (attacks often happen at night)
- Process lineage (what spawned this process?)
- Network connections (where is it communicating?)
- File locations (executables in /tmp are suspicious)
- Resource usage patterns (sudden spikes are suspicious)

Respond ONLY with valid JSON. No markdown, no explanation outside JSON."""

    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.enabled = config.get("llm.enabled", True)
        self.model = config.get("llm.model", "claude-sonnet-4-20250514")
        self.min_confidence = config.get("llm.analysis.min_confidence_for_action", 0.85)
        self.max_tokens = config.get("llm.analysis.max_tokens", 1000)

        # Initialize Anthropic client
        self.client = None
        if self.enabled:
            api_key = config.get_secret("anthropic_api_key")
            if api_key:
                try:
                    from anthropic import Anthropic
                    self.client = Anthropic(api_key=api_key)
                    self.logger.info("LLM Analyzer initialized successfully")
                except ImportError:
                    self.logger.error("anthropic package not installed")
                    self.enabled = False
            else:
                self.logger.warning("No Anthropic API key found, LLM disabled")
                self.enabled = False

    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information before sending to LLM"""
        sensitive_patterns = [
            r'password[=:]\s*\S+',
            r'api[_-]?key[=:]\s*\S+',
            r'token[=:]\s*\S+',
            r'secret[=:]\s*\S+',
            r'Authorization:\s*Bearer\s+\S+',
            r'-----BEGIN.*PRIVATE KEY-----',
        ]

        def sanitize_value(v):
            if isinstance(v, str):
                for pattern in sensitive_patterns:
                    v = re.sub(pattern, '[REDACTED]', v, flags=re.I)
                return v
            elif isinstance(v, dict):
                return {k: sanitize_value(val) for k, val in v.items()}
            elif isinstance(v, list):
                return [sanitize_value(item) for item in v]
            return v

        return sanitize_value(data)

    def _call_llm(self, prompt: str) -> Optional[str]:
        """Make a call to Claude API"""
        if not self.client:
            return None

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=self.SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            self.logger.error(f"LLM API call failed: {e}")
            return None

    def _parse_json_response(self, response: str) -> Optional[Dict]:
        """Parse JSON from LLM response"""
        if not response:
            return None

        # Try to extract JSON if wrapped in markdown
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', response)
        if json_match:
            response = json_match.group(1)

        try:
            return json.loads(response.strip())
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse LLM JSON response: {e}")
            return None

    def analyze_threat(
        self,
        anomaly: Dict[str, Any],
        ioc_results: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> ThreatAnalysis:
        """Analyze a potential threat and decide on action"""

        if not self.enabled:
            return self._fallback_analysis(anomaly, ioc_results)

        # Sanitize data
        safe_anomaly = self._sanitize_data(anomaly)
        safe_context = self._sanitize_data(context)

        prompt = f"""Analyze this security anomaly and decide what action to take.

SERVER CONTEXT:
- Hostname: {safe_context.get('hostname', 'unknown')}
- Environment: {safe_context.get('environment', 'production')}
- Critical services (DO NOT auto-stop): {safe_context.get('critical_services', [])}
- Normal baseline CPU: {safe_context.get('baseline_cpu', 'unknown')}%
- Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

ANOMALY DETECTED:
{json.dumps(safe_anomaly, indent=2)}

IOC LOOKUP RESULTS:
{json.dumps(ioc_results, indent=2)}

Respond with JSON:
{{
    "threat_level": "critical|high|medium|low|info",
    "confidence": 0.0-1.0,
    "threat_type": "cryptominer|backdoor|botnet|c2|ransomware|bruteforce|unknown",
    "analysis": "Clear explanation of what you found and why",
    "recommended_action": "none|monitor|alert|contain|kill",
    "auto_remediate": true|false,
    "remediation_command": "specific command if auto_remediate is true",
    "rollback_command": "command to undo remediation if needed"
}}"""

        response = self._call_llm(prompt)
        result = self._parse_json_response(response)

        if not result:
            return self._fallback_analysis(anomaly, ioc_results)

        return ThreatAnalysis(
            threat_level=result.get("threat_level", "medium"),
            confidence=float(result.get("confidence", 0.5)),
            threat_type=result.get("threat_type", "unknown"),
            analysis=result.get("analysis", "Analysis unavailable"),
            recommended_action=result.get("recommended_action", "alert"),
            auto_remediate=result.get("auto_remediate", False) and
                          float(result.get("confidence", 0)) >= self.min_confidence,
            remediation_command=result.get("remediation_command"),
            rollback_command=result.get("rollback_command"),
            ioc_matches=ioc_results
        )

    def correlate_signals(
        self,
        signals: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> CorrelationResult:
        """Correlate multiple weak signals to detect coordinated attacks"""

        if not self.enabled or len(signals) < 2:
            return CorrelationResult(
                correlated=False,
                threat_type="unknown",
                confidence=0.0,
                explanation="Insufficient signals for correlation",
                signals_used=[],
                recommended_action="monitor"
            )

        safe_signals = self._sanitize_data(signals)

        prompt = f"""Analyze these security signals and determine if they indicate a coordinated attack.

SIGNALS DETECTED (last 15 minutes):
{json.dumps(safe_signals, indent=2)}

SERVER CONTEXT:
- Environment: {context.get('environment', 'production')}
- Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Look for patterns like:
- Cryptomining: new process + high CPU + outbound connection to mining port
- Backdoor installation: file created + process spawned + new listener
- Data exfiltration: unusual outbound traffic + file access patterns

Respond with JSON:
{{
    "correlated": true|false,
    "threat_type": "cryptominer|backdoor|botnet|c2|exfiltration|unknown",
    "confidence": 0.0-1.0,
    "explanation": "Why these signals are (or aren't) related",
    "signals_used": ["signal1", "signal2"],
    "recommended_action": "none|monitor|alert|contain|kill"
}}"""

        response = self._call_llm(prompt)
        result = self._parse_json_response(response)

        if not result:
            return CorrelationResult(
                correlated=False,
                threat_type="unknown",
                confidence=0.0,
                explanation="Correlation analysis failed",
                signals_used=[],
                recommended_action="monitor"
            )

        return CorrelationResult(
            correlated=result.get("correlated", False),
            threat_type=result.get("threat_type", "unknown"),
            confidence=float(result.get("confidence", 0.0)),
            explanation=result.get("explanation", ""),
            signals_used=result.get("signals_used", []),
            recommended_action=result.get("recommended_action", "monitor")
        )

    def generate_summary(self, report_data: Dict[str, Any]) -> str:
        """Generate executive summary for daily report - BULLET FORMAT, MAX 3 LINES"""

        if not self.enabled:
            return self._generate_static_summary(report_data)

        safe_data = self._sanitize_data(report_data)

        prompt = f"""Analiza este reporte de seguridad y genera un resumen ejecutivo MUY BREVE.

DATOS:
{json.dumps(safe_data, indent=2)}

RESPONDE SOLO CON 3 LÍNEAS en este formato exacto (sin JSON, sin markdown):
• Puntuación X/100 - Estado [bueno/regular/crítico]
• [Hallazgo principal - positivo o negativo]
• [Acción necesaria O "Sin acciones pendientes"]

Ejemplo de respuesta correcta:
• Puntuación 85/100 - Estado bueno
• 12 contenedores activos, sin amenazas detectadas
• Sin acciones pendientes"""

        response = self._call_llm(prompt)

        if not response:
            return self._generate_static_summary(report_data)

        # Post-process: if LLM returned JSON, extract the summary
        if '```' in response or '{' in response:
            parsed = self._parse_json_response(response)
            if parsed:
                # Try to extract readable summary from JSON
                if 'executive_summary_spanish' in parsed:
                    return parsed['executive_summary_spanish']
                elif 'summary' in parsed:
                    return parsed['summary']
                elif 'executive_summary' in parsed:
                    return parsed['executive_summary']
            # If JSON but no summary field, generate static
            return self._generate_static_summary(report_data)

        # Clean up any markdown formatting
        response = response.replace('**', '').replace('`', '').strip()
        return response

    def _fallback_analysis(
        self,
        anomaly: Dict[str, Any],
        ioc_results: List[Dict[str, Any]]
    ) -> ThreatAnalysis:
        """Fallback analysis when LLM is unavailable"""

        # Simple rule-based analysis
        threat_level = "low"
        confidence = 0.5
        threat_type = "unknown"
        auto_remediate = False

        # Check IOC matches
        if ioc_results:
            max_conf = max(ioc.get("confidence", 0) for ioc in ioc_results)
            if max_conf > 0.8:
                threat_level = "critical"
                confidence = max_conf
                threat_type = ioc_results[0].get("threat_type", "unknown")
                auto_remediate = True

        # Check for obvious cryptominer indicators
        if anomaly.get("type") == "suspicious_process":
            if any(p in anomaly.get("process_name", "").lower()
                   for p in ["xmrig", "miner", ".svc"]):
                threat_level = "critical"
                confidence = 0.9
                threat_type = "cryptominer"
                auto_remediate = True

        return ThreatAnalysis(
            threat_level=threat_level,
            confidence=confidence,
            threat_type=threat_type,
            analysis="Fallback analysis (LLM unavailable)",
            recommended_action="alert" if threat_level in ["critical", "high"] else "monitor",
            auto_remediate=auto_remediate,
            remediation_command=anomaly.get("suggested_remediation"),
            ioc_matches=ioc_results
        )

    def _generate_static_summary(self, report_data: Dict[str, Any]) -> str:
        """Generate static summary without LLM - BULLET FORMAT"""
        score = report_data.get("health_score", 0)
        status = "excelente" if score >= 90 else "bueno" if score >= 70 else "requiere atención" if score >= 50 else "crítico"

        pending = report_data.get("pending_actions", [])
        critical = [a for a in pending if a.get("severity") == "critical"]

        lines = [
            f"• Puntuación {score}/100 - Estado {status}",
        ]

        if critical:
            lines.append(f"• {len(critical)} problemas críticos detectados")
            lines.append(f"• Acción requerida: revisar alertas")
        else:
            lines.append("• Sin problemas críticos detectados")
            lines.append("• Sin acciones pendientes")

        return "\n".join(lines)
