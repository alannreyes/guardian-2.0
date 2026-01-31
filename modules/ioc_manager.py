"""
Guardian 2.0 - IOC Manager
===========================
Manages Indicators of Compromise from multiple threat intelligence feeds.
Supports:
- ThreatFox (abuse.ch)
- AbuseIPDB
- Blocklist.de
- Feodo Tracker
- NIST NVD (CVEs)
- Local custom IOCs
"""

import os
import re
import json
import sqlite3
import hashlib
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import Config
from core.logger import Logger


@dataclass
class IOCMatch:
    """Represents a matched IOC"""
    ioc_type: str           # ip, domain, hash, process_name
    value: str              # The actual IOC value
    source: str             # Where it came from (threatfox, abuseipdb, etc.)
    threat_type: str        # cryptominer, botnet, c2, ransomware, etc.
    confidence: float       # 0.0 to 1.0
    description: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    references: Optional[List[str]] = None


class IOCDatabase:
    """SQLite database for IOC storage and lookup"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                value_hash TEXT NOT NULL,
                source TEXT NOT NULL,
                threat_type TEXT,
                confidence REAL DEFAULT 0.5,
                description TEXT,
                first_seen TEXT,
                last_seen TEXT,
                references_json TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(value_hash, source)
            )
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ioc_hash ON iocs(value_hash)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type)
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feed_updates (
                feed_name TEXT PRIMARY KEY,
                last_update TEXT,
                entries_count INTEGER,
                status TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def add_ioc(self, ioc: Dict[str, Any]) -> bool:
        """Add or update an IOC"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        value_hash = hashlib.sha256(
            f"{ioc['ioc_type']}:{ioc['value']}".encode()
        ).hexdigest()

        try:
            cursor.execute('''
                INSERT INTO iocs (
                    ioc_type, value, value_hash, source, threat_type,
                    confidence, description, first_seen, last_seen, references_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(value_hash, source) DO UPDATE SET
                    confidence = excluded.confidence,
                    description = excluded.description,
                    last_seen = excluded.last_seen,
                    updated_at = CURRENT_TIMESTAMP
            ''', (
                ioc.get('ioc_type'),
                ioc.get('value'),
                value_hash,
                ioc.get('source'),
                ioc.get('threat_type'),
                ioc.get('confidence', 0.5),
                ioc.get('description'),
                ioc.get('first_seen'),
                ioc.get('last_seen'),
                json.dumps(ioc.get('references', []))
            ))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding IOC: {e}")
            return False
        finally:
            conn.close()

    def lookup(self, value: str, ioc_type: Optional[str] = None) -> List[IOCMatch]:
        """Lookup an IOC value"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Hash the value for lookup
        if ioc_type:
            value_hash = hashlib.sha256(f"{ioc_type}:{value}".encode()).hexdigest()
            cursor.execute(
                'SELECT * FROM iocs WHERE value_hash = ?',
                (value_hash,)
            )
        else:
            # Search by raw value
            cursor.execute(
                'SELECT * FROM iocs WHERE value = ?',
                (value,)
            )

        results = []
        for row in cursor.fetchall():
            results.append(IOCMatch(
                ioc_type=row[1],
                value=row[2],
                source=row[4],
                threat_type=row[5] or "unknown",
                confidence=row[6] or 0.5,
                description=row[7] or "",
                first_seen=row[8],
                last_seen=row[9],
                references=json.loads(row[10]) if row[10] else []
            ))

        conn.close()
        return results

    def update_feed_status(self, feed_name: str, count: int, status: str):
        """Update feed sync status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO feed_updates (feed_name, last_update, entries_count, status)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(feed_name) DO UPDATE SET
                last_update = excluded.last_update,
                entries_count = excluded.entries_count,
                status = excluded.status
        ''', (feed_name, datetime.utcnow().isoformat(), count, status))

        conn.commit()
        conn.close()

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM iocs')
        total = cursor.fetchone()[0]

        cursor.execute('SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type')
        by_type = dict(cursor.fetchall())

        cursor.execute('SELECT source, COUNT(*) FROM iocs GROUP BY source')
        by_source = dict(cursor.fetchall())

        cursor.execute('SELECT * FROM feed_updates')
        feeds = {row[0]: {
            'last_update': row[1],
            'count': row[2],
            'status': row[3]
        } for row in cursor.fetchall()}

        conn.close()

        return {
            'total_iocs': total,
            'by_type': by_type,
            'by_source': by_source,
            'feeds': feeds
        }


class IOCManager:
    """Main IOC Manager class"""

    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.db = IOCDatabase(Path("/opt/luxia/guardian/data/iocs.db"))

        # API keys
        self.abuseipdb_key = config.get_secret("abuseipdb_api_key")
        self.threatfox_enabled = config.get("ioc.feeds.threatfox.enabled", True)

        # Load local patterns
        self.mining_ports = set(config.mining_ports)
        self.suspicious_patterns = [
            re.compile(p) for p in config.suspicious_patterns
        ]

    def update_all_feeds(self) -> Dict[str, Any]:
        """Update all IOC feeds"""
        self.logger.info("Starting IOC feed update...")
        results = {}

        feeds = [
            ("blocklist_de", self._fetch_blocklist_de),
            ("feodo", self._fetch_feodo),
            ("mining_pools", self._fetch_mining_pools),
        ]

        # ThreatFox needs special handling (API-based)
        if self.threatfox_enabled:
            feeds.append(("threatfox", self._fetch_threatfox))

        for feed_name, fetch_func in feeds:
            try:
                count = fetch_func()
                self.db.update_feed_status(feed_name, count, "success")
                results[feed_name] = {"status": "success", "count": count}
                self.logger.info(f"Updated {feed_name}: {count} entries")
            except Exception as e:
                self.db.update_feed_status(feed_name, 0, f"error: {str(e)}")
                results[feed_name] = {"status": "error", "error": str(e)}
                self.logger.error(f"Failed to update {feed_name}: {e}")

        return results

    def _fetch_blocklist_de(self) -> int:
        """Fetch IPs from blocklist.de"""
        url = self.config.get(
            "ioc.feeds.blocklist_de.url",
            "https://lists.blocklist.de/lists/all.txt"
        )
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        count = 0
        for line in response.text.strip().split('\n'):
            ip = line.strip()
            if ip and not ip.startswith('#'):
                self.db.add_ioc({
                    'ioc_type': 'ip',
                    'value': ip,
                    'source': 'blocklist_de',
                    'threat_type': 'attacker',
                    'confidence': 0.7,
                    'description': 'Reported attacker IP'
                })
                count += 1

        return count

    def _fetch_feodo(self) -> int:
        """Fetch C2 IPs from Feodo Tracker"""
        url = self.config.get(
            "ioc.feeds.feodo.url",
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
        )
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        count = 0
        for line in response.text.strip().split('\n'):
            ip = line.strip()
            if ip and not ip.startswith('#'):
                self.db.add_ioc({
                    'ioc_type': 'ip',
                    'value': ip,
                    'source': 'feodo',
                    'threat_type': 'c2',
                    'confidence': 0.9,
                    'description': 'Feodo/Emotet/Dridex C2 server'
                })
                count += 1

        return count

    def _fetch_mining_pools(self) -> int:
        """Fetch known mining pool IPs/domains"""
        # Static list of well-known mining pools
        pools = [
            "pool.minexmr.com", "xmr.pool.minergate.com",
            "monerohash.com", "xmrpool.eu", "supportxmr.com",
            "pool.hashvault.pro", "xmr-usa.dwarfpool.com",
            "xmr.2miners.com", "xmr.nanopool.org"
        ]

        count = 0
        for pool in pools:
            self.db.add_ioc({
                'ioc_type': 'domain',
                'value': pool,
                'source': 'mining_pools',
                'threat_type': 'cryptominer',
                'confidence': 0.95,
                'description': 'Known cryptocurrency mining pool'
            })
            count += 1

        return count

    def _fetch_threatfox(self) -> int:
        """Fetch recent IOCs from ThreatFox API"""
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "get_iocs", "days": 7}

        response = requests.post(url, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()

        if data.get("query_status") != "ok":
            raise Exception(f"ThreatFox API error: {data.get('query_status')}")

        count = 0
        for ioc in data.get("data", []):
            ioc_type = "ip" if ":" in ioc.get("ioc", "") else "domain"
            if ioc.get("ioc_type") == "sha256_hash":
                ioc_type = "hash"

            self.db.add_ioc({
                'ioc_type': ioc_type,
                'value': ioc.get("ioc", "").split(":")[0],  # Remove port if present
                'source': 'threatfox',
                'threat_type': ioc.get("malware", "unknown").lower(),
                'confidence': min(ioc.get("confidence_level", 50) / 100, 1.0),
                'description': ioc.get("threat_type", ""),
                'first_seen': ioc.get("first_seen"),
                'last_seen': ioc.get("last_seen"),
                'references': [ioc.get("reference")] if ioc.get("reference") else []
            })
            count += 1

        return count

    def check_ip(self, ip: str) -> List[IOCMatch]:
        """Check if an IP is malicious"""
        matches = self.db.lookup(ip, "ip")

        # Also check AbuseIPDB if we have a key
        if self.abuseipdb_key and not matches:
            abuseipdb_result = self._check_abuseipdb(ip)
            if abuseipdb_result:
                matches.append(abuseipdb_result)

        return matches

    def _check_abuseipdb(self, ip: str) -> Optional[IOCMatch]:
        """Check IP against AbuseIPDB"""
        if not self.abuseipdb_key:
            return None

        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10
            )
            response.raise_for_status()
            data = response.json().get("data", {})

            if data.get("abuseConfidenceScore", 0) > 25:
                return IOCMatch(
                    ioc_type="ip",
                    value=ip,
                    source="abuseipdb",
                    threat_type="reported_abuser",
                    confidence=data["abuseConfidenceScore"] / 100,
                    description=f"Reported {data.get('totalReports', 0)} times. ISP: {data.get('isp', 'Unknown')}"
                )
        except Exception as e:
            self.logger.warning(f"AbuseIPDB check failed: {e}")

        return None

    def check_process(self, process_name: str, process_path: str = "") -> List[IOCMatch]:
        """Check if a process name/path matches known malware patterns"""
        matches = []

        # Check against suspicious patterns
        full_check = f"{process_path}/{process_name}" if process_path else process_name

        for pattern in self.suspicious_patterns:
            if pattern.search(full_check):
                matches.append(IOCMatch(
                    ioc_type="process_name",
                    value=process_name,
                    source="local_patterns",
                    threat_type="suspicious",
                    confidence=0.7,
                    description=f"Matches suspicious pattern: {pattern.pattern}"
                ))

        # Check in database
        db_matches = self.db.lookup(process_name, "process_name")
        matches.extend(db_matches)

        return matches

    def check_port(self, port: int) -> Optional[IOCMatch]:
        """Check if a port is associated with mining/malware"""
        if port in self.mining_ports:
            return IOCMatch(
                ioc_type="port",
                value=str(port),
                source="local_patterns",
                threat_type="cryptominer",
                confidence=0.85,
                description=f"Port {port} is commonly used by cryptocurrency miners"
            )
        return None

    def check_hash(self, file_hash: str) -> List[IOCMatch]:
        """Check if a file hash is known malware"""
        return self.db.lookup(file_hash, "hash")

    def get_stats(self) -> Dict[str, Any]:
        """Get IOC database statistics"""
        return self.db.get_stats()
