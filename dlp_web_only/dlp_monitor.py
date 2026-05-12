import os
import re
import hashlib
import json
import logging
import csv
import shutil
import time
import socket
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Any, List, Dict, Set, Optional
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [Cyber Sentinel] - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cyber_sentinel.log'),
        logging.StreamHandler()
    ]
)

class SensitiveDataPatterns:
    """Define patterns for sensitive data detection"""
    
    PATTERNS = {
        'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',
        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'api_key': r'\b(?:[A-Za-z0-9+/]{32,}={0,2}|[A-Fa-f0-9]{32,64})\b',
        'aws_key': r'\bAKIA[0-9A-Z]{16}\b',
        'private_key': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
        'cvv': r'\b[0-9]{3,4}\b(?=.*(?:CVV|CVC|security code))',
    }
    
    @classmethod
    def scan_content(cls, content: str) -> Dict[str, List[str]]:
        """Scan content for sensitive data patterns"""
        findings = {}
        for pattern_name, pattern in cls.PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                findings[pattern_name] = matches
        return findings


class DLPAlert:
    """Handle alert generation and notification"""
    
    def __init__(self, alert_email: str = None, smtp_config: Dict = None):
        self.alert_email = alert_email
        self.smtp_config = smtp_config or {}
        self.alerts = []
        self.whitelist = set()  # Files/patterns to ignore
        self.statistics = defaultdict(int)  # Track alert statistics
    
    def create_alert(self, severity: str, message: str, details: Dict):
        """Create a security alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'message': message,
            'details': details
        }
        self.alerts.append(alert)
        logging.warning(f"[{severity}] {message}")
        
        if self.alert_email and self.smtp_config:
            self._send_email_alert(alert)
        
        return alert
    
    def _send_email_alert(self, alert: Dict):
        """Send email notification"""
        try:
            # Check if SMTP is configured
            if not self.smtp_config.get('server') or not self.smtp_config.get('port'):
                logging.info("SMTP not configured, skipping email")
                return
            
            msg = MIMEMultipart()
            msg['From'] = self.smtp_config.get('from_email', 'dlp@company.com')
            msg['To'] = self.alert_email
            msg['Subject'] = f"DLP Alert: {alert['severity']} - {alert['message']}"
            
            body = f"""
            Security Alert Generated
            
            Severity: {alert['severity']}
            Time: {alert['timestamp']}
            Message: {alert['message']}
            
            Details:
            {json.dumps(alert['details'], indent=2)}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send the email
            with smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port']) as server:
                if self.smtp_config.get('use_tls', True):
                    server.starttls()
                if self.smtp_config.get('username') and self.smtp_config.get('password'):
                    server.login(self.smtp_config['username'], self.smtp_config['password'])
                server.send_message(msg)
            
            logging.info(f"Alert email sent to {self.alert_email}")
            
        except Exception as e:
            logging.error(f"Failed to send email alert: {e}")
    
    def get_alerts(self, severity: str = None) -> List[Dict]:
        """Retrieve alerts, optionally filtered by severity"""
        if severity:
            return [a for a in self.alerts if a['severity'] == severity]
        return self.alerts
    
    def add_to_whitelist(self, item: str):
        """Add file path or pattern to whitelist"""
        self.whitelist.add(item)
        logging.info(f"Added to whitelist: {item}")
    
    def remove_from_whitelist(self, item: str):
        """Remove from whitelist"""
        self.whitelist.discard(item)
        logging.info(f"Removed from whitelist: {item}")
    
    def is_whitelisted(self, filepath: str) -> bool:
        """Check if file is whitelisted"""
        filepath_str = str(filepath)
        # Exact match
        if filepath_str in self.whitelist:
            return True
        # Pattern match
        for pattern in self.whitelist:
            if '*' in pattern and re.match(pattern.replace('*', '.*'), filepath_str):
                return True
        return False
    
    def get_statistics(self) -> Dict:
        """Get alert statistics"""
        severity_counts = defaultdict(int)
        pattern_counts = defaultdict(int)
        
        for alert in self.alerts:
            severity_counts[alert['severity']] += 1
            if 'findings' in alert.get('details', {}):
                for pattern in alert['details']['findings']:
                    pattern_counts[pattern] += 1
        
        return {
            'total_alerts': len(self.alerts),
            'by_severity': dict(severity_counts),
            'by_pattern': dict(pattern_counts),
            'whitelist_count': len(self.whitelist)
        }


class NetworkFileMonitor:
    """Monitor file operations for data exfiltration"""
    
    def __init__(self, monitored_paths: List[str], alert_system: DLPAlert):
        self.monitored_paths = [Path(p) for p in monitored_paths]
        self.alert_system = alert_system
        self.file_hashes = {}
        self.authorized_destinations = set()
        self.quarantine_folder = Path("quarantine")
        self.quarantine_folder.mkdir(exist_ok=True)
        self.quarantine_enabled = False
        self.scan_stats = {
            'total_scans': 0,
            'files_checked': 0,
            'last_scan_duration': 0,
            'scan_start_time': None
        }
        
    def add_authorized_destination(self, destination: str):
        """Add authorized external destinations"""
        self.authorized_destinations.add(destination)
    
    def calculate_file_hash(self, filepath: Path) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Error hashing file {filepath}: {e}")
            return None
    
    def scan_file(self, filepath: Path) -> Dict:
        """Scan a file for sensitive data"""
        try:
            # Check if whitelisted
            if self.alert_system.is_whitelisted(str(filepath)):
                logging.info(f"Skipping whitelisted file: {filepath}")
                return {'status': 'whitelisted'}
            
            # Skip binary and non-text files
            binary_extensions = {'.exe', '.dll', '.so', '.dylib', '.bin', '.jpg', '.jpeg', 
                                '.png', '.gif', '.bmp', '.ico', '.pdf', '.zip', '.tar', 
                                '.gz', '.mp4', '.mp3', '.avi', '.mov', '.wav'}
            if filepath.suffix.lower() in binary_extensions:
                logging.info(f"Skipping binary file: {filepath}")
                return {'status': 'skipped', 'reason': 'binary_file'}
            
            file_size = filepath.stat().st_size
            if file_size > 10 * 1024 * 1024:  # 10MB
                logging.info(f"Skipping large file: {filepath}")
                return {'status': 'skipped', 'reason': 'file_too_large', 'file_size': file_size}
            
            # Calculate file hash for deduplication
            file_hash = self.calculate_file_hash(filepath)
            if not file_hash:
                return {'status': 'error', 'error': 'Could not calculate hash'}
            
            # Check if file was already scanned (deduplication)
            if file_hash in self.file_hashes:
                logging.debug(f"File already scanned (hash match): {filepath}")
                return {'status': 'already_scanned', 'hash': file_hash}
            
            self.scan_stats['files_checked'] += 1
            
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            findings = SensitiveDataPatterns.scan_content(content)
            
            if findings:
                # Store hash to prevent duplicate alerts
                self.file_hashes[file_hash] = {
                    'filepath': str(filepath),
                    'timestamp': datetime.now().isoformat(),
                    'findings': {k: len(v) for k, v in findings.items()}
                }
                
                self.alert_system.create_alert(
                    severity='HIGH',
                    message=f'Sensitive data detected in file',
                    details={
                        'file': str(filepath),
                        'findings': {k: len(v) for k, v in findings.items()},
                        'hash': file_hash,
                        'file_size': file_size
                    }
                )
                
                # Quarantine if enabled
                if self.quarantine_enabled:
                    self.quarantine_file(filepath)
            else:
                # Even clean files should be tracked to avoid re-scanning
                self.file_hashes[file_hash] = {
                    'filepath': str(filepath),
                    'timestamp': datetime.now().isoformat(),
                    'findings': {}
                }
            
            return {'status': 'scanned', 'findings': findings}
            
        except Exception as e:
            logging.error(f"Error scanning file {filepath}: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def monitor_directory(self, path: Path):
        """Monitor a directory for sensitive files"""
        scan_start = time.time()
        logging.info(f"Scanning directory: {path}")
        
        for filepath in path.rglob('*'):
            if filepath.is_file():
                self.scan_file(filepath)
        
        self.scan_stats['last_scan_duration'] = time.time() - scan_start
        self.scan_stats['total_scans'] += 1
    
    def quarantine_file(self, filepath: Path) -> bool:
        """Move file to quarantine folder"""
        try:
            # Create timestamped quarantine subfolder
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            quarantine_path = self.quarantine_folder / timestamp / filepath.name
            quarantine_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Move file
            shutil.move(str(filepath), str(quarantine_path))
            
            logging.warning(f"Quarantined file: {filepath} -> {quarantine_path}")
            
            # Create metadata file
            metadata = {
                'original_path': str(filepath),
                'quarantine_path': str(quarantine_path),
                'timestamp': timestamp,
                'hash': self.calculate_file_hash(quarantine_path)
            }
            metadata_file = quarantine_path.parent / f"{filepath.name}.metadata.json"
            metadata_file.write_text(json.dumps(metadata, indent=2))
            
            return True
        except Exception as e:
            logging.error(f"Failed to quarantine file {filepath}: {e}")
            return False
    
    def check_external_transfer(self, filepath: Path, destination: str) -> bool:
        """Check if file transfer to destination is authorized"""
        if destination in self.authorized_destinations:
            logging.info(f"Authorized transfer: {filepath} -> {destination}")
            return True
        
        scan_result = self.scan_file(filepath)
        
        if scan_result.get('findings'):
            self.alert_system.create_alert(
                severity='CRITICAL',
                message='Unauthorized transfer of sensitive data blocked',
                details={
                    'file': str(filepath),
                    'destination': destination,
                    'findings': scan_result['findings']
                }
            )
            return False
        
        return True


class NetworkRiskScanner:
    """Scan network targets and alert when risky services are exposed."""

    RISKY_PORTS = {
        21: ("FTP", "HIGH", "Unencrypted file transfer service is exposed", "Disable FTP or enforce SFTP/FTPS only"),
        23: ("Telnet", "CRITICAL", "Insecure remote shell service is exposed", "Disable Telnet and use SSH with key auth"),
        139: ("NetBIOS", "HIGH", "Legacy file sharing service is exposed", "Restrict NetBIOS to trusted internal hosts"),
        445: ("SMB", "HIGH", "File sharing service is exposed", "Restrict SMB exposure and enforce SMB signing"),
        3389: ("RDP", "HIGH", "Remote desktop service is exposed", "Restrict RDP to VPN and enforce MFA"),
        5900: ("VNC", "HIGH", "Remote desktop service is exposed", "Restrict VNC to trusted networks"),
        6379: ("Redis", "CRITICAL", "Database/cache service commonly abused when exposed", "Bind Redis to localhost or private network only"),
        9200: ("Elasticsearch", "HIGH", "Search cluster endpoint is exposed", "Require auth and restrict network access"),
        27017: ("MongoDB", "HIGH", "Database endpoint is exposed", "Enable authentication and restrict inbound access"),
        11211: ("Memcached", "HIGH", "Caching service can be abused for amplification", "Disable public access immediately"),
    }

    @classmethod
    def default_config(cls) -> Dict[str, Any]:
        return {
            "enabled": False,
            "targets": ["127.0.0.1"],
            "ports": [21, 22, 23, 80, 135, 139, 443, 445, 3389],
            "scan_interval_seconds": 900,
            "timeout_seconds": 0.35,
            "max_hosts_per_cidr": 32,
            "alert_cooldown_seconds": 1800,
        }

    def __init__(self, config: Optional[Dict[str, Any]], alert_system: DLPAlert):
        self.alert_system = alert_system
        self.config: Dict[str, Any] = {}
        self.alert_cache: Dict[str, float] = {}
        self.last_scan_result: Dict[str, Any] = {}
        self.stats = {
            "total_scans": 0,
            "hosts_scanned_total": 0,
            "open_ports_found_total": 0,
            "risks_found_total": 0,
            "last_scan_duration": 0.0,
            "last_scan_time": None,
            "last_scan_time_epoch": 0.0,
            "last_hosts_scanned": 0,
            "last_open_ports_found": 0,
            "last_risks_found": 0,
        }
        self.update_config(config or {})

    def update_config(self, config: Dict[str, Any]) -> None:
        merged = self.default_config()
        if isinstance(config, dict):
            merged.update(config)

        targets = [str(t).strip() for t in merged.get("targets", []) if str(t).strip()]
        ports = self._normalize_ports(merged.get("ports", []))

        merged["targets"] = targets
        merged["ports"] = ports
        merged["enabled"] = bool(merged.get("enabled", False))
        merged["scan_interval_seconds"] = max(30, self._to_int(merged.get("scan_interval_seconds"), 900))
        merged["timeout_seconds"] = max(0.1, self._to_float(merged.get("timeout_seconds"), 0.35))
        merged["max_hosts_per_cidr"] = max(1, self._to_int(merged.get("max_hosts_per_cidr"), 32))
        merged["alert_cooldown_seconds"] = max(60, self._to_int(merged.get("alert_cooldown_seconds"), 1800))
        self.config = merged

    def _to_int(self, value: Any, default: int) -> int:
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default

    def _to_float(self, value: Any, default: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _normalize_ports(self, ports: Any) -> List[int]:
        if not isinstance(ports, list):
            return self.default_config()["ports"]

        normalized: List[int] = []
        seen = set()
        for value in ports:
            try:
                port = int(value)
            except (TypeError, ValueError):
                continue

            if 1 <= port <= 65535 and port not in seen:
                seen.add(port)
                normalized.append(port)

        return sorted(normalized) if normalized else self.default_config()["ports"]

    def _expand_targets(self) -> List[str]:
        expanded: List[str] = []
        max_hosts = self.config.get("max_hosts_per_cidr", 32)

        for target in self.config.get("targets", []):
            if "/" not in target:
                expanded.append(target)
                continue

            try:
                network = ipaddress.ip_network(target, strict=False)
                count = 0
                for host in network.hosts():
                    expanded.append(str(host))
                    count += 1
                    if count >= max_hosts:
                        break
            except ValueError:
                expanded.append(target)

        deduped: List[str] = []
        seen = set()
        for host in expanded:
            if host not in seen:
                seen.add(host)
                deduped.append(host)
        return deduped

    def _is_port_open(self, host: str, port: int) -> bool:
        timeout = self.config.get("timeout_seconds", 0.35)
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _build_risk_profile(self, port: int) -> Optional[Dict[str, str]]:
        if port in self.RISKY_PORTS:
            service, severity, risk, recommendation = self.RISKY_PORTS[port]
            return {
                "service": service,
                "severity": severity,
                "risk": risk,
                "recommendation": recommendation,
            }

        if port < 1024:
            return {
                "service": f"System port {port}",
                "severity": "MEDIUM",
                "risk": "Privileged service is externally reachable",
                "recommendation": "Validate necessity and restrict source IP ranges",
            }

        return None

    def _should_emit_alert(self, alert_key: str, now: float) -> bool:
        cooldown = self.config.get("alert_cooldown_seconds", 1800)
        last_seen = self.alert_cache.get(alert_key, 0.0)
        if now - last_seen < cooldown:
            return False
        self.alert_cache[alert_key] = now
        return True

    def scan(self, force: bool = False) -> Dict[str, Any]:
        if not self.config.get("enabled", False):
            return {
                "status": "disabled",
                "message": "Network scanning is disabled in configuration",
            }

        now = time.time()
        interval = self.config.get("scan_interval_seconds", 900)
        last_epoch = self.stats.get("last_scan_time_epoch", 0.0)

        if not force and last_epoch and (now - last_epoch) < interval:
            return {
                "status": "skipped",
                "reason": "interval_not_reached",
                "next_scan_in_seconds": max(0, int(interval - (now - last_epoch))),
                "last_scan_time": self.stats.get("last_scan_time"),
            }

        targets = self._expand_targets()
        ports = self.config.get("ports", [])

        if not targets:
            return {"status": "skipped", "reason": "no_targets_configured"}

        if not ports:
            return {"status": "skipped", "reason": "no_ports_configured"}

        scan_start = time.time()
        open_ports_by_host: Dict[str, List[int]] = {}
        risk_findings: List[Dict[str, Any]] = []
        alerts_created = 0

        for host in targets:
            host_open_ports: List[int] = []
            for port in ports:
                if not self._is_port_open(host, port):
                    continue

                host_open_ports.append(port)
                risk_profile = self._build_risk_profile(port)
                if not risk_profile:
                    continue

                finding = {
                    "host": host,
                    "port": port,
                    "service": risk_profile["service"],
                    "severity": risk_profile["severity"],
                    "risk": risk_profile["risk"],
                    "recommendation": risk_profile["recommendation"],
                }
                risk_findings.append(finding)

                alert_key = f"{host}:{port}:{risk_profile['severity']}"
                if self._should_emit_alert(alert_key, now):
                    self.alert_system.create_alert(
                        severity=risk_profile["severity"],
                        message=f"Network risk detected: open {risk_profile['service']} service",
                        details={
                            "scan_type": "network",
                            "category": "network_exposure",
                            "host": host,
                            "port": port,
                            "service": risk_profile["service"],
                            "risk": risk_profile["risk"],
                            "recommended_action": risk_profile["recommendation"],
                        },
                    )
                    alerts_created += 1

            if host_open_ports:
                open_ports_by_host[host] = sorted(host_open_ports)

        duration = time.time() - scan_start
        scan_time = datetime.now().isoformat()
        open_ports_count = sum(len(v) for v in open_ports_by_host.values())

        self.stats["total_scans"] += 1
        self.stats["hosts_scanned_total"] += len(targets)
        self.stats["open_ports_found_total"] += open_ports_count
        self.stats["risks_found_total"] += len(risk_findings)
        self.stats["last_scan_duration"] = duration
        self.stats["last_scan_time"] = scan_time
        self.stats["last_scan_time_epoch"] = now
        self.stats["last_hosts_scanned"] = len(targets)
        self.stats["last_open_ports_found"] = open_ports_count
        self.stats["last_risks_found"] = len(risk_findings)

        result = {
            "status": "completed",
            "scan_time": scan_time,
            "duration_seconds": round(duration, 3),
            "hosts_scanned": len(targets),
            "ports_tested_per_host": len(ports),
            "open_ports_found": open_ports_count,
            "risks_found": len(risk_findings),
            "alerts_created": alerts_created,
            "open_ports_by_host": open_ports_by_host,
            "risk_findings": risk_findings,
        }
        self.last_scan_result = result
        return result

    def maybe_scan_periodic(self) -> Dict[str, Any]:
        return self.scan(force=False)

    def get_status(self) -> Dict[str, Any]:
        return {
            "enabled": self.config.get("enabled", False),
            "targets": self.config.get("targets", []),
            "ports": self.config.get("ports", []),
            "scan_interval_seconds": self.config.get("scan_interval_seconds"),
            "last_scan_time": self.stats.get("last_scan_time"),
            "stats": {
                "total_scans": self.stats.get("total_scans", 0),
                "hosts_scanned_total": self.stats.get("hosts_scanned_total", 0),
                "open_ports_found_total": self.stats.get("open_ports_found_total", 0),
                "risks_found_total": self.stats.get("risks_found_total", 0),
                "last_scan_duration": self.stats.get("last_scan_duration", 0),
                "last_hosts_scanned": self.stats.get("last_hosts_scanned", 0),
                "last_open_ports_found": self.stats.get("last_open_ports_found", 0),
                "last_risks_found": self.stats.get("last_risks_found", 0),
            },
            "last_result": self.last_scan_result,
        }


class DLPSystem:
    """Main DLP system coordinator"""
    
    def __init__(self, config_file: str = 'dlp_config.json'):
        self.config = self._load_config(config_file)
        self.alert_system = DLPAlert(
            alert_email=self.config.get('alert_email'),
            smtp_config=self.config.get('smtp_config', {})
        )
        self.file_monitor = NetworkFileMonitor(
            monitored_paths=self.config.get('monitored_paths', []),
            alert_system=self.alert_system
        )
        self.network_scanner = NetworkRiskScanner(
            config=self.config.get('network_scan', {}),
            alert_system=self.alert_system,
        )
        
        for dest in self.config.get('authorized_destinations', []):
            self.file_monitor.add_authorized_destination(dest)
    
    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from file"""
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                loaded_config = json.load(f)

            default_network_cfg = NetworkRiskScanner.default_config()
            if not isinstance(loaded_config.get('network_scan'), dict):
                loaded_config['network_scan'] = default_network_cfg
            else:
                merged_network_cfg = default_network_cfg.copy()
                merged_network_cfg.update(loaded_config['network_scan'])
                loaded_config['network_scan'] = merged_network_cfg

            return loaded_config
        
        default_config = {
            'monitored_paths': ['./monitored_data'],
            'authorized_destinations': [],
            'alert_email': 'security@company.com',
            'smtp_config': {},
            'network_scan': NetworkRiskScanner.default_config(),
        }
        
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        return default_config
    
    def start_monitoring(self):
        """Start the DLP monitoring system"""
        logging.info("Cyber Sentinel starting...")
        
        for path in self.file_monitor.monitored_paths:
            if path.exists():
                self.file_monitor.monitor_directory(path)
            else:
                logging.warning(f"Monitored path does not exist: {path}")

        network_result = self.network_scanner.maybe_scan_periodic()
        if network_result.get('status') == 'completed':
            logging.info(
                "Network scan complete: hosts=%s open_ports=%s risks=%s alerts=%s",
                network_result.get('hosts_scanned', 0),
                network_result.get('open_ports_found', 0),
                network_result.get('risks_found', 0),
                network_result.get('alerts_created', 0),
            )
        
        logging.info("Initial scan complete")
    
    def simulate_transfer(self, filepath: str, destination: str):
        """Simulate a file transfer attempt"""
        logging.info(f"Simulating transfer: {filepath} -> {destination}")
        allowed = self.file_monitor.check_external_transfer(Path(filepath), destination)
        return allowed
    
    def get_security_report(self) -> Dict:
        """Generate security report"""
        alerts = self.alert_system.get_alerts()
        network_alert_count = len([
            a for a in alerts
            if a.get('details', {}).get('scan_type') == 'network'
        ])
        
        report = {
            'report_time': datetime.now().isoformat(),
            'total_alerts': len(alerts),
            'critical_alerts': len([a for a in alerts if a['severity'] == 'CRITICAL']),
            'high_alerts': len([a for a in alerts if a['severity'] == 'HIGH']),
            'network_risk_alerts': network_alert_count,
            'recent_alerts': alerts[-10:],
            'statistics': self.alert_system.get_statistics(),
            'network_scan': self.network_scanner.get_status(),
        }
        
        return report

    def run_network_scan(self, force: bool = True) -> Dict[str, Any]:
        """Run a network risk scan and return summary."""
        return self.network_scanner.scan(force=force)

    def get_network_scan_status(self) -> Dict[str, Any]:
        """Get latest network scanner status and stats."""
        return self.network_scanner.get_status()
    
    def export_alerts_csv(self, filepath: str = None) -> str:
        """Export alerts to CSV file"""
        if filepath is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = f"alerts_export_{timestamp}.csv"
        
        alerts = self.alert_system.get_alerts()
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['timestamp', 'severity', 'message', 'scan_type', 'file', 'host', 'port', 'destination', 'findings']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for alert in alerts:
                details = alert.get('details', {})
                writer.writerow({
                    'timestamp': alert.get('timestamp', ''),
                    'severity': alert.get('severity', ''),
                    'message': alert.get('message', ''),
                    'scan_type': details.get('scan_type', 'file'),
                    'file': details.get('file', ''),
                    'host': details.get('host', ''),
                    'port': details.get('port', ''),
                    'destination': details.get('destination', ''),
                    'findings': json.dumps(details.get('findings', {}))
                })
        
        logging.info(f"Alerts exported to CSV: {filepath}")
        return filepath
    
    def export_alerts_json(self, filepath: str = None) -> str:
        """Export alerts to JSON file"""
        if filepath is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filepath = f"alerts_export_{timestamp}.json"
        
        alerts = self.alert_system.get_alerts()
        
        export_data = {
            'export_time': datetime.now().isoformat(),
            'total_alerts': len(alerts),
            'alerts': alerts,
            'statistics': self.alert_system.get_statistics()
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2)
        
        logging.info(f"Alerts exported to JSON: {filepath}")
        return filepath
    
    def backup_config(self, backup_dir: str = "backups") -> str:
        """Create a backup of current configuration"""
        backup_path = Path(backup_dir)
        backup_path.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = backup_path / f"dlp_config_backup_{timestamp}.json"
        
        backup_data = {
            'backup_time': datetime.now().isoformat(),
            'config': self.config,
            'whitelist': list(self.alert_system.whitelist),
            'statistics': self.alert_system.get_statistics()
        }
        
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(backup_data, f, indent=2)
        
        logging.info(f"Configuration backed up to: {backup_file}")
        return str(backup_file)
    
    def restore_config(self, backup_file: str) -> bool:
        """Restore configuration from backup"""
        try:
            with open(backup_file, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            
            self.config = backup_data.get('config', {})
            
            # Restore whitelist
            whitelist = backup_data.get('whitelist', [])
            for item in whitelist:
                self.alert_system.add_to_whitelist(item)
            
            logging.info(f"Configuration restored from: {backup_file}")
            return True
        except Exception as e:
            logging.error(f"Failed to restore config from {backup_file}: {e}")
            return False
