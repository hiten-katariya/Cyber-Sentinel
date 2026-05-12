import json
import os
import re
import secrets
import threading
import time
import ipaddress
from collections import defaultdict
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional, cast

from flask import Flask, jsonify, redirect, render_template, request, url_for

from dlp_monitor import DLPSystem, SensitiveDataPatterns
from secure_config import config, ConfigurationError, init_secure_config

# Rate limiting storage
rate_limit_storage = defaultdict(lambda: {'count': 0, 'reset_time': time.time()})

# Load API key from secure configuration (.env file)
# See secure_config.py and .env.example for setup instructions
try:
    API_KEY = config.get_secret('DLP_API_KEY', required=True)
    print(f"\n{'='*60}")
    print(f"🛡️  CYBER SENTINEL - API KEY LOADED")
    print(f"{'='*60}")
    print(f"✓ API Key loaded from environment configuration")
    print(f"✓ Configuration: {config}")
    print(f"✓ Environment: {os.getenv('FLASK_ENV', 'development')}")
    print(f"{'='*60}\n")
except ConfigurationError as e:
    print(f"\n{'='*60}")
    print(f"✗ CONFIGURATION ERROR")
    print(f"{'='*60}")
    print(f"Failed to load API key from environment.")
    print(f"Error: {e}")
    print(f"\nSetup Instructions:")
    print(f"  1. Copy .env.example to .env")
    print(f"  2. Generate a secure API key: python -c \"import secrets; print(secrets.token_urlsafe(32))\"")
    print(f"  3. Set DLP_API_KEY=<generated-key> in .env")
    print(f"  4. Start the application again")
    print(f"\nFor more details, see: SECURITY_SETUP.md")
    print(f"{'='*60}\n")
    exit(1)


def require_auth(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check for API key in header or query param
        key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if key != API_KEY:
            return jsonify({"error": "Unauthorized. Provide valid API key."}), 401
        
        # Rate limiting: 60 requests per minute per IP
        client_ip = request.remote_addr or 'unknown'
        current_time = time.time()
        
        if current_time > rate_limit_storage[client_ip]['reset_time'] + 60:
            rate_limit_storage[client_ip] = {'count': 0, 'reset_time': current_time}
        
        rate_limit_storage[client_ip]['count'] += 1
        
        if rate_limit_storage[client_ip]['count'] > 60:
            return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
        
        return f(*args, **kwargs)
    return decorated


def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_path(path_str: str) -> bool:
    """Validate path exists and is accessible"""
    try:
        p = Path(path_str)
        return p.exists() or path_str.startswith('./') or path_str.startswith('.\\')  
    except Exception:
        return False


def validate_network_target(target: str) -> bool:
    """Validate network targets (IP, CIDR, or hostname)."""
    value = (target or "").strip()
    if not value:
        return False

    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        hostname_pattern = r"^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$"
        return bool(re.match(hostname_pattern, value))


def _default_network_scan_config() -> Dict[str, Any]:
    return {
        "enabled": False,
        "targets": ["127.0.0.1"],
        "ports": [21, 22, 23, 80, 135, 139, 443, 445, 3389],
        "scan_interval_seconds": 900,
        "timeout_seconds": 0.35,
        "max_hosts_per_cidr": 32,
        "alert_cooldown_seconds": 1800,
    }


def _read_json(path: Path) -> Dict[str, Any]:
    defaults = {
        "monitored_paths": ["./monitored_data"],
        "authorized_destinations": [],
        "alert_email": "security@company.com",
        "smtp_config": {},
        "network_scan": _default_network_scan_config(),
    }

    if path.exists():
        loaded = json.loads(path.read_text(encoding="utf-8"))
    else:
        loaded = {}

    config = defaults.copy()
    for key, value in loaded.items():
        if key != "network_scan":
            config[key] = value

    network_cfg = _default_network_scan_config()
    loaded_network = loaded.get("network_scan", {})
    if isinstance(loaded_network, dict):
        network_cfg.update(loaded_network)
    config["network_scan"] = network_cfg

    return config


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _tail_file(path: Path, max_lines: int = 200) -> str:
    if not path.exists():
        return ""
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        return "".join(lines[-max_lines:])
    except Exception:
        return ""


class DLPWebState:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.lock = threading.Lock()
        self.dlp: Optional[DLPSystem] = None

        self.is_monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.last_scan_time: Optional[float] = None
        self.last_scan_error: Optional[str] = None

    def get_dlp(self) -> DLPSystem:
        with self.lock:
            if self.dlp is None:
                self.dlp = DLPSystem(config_file=str(self.config_path))
            return self.dlp

    def reload_dlp(self) -> None:
        with self.lock:
            self.dlp = DLPSystem(config_file=str(self.config_path))
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status in a thread-safe way"""
        with self.lock:
            network_status: Dict[str, Any] = {
                "enabled": False,
                "last_scan_time": None,
                "stats": {},
            }
            if self.dlp is not None:
                try:
                    network_status = self.dlp.get_network_scan_status()
                except Exception:
                    pass

            return {
                "is_monitoring": self.is_monitoring,
                "last_scan_time": self.last_scan_time,
                "last_scan_error": self.last_scan_error,
                "network_scan": network_status,
            }

    def start_background_monitoring(self, interval_seconds: int = 5) -> None:
        with self.lock:
            if self.is_monitoring:
                return
            self.is_monitoring = True

        def worker():
            while self.is_monitoring:
                try:
                    dlp = self.get_dlp()
                    dlp.start_monitoring()
                    with self.lock:
                        self.last_scan_time = time.time()
                        self.last_scan_error = None
                except Exception as e:
                    with self.lock:
                        self.last_scan_error = str(e)
                time.sleep(max(1, int(interval_seconds)))

        self.monitor_thread = threading.Thread(target=worker, daemon=True)
        self.monitor_thread.start()

    def stop_background_monitoring(self) -> None:
        with self.lock:
            self.is_monitoring = False

    def start_manual_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            return

        def worker():
            try:
                dlp = self.get_dlp()
                for p in dlp.file_monitor.monitored_paths:
                    if p.exists():
                        dlp.file_monitor.monitor_directory(p)
                dlp.run_network_scan(force=True)
                self.last_scan_time = time.time()
                self.last_scan_error = None
            except Exception as e:
                self.last_scan_error = str(e)

        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()


def create_app() -> Flask:
    app = Flask(__name__)
    
    # Initialize Flask app with secure configuration from .env
    try:
        init_secure_config(app)
    except ConfigurationError as e:
        print(f"Error initializing Flask configuration: {e}")
        raise
    
    state = DLPWebState(config_path=Path("dlp_config.json"))

    @app.get("/")
    def index():
        return redirect(url_for("monitoring_page"))

    @app.get("/monitoring")
    def monitoring_page():
        config = _read_json(state.config_path)
        # Get flash message from query string (simple approach, no session needed)
        msg = request.args.get("msg", "")
        transfer_result = request.args.get("transfer_result", "")
        return render_template(
            "monitoring.html",
            config=config,
            is_monitoring=state.is_monitoring,
            last_scan_time=state.last_scan_time,
            msg=msg,
            transfer_result=transfer_result,
        )

    # -------- Form-based actions (work without JavaScript) --------
    @app.post("/action/start")
    def action_start():
        state.start_background_monitoring()
        return redirect(url_for("monitoring_page", msg="Monitoring started"))

    @app.post("/action/stop")
    def action_stop():
        state.stop_background_monitoring()
        return redirect(url_for("monitoring_page", msg="Monitoring stopped"))

    @app.post("/action/scan")
    def action_scan():
        state.start_manual_scan()
        return redirect(url_for("monitoring_page", msg="Manual scan started"))

    @app.post("/action/network-scan")
    def action_network_scan():
        dlp = state.get_dlp()
        result = dlp.run_network_scan(force=True)
        if result.get("status") != "completed":
            msg = f"Network scan status: {result.get('status', 'unknown')}"
        else:
            msg = (
                "Network scan complete"
                f" | hosts: {result.get('hosts_scanned', 0)}"
                f" | risks: {result.get('risks_found', 0)}"
                f" | alerts: {result.get('alerts_created', 0)}"
            )
        return redirect(url_for("monitoring_page", msg=msg))

    @app.post("/action/test-transfer")
    def action_test_transfer():
        file_path = (request.form.get("file_path") or "").strip()
        destination = (request.form.get("destination") or "").strip()
        if not file_path or not destination:
            return redirect(url_for("monitoring_page", transfer_result="Please fill both fields"))
        
        # Validate file path exists
        if not Path(file_path).exists():
            return redirect(url_for("monitoring_page", transfer_result=f"File not found: {file_path}"))
        
        dlp = state.get_dlp()
        allowed = dlp.simulate_transfer(file_path, destination)
        result = "Transfer ALLOWED" if allowed else "Transfer BLOCKED"
        return redirect(url_for("monitoring_page", transfer_result=result))

    @app.get("/configuration")
    def configuration_page():
        config = _read_json(state.config_path)
        return render_template(
            "config.html",
            config=config,
            patterns=SensitiveDataPatterns.PATTERNS,
        )

    @app.get("/logs")
    def logs_page():
        return render_template("logs.html")

    @app.get("/alerts")
    def alerts_page():
        return render_template("alerts.html")
    
    @app.get("/dashboard")
    def dashboard_page():
        return render_template("dashboard.html")
    
    @app.get("/advanced")
    def advanced_page():
        return render_template("advanced.html")

    # -------------------- APIs --------------------

    @app.get("/api/status")
    def api_status():
        return jsonify(state.get_status())

    @app.post("/api/start")
    @require_auth
    def api_start():
        try:
            state.start_background_monitoring()
            return jsonify({"ok": True, "is_monitoring": state.is_monitoring})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.post("/api/stop")
    @require_auth
    def api_stop():
        try:
            state.stop_background_monitoring()
            return jsonify({"ok": True, "is_monitoring": state.is_monitoring})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.post("/api/scan")
    @require_auth
    def api_scan():
        try:
            state.start_manual_scan()
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.post("/api/network-scan")
    @require_auth
    def api_network_scan():
        try:
            payload: Dict[str, Any] = cast(Dict[str, Any], request.get_json(silent=True) or {})
            force = bool(payload.get("force", True))
            dlp = state.get_dlp()
            result = dlp.run_network_scan(force=force)
            return jsonify({"ok": True, "result": result})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.get("/api/network-scan/status")
    @require_auth
    def api_network_scan_status():
        try:
            dlp = state.get_dlp()
            return jsonify({"ok": True, "network_scan": dlp.get_network_scan_status()})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.get("/api/report")
    @require_auth
    def api_report():
        try:
            dlp = state.get_dlp()
            report = dlp.get_security_report()
            return jsonify(report)
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.post("/api/test-transfer")
    @require_auth
    def api_test_transfer():
        try:
            payload: Dict[str, Any] = cast(Dict[str, Any], request.get_json(silent=True) or {})
            file_path = (payload.get("file_path") or "").strip()
            destination = (payload.get("destination") or "").strip()

            if not file_path or not destination:
                return jsonify({"ok": False, "error": "file_path and destination are required"}), 400

            dlp = state.get_dlp()
            allowed = dlp.simulate_transfer(file_path, destination)
            return jsonify({"ok": True, "allowed": bool(allowed)})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.get("/api/alerts")
    @require_auth
    def api_alerts():
        try:
            dlp = state.get_dlp()
            alerts = dlp.alert_system.get_alerts()
            return jsonify({"alerts": alerts[-200:]})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.post("/api/alerts/clear")
    @require_auth
    def api_alerts_clear():
        try:
            dlp = state.get_dlp()
            dlp.alert_system.alerts.clear()
            # Also clear file hash tracking to allow rescanning
            dlp.file_monitor.file_hashes.clear()
            dlp.network_scanner.alert_cache.clear()
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.get("/api/logs")
    @require_auth
    def api_logs():
        try:
            max_lines = int(request.args.get("lines", "250"))
            text = _tail_file(Path("cyber_sentinel.log"), max_lines=max(50, min(max_lines, 2000)))
            return jsonify({"text": text})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.get("/api/config")
    @require_auth
    def api_get_config():
        try:
            return jsonify(_read_json(state.config_path))
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.post("/api/config")
    @require_auth
    def api_set_config():
        try:
            payload: Dict[str, Any] = cast(Dict[str, Any], request.get_json(silent=True) or {})

            # Normalize / validate
            monitored_paths = payload.get("monitored_paths") or []
            authorized_destinations = payload.get("authorized_destinations") or []
            alert_email = (payload.get("alert_email") or "").strip()
            smtp_config = payload.get("smtp_config") or {}
            network_scan = payload.get("network_scan") or {}

            if not isinstance(monitored_paths, list) or not isinstance(authorized_destinations, list):
                return jsonify({"ok": False, "error": "monitored_paths and authorized_destinations must be lists"}), 400

            if not isinstance(network_scan, dict):
                return jsonify({"ok": False, "error": "network_scan must be an object"}), 400

            # Validate email if provided
            if alert_email and not validate_email(alert_email):
                return jsonify({"ok": False, "error": "Invalid email format"}), 400

            # Validate paths
            clean_paths = []
            for p in monitored_paths:
                p_str = str(p).strip()
                if p_str:
                    if not validate_path(p_str):
                        return jsonify({"ok": False, "error": f"Invalid or inaccessible path: {p_str}"}), 400
                    clean_paths.append(p_str)

            network_defaults = _default_network_scan_config()
            merged_network_scan = network_defaults.copy()
            merged_network_scan.update(network_scan)

            raw_targets = merged_network_scan.get("targets", [])
            if not isinstance(raw_targets, list):
                return jsonify({"ok": False, "error": "network_scan.targets must be a list"}), 400

            clean_targets = []
            for target in raw_targets:
                target_str = str(target).strip()
                if not target_str:
                    continue
                if not validate_network_target(target_str):
                    return jsonify({"ok": False, "error": f"Invalid network target: {target_str}"}), 400
                clean_targets.append(target_str)

            raw_ports = merged_network_scan.get("ports", [])
            if not isinstance(raw_ports, list):
                return jsonify({"ok": False, "error": "network_scan.ports must be a list"}), 400

            clean_ports = []
            for port_value in raw_ports:
                try:
                    port = int(port_value)
                except (TypeError, ValueError):
                    return jsonify({"ok": False, "error": f"Invalid network port: {port_value}"}), 400

                if port < 1 or port > 65535:
                    return jsonify({"ok": False, "error": f"Network port out of range: {port}"}), 400
                if port not in clean_ports:
                    clean_ports.append(port)

            if len(clean_ports) > 512:
                return jsonify({"ok": False, "error": "Too many ports configured (max 512)"}), 400

            try:
                scan_interval_seconds = int(merged_network_scan.get("scan_interval_seconds", network_defaults["scan_interval_seconds"]))
                timeout_seconds = float(merged_network_scan.get("timeout_seconds", network_defaults["timeout_seconds"]))
                max_hosts_per_cidr = int(merged_network_scan.get("max_hosts_per_cidr", network_defaults["max_hosts_per_cidr"]))
                alert_cooldown_seconds = int(merged_network_scan.get("alert_cooldown_seconds", network_defaults["alert_cooldown_seconds"]))
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "Invalid numeric value in network_scan configuration"}), 400

            if scan_interval_seconds < 30 or scan_interval_seconds > 86400:
                return jsonify({"ok": False, "error": "network_scan.scan_interval_seconds must be between 30 and 86400"}), 400
            if timeout_seconds < 0.1 or timeout_seconds > 5:
                return jsonify({"ok": False, "error": "network_scan.timeout_seconds must be between 0.1 and 5"}), 400
            if max_hosts_per_cidr < 1 or max_hosts_per_cidr > 4096:
                return jsonify({"ok": False, "error": "network_scan.max_hosts_per_cidr must be between 1 and 4096"}), 400
            if alert_cooldown_seconds < 60 or alert_cooldown_seconds > 86400:
                return jsonify({"ok": False, "error": "network_scan.alert_cooldown_seconds must be between 60 and 86400"}), 400

            network_enabled = bool(merged_network_scan.get("enabled", False))
            if network_enabled and not clean_targets:
                return jsonify({"ok": False, "error": "At least one network target is required when network scanning is enabled"}), 400
            if network_enabled and not clean_ports:
                return jsonify({"ok": False, "error": "At least one network port is required when network scanning is enabled"}), 400

            clean_network_scan = {
                "enabled": network_enabled,
                "targets": clean_targets,
                "ports": sorted(clean_ports),
                "scan_interval_seconds": scan_interval_seconds,
                "timeout_seconds": timeout_seconds,
                "max_hosts_per_cidr": max_hosts_per_cidr,
                "alert_cooldown_seconds": alert_cooldown_seconds,
            }

            config = {
                "monitored_paths": clean_paths,
                "authorized_destinations": [str(d).strip() for d in authorized_destinations if str(d).strip()],
                "alert_email": alert_email,
                "smtp_config": smtp_config,
                "network_scan": clean_network_scan,
            }

            _write_json(state.config_path, config)
            state.reload_dlp()

            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    # -------------------- Export & Reporting APIs --------------------

    @app.get("/api/export/csv")
    @require_auth
    def api_export_csv():
        try:
            dlp = state.get_dlp()
            filepath = dlp.export_alerts_csv()
            return jsonify({"ok": True, "file": filepath})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.get("/api/export/json")
    @require_auth
    def api_export_json():
        try:
            dlp = state.get_dlp()
            filepath = dlp.export_alerts_json()
            return jsonify({"ok": True, "file": filepath})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.get("/api/statistics")
    @require_auth
    def api_statistics():
        try:
            dlp = state.get_dlp()
            stats = dlp.alert_system.get_statistics()
            scan_stats = dlp.file_monitor.scan_stats
            network_scan = dlp.get_network_scan_status()
            return jsonify({
                "ok": True, 
                "statistics": stats,
                "scan_stats": {
                    "total_scans": scan_stats.get('total_scans', 0),
                    "files_checked": scan_stats.get('files_checked', 0),
                    "last_scan_duration": scan_stats.get('last_scan_duration', 0)
                },
                "network_scan": {
                    "enabled": network_scan.get("enabled", False),
                    "last_scan_time": network_scan.get("last_scan_time"),
                    "stats": network_scan.get("stats", {}),
                },
            })
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    # -------------------- Whitelist APIs --------------------

    @app.get("/api/whitelist")
    @require_auth
    def api_get_whitelist():
        try:
            dlp = state.get_dlp()
            return jsonify({"ok": True, "whitelist": list(dlp.alert_system.whitelist)})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.post("/api/whitelist/add")
    @require_auth
    def api_add_whitelist():
        try:
            payload: Dict[str, Any] = cast(Dict[str, Any], request.get_json(silent=True) or {})
            item = payload.get("item", "").strip()
            if not item:
                return jsonify({"ok": False, "error": "Item is required"}), 400
            
            dlp = state.get_dlp()
            dlp.alert_system.add_to_whitelist(item)
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.post("/api/whitelist/remove")
    @require_auth
    def api_remove_whitelist():
        try:
            payload: Dict[str, Any] = cast(Dict[str, Any], request.get_json(silent=True) or {})
            item = payload.get("item", "").strip()
            if not item:
                return jsonify({"ok": False, "error": "Item is required"}), 400
            
            dlp = state.get_dlp()
            dlp.alert_system.remove_from_whitelist(item)
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    # -------------------- Quarantine APIs --------------------

    @app.post("/api/quarantine/enable")
    @require_auth
    def api_enable_quarantine():
        try:
            dlp = state.get_dlp()
            dlp.file_monitor.quarantine_enabled = True
            return jsonify({"ok": True, "enabled": True})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.post("/api/quarantine/disable")
    @require_auth
    def api_disable_quarantine():
        try:
            dlp = state.get_dlp()
            dlp.file_monitor.quarantine_enabled = False
            return jsonify({"ok": True, "enabled": False})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.get("/api/quarantine/status")
    @require_auth
    def api_quarantine_status():
        try:
            dlp = state.get_dlp()
            return jsonify({"ok": True, "enabled": dlp.file_monitor.quarantine_enabled})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    # -------------------- Backup & Restore APIs --------------------

    @app.post("/api/backup/create")
    @require_auth
    def api_create_backup():
        try:
            dlp = state.get_dlp()
            backup_file = dlp.backup_config()
            return jsonify({"ok": True, "backup_file": backup_file})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.post("/api/backup/restore")
    @require_auth
    def api_restore_backup():
        try:
            payload: Dict[str, Any] = cast(Dict[str, Any], request.get_json(silent=True) or {})
            backup_file = payload.get("backup_file", "").strip()
            if not backup_file:
                return jsonify({"ok": False, "error": "Backup file is required"}), 400
            
            dlp = state.get_dlp()
            success = dlp.restore_config(backup_file)
            if success:
                state.reload_dlp()
                return jsonify({"ok": True})
            else:
                return jsonify({"ok": False, "error": "Failed to restore backup"}), 500
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    return app


if __name__ == "__main__":
    app = create_app()
    # Local dev server (website-based UI)
    app.run(host="127.0.0.1", port=5000, debug=False)
