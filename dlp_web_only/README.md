# Cyber Sentinel - Advanced DLP System

A secure web-based Data Loss Prevention (DLP) monitoring system built with Flask. Cyber Sentinel provides real-time threat detection and automated response to protect sensitive data.

## Features

- **🔒 API Authentication**: Secure API endpoints with auto-generated API keys
- **Real-time Monitoring**: Continuous scanning of configured directories for sensitive data
- **Network Risk Scanning**: Scan hosts/CIDR ranges for exposed risky services and create alerts
- **Sensitive Data Detection**: Detects credit cards, SSN, emails, phone numbers, IP addresses, API keys
- **Transfer Testing**: Simulate and validate file transfers to external destinations
- **Alert Management**: View and manage security alerts with optional email notifications
- **Log Viewer**: Real-time log monitoring
- **Configuration Validation**: Path and email validation before saving
- **Thread-Safe**: Improved concurrency handling for production use

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Web Server

```bash
python dlp_web.py
```

**Important**: On first run, an API key will be generated and displayed in the console. This key is also saved to `dlp_api_key.txt`. Keep this key secure!

### 3. Access the Dashboard

Open your browser and go to: **http://127.0.0.1:5000**

When accessing API endpoints through JavaScript, you'll be prompted to enter your API key. The key is stored in localStorage for convenience.

## Security

### API Authentication

All control and configuration API endpoints require authentication via API key:
- **Header**: `X-API-Key: your-api-key-here`
- **Query param**: `?api_key=your-api-key-here`

The web interface automatically handles authentication. For external API access, include the key in your requests:

```bash
curl -H "X-API-Key: your-api-key" http://127.0.0.1:5000/api/status
```

### Email Alerts

To enable email notifications, configure SMTP settings in the configuration:

```json
{
  "smtp_config": {
    "server": "smtp.gmail.com",
    "port": 587,
    "use_tls": true,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "from_email": "dlp@company.com"
  }
}
```

### Network Risk Scan Configuration

You can enable host/port risk scanning from the Configuration page or directly in `dlp_config.json`:

```json
{
  "network_scan": {
    "enabled": true,
    "targets": ["127.0.0.1", "192.168.1.0/24"],
    "ports": [21, 22, 23, 80, 443, 445, 3389],
    "scan_interval_seconds": 900,
    "timeout_seconds": 0.35,
    "max_hosts_per_cidr": 32,
    "alert_cooldown_seconds": 1800
  }
}
```

When risky services are detected, Cyber Sentinel creates alerts with host, port, service, and mitigation recommendations.

## Files Structure

```
dlp_web_only/
├── dlp_web.py          # Flask web application
├── dlp_monitor.py      # Core DLP scanning engine
├── dlp_config.json     # Configuration file
├── dlp_api_key.txt     # Auto-generated API key (keep secure!)
├── requirements.txt    # Python dependencies
├── templates/          # HTML templates
│   ├── base.html
│   ├── monitoring.html
│   ├── config.html
│   ├── logs.html
│   └── alerts.html
├── static/             # CSS and JavaScript
│   ├── app.css
│   └── app.js
└── monitored_data/     # Default folder to monitor
```

## Usage

### Monitoring Tab
- **Start Monitoring**: Begin continuous background scanning
- **Stop Monitoring**: Stop background scanning
- **Manual Scan**: Run a one-time scan
- **Network Risk Scan**: Run an on-demand host/port risk scan
- **Test Transfer**: Simulate file transfer to check if it would be blocked

### Configuration Tab
- Add/remove monitored paths
- Add/remove authorized destinations
- Set alert email address
- View detection patterns

### Logs Tab
- View real-time system logs

### Alerts Tab
- View all security alerts
- Clear alerts when resolved

## API Endpoints

All API endpoints now require authentication via `X-API-Key` header.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/status` | GET | No | Get monitoring status |
| `/api/start` | POST | **Yes** | Start monitoring |
| `/api/stop` | POST | **Yes** | Stop monitoring |
| `/api/scan` | POST | **Yes** | Trigger manual scan |
| `/api/network-scan` | POST | **Yes** | Trigger network risk scan |
| `/api/network-scan/status` | GET | **Yes** | Get network scanner status and stats |
| `/api/report` | GET | **Yes** | Get security report |
| `/api/test-transfer` | POST | **Yes** | Test file transfer |
| `/api/alerts` | GET | **Yes** | Get all alerts |
| `/api/alerts/clear` | POST | **Yes** | Clear all alerts |
| `/api/logs` | GET | **Yes** | Get log content |
| `/api/config` | GET | **Yes** | Get configuration |
| `/api/config` | POST | **Yes** | Update configuration |

### Error Handling

All endpoints return consistent error responses:
```json
{
  "ok": false,
  "error": "Error message here"
}
```

## Configuration Validation

The system now validates:
- ✅ Email format (RFC 5322 compliant)
- ✅ Path existence and accessibility
- ✅ Required fields presence
- ✅ Data type correctness

## Changelog

### Version 2.0 (Security Update)
- ✅ Added API key authentication
- ✅ Fixed SMTP email sending functionality
- ✅ Improved thread safety with proper locking
- ✅ Added comprehensive input validation
- ✅ Enhanced error handling across all endpoints
- ✅ Added configuration validation for paths and emails

## License

MIT License
