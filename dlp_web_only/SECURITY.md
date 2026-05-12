# Cyber Sentinel Security Guide

## Overview
This document covers security best practices for deploying and using Cyber Sentinel, an advanced Data Loss Prevention system.

## API Key Management

### Generation
- API key is auto-generated on first run using `secrets.token_urlsafe(32)`
- Stored in `dlp_api_key.txt` (included in .gitignore)
- **NEVER commit the API key to version control**

### Rotation
To rotate the API key:
1. Delete `dlp_api_key.txt`
2. Restart the application
3. Update all clients with the new key

### Storage
- Keep `dlp_api_key.txt` secure with restricted file permissions
- On production systems, consider using environment variables or secret management services

## SMTP Configuration

### Gmail Example
For Gmail, use App Passwords (not your regular password):
1. Enable 2FA on your Google account
2. Generate an App Password: https://myaccount.google.com/apppasswords
3. Use the 16-character password in your config

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

### Other Providers
- **Outlook/Office365**: smtp.office365.com:587
- **Yahoo**: smtp.mail.yahoo.com:587
- **Custom SMTP**: Use your organization's SMTP server

## Production Deployment

### 1. Use HTTPS
Never run the DLP system over plain HTTP in production. Use:
- Reverse proxy (nginx, Apache) with SSL/TLS
- Let's Encrypt for free SSL certificates
- Or deploy behind a VPN

### 2. Network Security
- Bind to specific IP: `app.run(host="127.0.0.1")` for local only
- Use firewall rules to restrict access
- Consider VPN or private network deployment

### 3. File Permissions
```bash
# Restrict API key file
chmod 600 dlp_api_key.txt

# Restrict config file
chmod 600 dlp_config.json

# Restrict log files
chmod 640 dlp_monitor.log
```

### 4. Environment Variables
For production, use environment variables:
```python
import os
API_KEY = os.getenv('DLP_API_KEY')
```

### 5. Use a Production WSGI Server
Don't use Flask's development server in production:
```bash
# Install gunicorn
pip install gunicorn

# Run with gunicorn
gunicorn -w 4 -b 127.0.0.1:5000 dlp_web:create_app()
```

## Authentication Flow

### Web Interface
1. User opens browser to `http://127.0.0.1:5000`
2. JavaScript attempts API call
3. If no API key in localStorage, prompts user
4. Stores key in localStorage for session
5. Includes key in `X-API-Key` header for all requests

### External API Access
```bash
# Using curl
curl -H "X-API-Key: your-key-here" http://127.0.0.1:5000/api/status

# Using Python requests
import requests
headers = {"X-API-Key": "your-key-here"}
response = requests.get("http://127.0.0.1:5000/api/status", headers=headers)
```

## Threat Model

### What This System Protects Against
✅ Unauthorized access to control functions  
✅ Configuration tampering  
✅ Detection of sensitive data in monitored directories  
✅ Blocking transfers containing sensitive data  

### What This System Does NOT Protect Against
❌ Network-level data exfiltration (needs OS-level DLP)  
❌ Encrypted/obfuscated data  
❌ Sophisticated attackers with system access  
❌ Malicious insiders with direct file system access  

## Logging and Auditing

### What Gets Logged
- All scan operations
- Alert generation
- File transfer attempts
- Configuration changes (via Flask logs)

### Log Security
- Logs may contain sensitive information
- Restrict access to `dlp_monitor.log`
- Implement log rotation
- Consider encrypted log storage

## Incident Response

### If API Key Is Compromised
1. Immediately delete `dlp_api_key.txt`
2. Restart the application (new key generated)
3. Update all legitimate clients
4. Review logs for unauthorized access
5. Check alert history for suspicious activity

### If Sensitive Data Is Detected
1. Review alert details
2. Verify false positive vs. true positive
3. If legitimate, document why data exists
4. If breach, follow your incident response plan
5. Rotate any exposed credentials

## Compliance Considerations

This system can assist with:
- GDPR data discovery requirements
- PCI DSS sensitive data protection
- HIPAA PHI monitoring
- SOC 2 security monitoring requirements

**Note**: This is a monitoring tool, not a complete compliance solution. Consult with compliance experts for your specific requirements.

## Security Checklist

- [ ] Changed default API key location to secure path
- [ ] Enabled HTTPS/TLS for production
- [ ] Configured firewall rules
- [ ] Set proper file permissions (600 for sensitive files)
- [ ] Using production WSGI server (not Flask dev server)
- [ ] SMTP credentials secured (using app passwords)
- [ ] Log rotation configured
- [ ] Regular security updates scheduled
- [ ] Incident response plan documented
- [ ] Team trained on alert handling

## Contact

For security issues, please report privately to your security team before public disclosure.
