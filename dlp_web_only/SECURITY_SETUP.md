# 🛡️ Security Setup Guide - Cyber Sentinel

## Overview
This guide explains how to properly set up Cyber Sentinel with secure environment variable management to ensure no secrets are committed to version control.

---

## ✅ Quick Start (5 minutes)

### 1. Create Your `.env` File
```bash
# Copy the template to create your local .env file
cp .env.example .env

# Edit .env with your actual credentials
# Windows: notepad .env
# Mac/Linux: nano .env
```

### 2. Generate a Secure API Key
```bash
# Python: Generate a new secure API key
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Copy the generated key and paste it into .env as DLP_API_KEY
```

### 3. Fill in Configuration Values
Edit `.env` and replace all `your_*_here` placeholders with actual values:
```env
DLP_API_KEY=<paste-generated-key-here>
FLASK_SECRET_KEY=<generate-another-key>
ALERT_EMAIL=security@company.com
FLASK_ENV=production
```

### 4. Verify Configuration
```bash
# Test that configuration loads correctly
python -c "from secure_config import config; print('✓ Config loaded')"
```

### 5. Start the Application
```bash
python dlp_web.py
```

✓ **You're done!** Secrets are now safely managed via environment variables.

---

## 📁 File Structure

```
.
├── .env                    ← YOUR SECRETS (DO NOT COMMIT)
├── .env.example            ← TEMPLATE (safe to commit)
├── .gitignore             ← Prevents committing secrets
├── secure_config.py       ← Config loader
├── dlp_web.py             ← Updated to use secure_config
└── SECURITY_SETUP.md      ← This file
```

---

## 🔐 Security Best Practices

### ✓ DO:
- ✅ Keep `.env` file private (add to `.gitignore`)
- ✅ Use strong, unique API keys and passwords
- ✅ Rotate secrets regularly
- ✅ Use different keys for dev/staging/production
- ✅ Store production secrets in a vault (AWS Secrets Manager, HashiCorp Vault)
- ✅ Review git history for accidentally committed secrets
- ✅ Use HTTPS in production
- ✅ Implement rate limiting and authentication
- ✅ Log security events
- ✅ Monitor for unauthorized access

### ✗ DON'T:
- ❌ Commit `.env` file to git
- ❌ Hardcode secrets in source code
- ❌ Share `.env` files via email or chat
- ❌ Use weak, predictable secrets
- ❌ Reuse the same key across environments
- ❌ Leave production credentials in development environments
- ❌ Log secret values
- ❌ Use FTP/HTTP to transmit secrets
- ❌ Store secrets in comments
- ❌ Use default/example values in production

---

## 🔄 Environment-Specific Configuration

The system supports multiple environment files with automatic precedence:

1. `.env` - Primary configuration (always loaded)
2. `.env.{FLASK_ENV}` - Environment-specific (e.g., `.env.production`)
3. `.env.local` - Local overrides (useful for development)

**Loading order (later files override earlier):**
```
.env
.env.development (if FLASK_ENV=development)
.env.local
```

**Example:**
```bash
# Development with local overrides
cp .env.example .env
cp .env.example .env.development
cp .env.example .env.local

# Edit each with environment-specific values
nano .env              # Common secrets
nano .env.development  # Dev-only settings
nano .env.local        # Your local machine settings
```

---

## 🚀 Using Secure Config in Your Code

### Basic Usage
```python
from secure_config import config

# Get string value
api_key = config.get_secret('DLP_API_KEY', required=True)

# Get with default
port = config.get_int('SERVER_PORT', default=5000)

# Get boolean
debug = config.get_bool('FLASK_DEBUG', False)

# Get list (comma-separated)
paths = config.get_list('MONITORED_PATHS')
```

### In Flask App
```python
from flask import Flask
from secure_config import config, init_secure_config

app = Flask(__name__)
init_secure_config(app)

@app.route('/api/status')
def status():
    api_key = config.get_secret('DLP_API_KEY')
    return {'status': 'ok'}
```

### Error Handling
```python
from secure_config import config, ConfigurationError

try:
    secret = config.get_secret('DATABASE_PASSWORD', required=True)
except ConfigurationError as e:
    logger.error(f"Configuration error: {e}")
    # Handle gracefully
```

---

## 🔑 Generating Secure Keys

### Python (Recommended)
```bash
# Generate a 32-byte URL-safe key (256-bit)
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Generate a hex key (64 characters)
python -c "import secrets; print(secrets.token_hex(32))"
```

### Using OpenSSL
```bash
# Generate random bytes
openssl rand -hex 32

# Generate base64-encoded random bytes
openssl rand -base64 32
```

### Using Linux/macOS
```bash
# Generate from /dev/urandom
head -c 32 /dev/urandom | base64
```

---

## 🛠️ If You Accidentally Committed Secrets

### Step 1: Identify Committed Secrets
```bash
# Search git history for secrets
git log -p -S "DLP_API_KEY" -- .

# View all files ever committed
git log --follow --name-only --pretty=format: -- .
```

### Step 2: Remove from Git History
```bash
# Option A: Using git-filter-repo (Recommended)
# Install: pip install git-filter-repo

git filter-repo --invert-paths --path .env
git filter-repo --invert-paths --path dlp_api_key.txt
git filter-repo --invert-paths --path .env.production

# Option B: Using BFG Repo-Cleaner
# Install: brew install bfg (macOS) or download from https://rtyley.github.io/bfg-repo-cleaner/

bfg --delete-files .env
git reflog expire --expire=now --all && git gc --prune=now --aggressive

# Option C: Manual git-filter-branch (More complex)
git filter-branch --tree-filter 'rm -f .env' HEAD
```

### Step 3: Force Push
```bash
# WARNING: This rewrites history and will affect all contributors
git push origin --force-with-lease --all
git push origin --force-with-lease --tags
```

### Step 4: Rotate Exposed Secrets
```bash
# Generate new secrets
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Update all services using the old key
# 1. Update .env file with new key
# 2. Update API key in application
# 3. Update any external services using this key
# 4. Monitor for unauthorized access using old key
```

### Step 5: Notify Team
- Alert team members to the compromised key
- Instruct them to pull the cleaned history: `git pull origin --rebase`
- Update any documentation that referenced the old key

---

## 📋 Verification Checklist

Before deploying to production, verify:

- [ ] `.env` is in `.gitignore`
- [ ] `.env.example` exists with placeholder values
- [ ] No `.env` files in git history: `git log --all --full-history -- .env`
- [ ] No hardcoded secrets in source code
- [ ] `secure_config.py` is properly integrated
- [ ] Application starts without errors
- [ ] All required secrets are defined in `.env`
- [ ] HTTPS is enabled in production
- [ ] API key authentication is working
- [ ] Rate limiting is enforced
- [ ] Logging does not expose secrets
- [ ] Error messages don't reveal sensitive data
- [ ] Database passwords are in `.env`
- [ ] Third-party API keys are in `.env`
- [ ] Development and production configs are separated

---

## 🔍 Detecting Leaks with GitHub Secret Scanning

GitHub automatically scans for common secrets. If detected:

1. **Fix immediately**: Remove secret from code and git history
2. **Rotate key**: Generate new key in external service
3. **Monitor**: Watch for unauthorized access
4. **Review**: Check who had access to the leaked secret

**Enable GitHub Secret Scanning:**
- Repository Settings → Security & Analysis → Secret Scanning → Enable

**Bypass Push Protection:**
```bash
# If a secret is detected, GitHub will block the push
# Option 1: Remove the secret and try again
git rm .env
git add -A
git commit -m "Remove .env file"
git push

# Option 2: Use git-filter-repo to remove from history (see above)
```

---

## 🚨 Production Deployment

### AWS Secrets Manager
```bash
# Store secrets in AWS
aws secretsmanager create-secret --name cyber-sentinel-prod \
  --secret-string '{"DLP_API_KEY":"...", "FLASK_SECRET_KEY":"..."}'

# Retrieve in application
import boto3
client = boto3.client('secretsmanager')
secrets = client.get_secret_value(SecretId='cyber-sentinel-prod')
```

### HashiCorp Vault
```bash
# Store secrets in Vault
vault kv put secret/cyber-sentinel \
  DLP_API_KEY="..." \
  FLASK_SECRET_KEY="..."

# Retrieve in application
import hvac
client = hvac.Client()
secrets = client.secrets.kv.read_secret_version(path='cyber-sentinel')
```

### Docker/Kubernetes
```dockerfile
# Use Docker secrets (not environment variables for production!)
# .env file is loaded by docker-compose

# docker-compose.yml
services:
  app:
    build: .
    env_file: .env  # Loaded from secure volume
    secrets:
      - db_password
```

---

## 🐛 Troubleshooting

### "Missing required environment variables"
```bash
# Check if .env file exists
ls -la .env

# Verify required secrets are set
grep DLP_API_KEY .env

# Verify correct file location
pwd

# Test configuration loading
python -c "from secure_config import config; print(config.get('DLP_API_KEY')[:10])"
```

### "Secret value is None"
```bash
# Check if variable is set
env | grep DLP_API_KEY

# Check if .env is in correct location
cat .env | head -20

# Verify python-dotenv is installed
pip list | grep dotenv
```

### "Connection refused" or "Authentication failed"
- Verify credentials in `.env` are correct
- Check if external service (SMTP, DB) is running
- Verify network connectivity
- Check firewall rules

### "File already exists" error
- `.gitignore` may already exist, merge configurations
- Use `cat .gitignore` to view existing rules
- Append security rules if not present

---

## 📚 Additional Resources

- [python-dotenv Documentation](https://python-dotenv.readthedocs.io/)
- [OWASP: Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [12 Factor App: Config](https://12factor.net/config)
- [GitHub: Managing Sensitive Data](https://docs.github.com/en/code-security/secret-scanning)
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [HashiCorp Vault](https://www.vaultproject.io/)

---

## ✅ Summary

| Task | Command |
|------|---------|
| Setup | `cp .env.example .env && nano .env` |
| Generate Key | `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| Verify Config | `python -c "from secure_config import config"` |
| Check Git | `git log --all -- .env` |
| Remove from History | `git filter-repo --invert-paths --path .env` |
| Test App | `python dlp_web.py` |

---

**Last Updated:** May 2026  
**Status:** ✓ Production Ready  
**Security Level:** 🛡️ High
