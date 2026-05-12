"""
Simple tests for DLP System improvements
Run with: python test_improvements.py
"""

import json
import re
from pathlib import Path


def test_email_validation():
    """Test email validation function"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    valid_emails = [
        "user@example.com",
        "test.user@company.co.uk",
        "admin+dlp@security.org"
    ]
    
    invalid_emails = [
        "notanemail",
        "@example.com",
        "user@",
        "user@.com",
        "user space@example.com"
    ]
    
    print("Testing email validation...")
    for email in valid_emails:
        assert bool(re.match(pattern, email)), f"Should be valid: {email}"
        print(f"  ✓ {email} - valid")
    
    for email in invalid_emails:
        assert not bool(re.match(pattern, email)), f"Should be invalid: {email}"
        print(f"  ✓ {email} - correctly rejected")
    
    print("✅ Email validation tests passed!\n")


def test_config_structure():
    """Test config file structure"""
    print("Testing config structure...")
    
    config_path = Path("dlp_config.json")
    if not config_path.exists():
        print("  ⚠ Config file doesn't exist yet (will be created on first run)")
        return
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    required_keys = ["monitored_paths", "authorized_destinations", "alert_email", "smtp_config"]
    for key in required_keys:
        assert key in config, f"Missing required key: {key}"
        print(f"  ✓ {key} present")
    
    assert isinstance(config["monitored_paths"], list), "monitored_paths should be a list"
    assert isinstance(config["authorized_destinations"], list), "authorized_destinations should be a list"
    assert isinstance(config["smtp_config"], dict), "smtp_config should be a dict"
    
    print("✅ Config structure tests passed!\n")


def test_api_key_generation():
    """Test API key file exists"""
    print("Testing API key...")
    
    key_path = Path("dlp_api_key.txt")
    if not key_path.exists():
        print("  ⚠ API key not generated yet (run dlp_web.py first)")
        return
    
    key = key_path.read_text(encoding="utf-8").strip()
    assert len(key) > 20, "API key should be sufficiently long"
    print(f"  ✓ API key exists (length: {len(key)})")
    print("✅ API key tests passed!\n")


def test_sensitive_patterns():
    """Test sensitive data patterns"""
    from dlp_monitor import SensitiveDataPatterns
    
    print("Testing sensitive data patterns...")
    
    test_content = """
    Credit Card: 4532-1234-5678-9010
    SSN: 123-45-6789
    Email: sensitive@company.com
    Phone: 555-123-4567
    IP: 192.168.1.1
    API Key: abcdef1234567890abcdef1234567890
    """
    
    findings = SensitiveDataPatterns.scan_content(test_content)
    
    expected_patterns = ['credit_card', 'ssn', 'email', 'phone', 'ip_address', 'api_key']
    for pattern in expected_patterns:
        assert pattern in findings, f"Should detect {pattern}"
        print(f"  ✓ {pattern} detected ({len(findings[pattern])} match(es))")
    
    print("✅ Pattern detection tests passed!\n")


def test_gitignore_exists():
    """Test .gitignore file exists"""
    print("Testing .gitignore...")
    
    gitignore_path = Path(".gitignore")
    assert gitignore_path.exists(), ".gitignore should exist"
    
    content = gitignore_path.read_text(encoding="utf-8")
    critical_entries = ["dlp_api_key.txt", "*.log", "__pycache__"]
    
    for entry in critical_entries:
        assert entry in content, f".gitignore should contain {entry}"
        print(f"  ✓ {entry} in .gitignore")
    
    print("✅ .gitignore tests passed!\n")


def main():
    """Run all tests"""
    print("="*60)
    print("🛡️  Cyber Sentinel - Test Suite")
    print("="*60 + "\n")
    
    try:
        test_email_validation()
        test_config_structure()
        test_api_key_generation()
        test_sensitive_patterns()
        test_gitignore_exists()
        
        print("="*60)
        print("✅ ALL TESTS PASSED!")
        print("="*60)
        print("\nNext steps:")
        print("1. Run: python dlp_web.py")
        print("2. Note the API key from console or dlp_api_key.txt")
        print("3. Open http://127.0.0.1:5000 in your browser")
        print("4. Enter API key when prompted")
        print("5. Start monitoring and test the features!")
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
