#!/usr/bin/env python
"""
Quick Start Script for DLP System
This script helps new users get started quickly.
"""

import sys
from pathlib import Path


def print_banner():
    print("\n" + "="*70)
    print("  🛡️  Cyber Sentinel - DLP System Quick Start")
    print("="*70 + "\n")


def check_files():
    """Check if required files exist"""
    print("📋 Checking required files...")
    
    required_files = {
        "dlp_web.py": "Main web application",
        "dlp_monitor.py": "Core monitoring engine",
        "requirements.txt": "Python dependencies",
        "templates/base.html": "Web templates",
        "static/app.js": "Frontend JavaScript",
    }
    
    missing = []
    for file, desc in required_files.items():
        path = Path(file)
        if path.exists():
            print(f"  ✓ {file} - {desc}")
        else:
            print(f"  ✗ {file} - MISSING!")
            missing.append(file)
    
    if missing:
        print(f"\n❌ Missing files: {', '.join(missing)}")
        print("Please ensure you're in the correct directory.")
        return False
    
    print("\n✅ All required files present!\n")
    return True


def check_dependencies():
    """Check if dependencies are installed"""
    print("📦 Checking dependencies...")
    
    try:
        import flask
        print(f"  ✓ Flask {flask.__version__} installed")
    except ImportError:
        print("  ✗ Flask not installed")
        print("\n❌ Dependencies missing!")
        print("Run: pip install -r requirements.txt")
        return False
    
    print("\n✅ Dependencies installed!\n")
    return True


def show_next_steps():
    """Show next steps to user"""
    print("🚀 Ready to start! Here's what to do:\n")
    
    print("STEP 1: Start the server")
    print("  → Run: python dlp_web.py")
    print("  → Look for the API key in the console output")
    print("  → The key is also saved to: dlp_api_key.txt\n")
    
    print("STEP 2: Open your browser")
    print("  → Navigate to: http://127.0.0.1:5000")
    print("  → Enter the API key when prompted\n")
    
    print("STEP 3: Configure monitoring")
    print("  → Go to Configuration tab")
    print("  → Add directories to monitor")
    print("  → (Optional) Configure SMTP for email alerts\n")
    
    print("STEP 4: Start monitoring")
    print("  → Go to Monitoring tab")
    print("  → Click 'Start Monitoring'")
    print("  → View alerts as they're detected\n")
    
    print("📖 Additional Resources:")
    print("  → README.md - Full documentation")
    print("  → SECURITY.md - Security best practices")
    print("  → CHANGES.md - What's new in v2.0")
    print("  → test_improvements.py - Run tests\n")
    
    print("⚠️  Important Security Notes:")
    print("  → Keep dlp_api_key.txt secure and private")
    print("  → Don't commit it to version control (.gitignore protects it)")
    print("  → For production, use HTTPS and proper network security")
    print("  → See SECURITY.md for deployment checklist\n")


def create_monitored_folder():
    """Create default monitored folder if it doesn't exist"""
    folder = Path("monitored_data")
    if not folder.exists():
        folder.mkdir()
        print(f"📁 Created default monitoring folder: {folder.absolute()}")
        
        # Create a sample file
        sample = folder / "sample.txt"
        sample.write_text(
            "This is a sample file in the monitored directory.\n"
            "Add files here to test the DLP monitoring system.\n\n"
            "Try adding sensitive data patterns to trigger alerts:\n"
            "- Credit card: 4532-1234-5678-9010\n"
            "- Email: test@example.com\n"
            "- SSN: 123-45-6789\n"
        )
        print(f"  ✓ Created sample file: {sample.name}\n")
    else:
        print(f"📁 Monitoring folder exists: {folder.absolute()}\n")


def main():
    """Main function"""
    print_banner()
    
    # Check everything
    if not check_files():
        return 1
    
    if not check_dependencies():
        return 1
    
    # Create default folder
    create_monitored_folder()
    
    # Show next steps
    show_next_steps()
    
    print("="*70)
    print("  Run 'python dlp_web.py' to get started!")
    print("="*70 + "\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
