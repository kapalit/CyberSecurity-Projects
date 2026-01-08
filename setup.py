#!/usr/bin/env python3
"""
Installation and setup script for Red Team Automation Scanner
Run this script to verify and set up the environment
"""

import sys
import subprocess
import os
from pathlib import Path


def check_python_version():
    """Verify Python version is 3.7+"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print(f"[-] Python 3.7+ required. Current version: {version.major}.{version.minor}")
        return False
    print(f"[+] Python version: {version.major}.{version.minor}.{version.micro}")
    return True


def check_nmap():
    """Verify Nmap is installed"""
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            print(f"[+] Nmap found: {version_line}")
            return True
    except Exception as e:
        pass
    
    print("[-] Nmap not found. Install with:")
    print("    Linux: sudo apt-get install nmap")
    print("    macOS: brew install nmap")
    print("    Windows: https://nmap.org/download.html")
    return False


def install_dependencies():
    """Install Python dependencies"""
    print("\n[*] Installing Python dependencies...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            check=True
        )
        print("[+] Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Error installing dependencies: {e}")
        return False


def verify_import():
    """Verify the scanner module can be imported"""
    print("\n[*] Verifying scanner module...")
    try:
        from red_team_scanner import RedTeamScanner, RISKY_SERVICES
        print(f"[+] Scanner module imported successfully")
        print(f"[+] Risky services database: {len(RISKY_SERVICES)} services configured")
        return True
    except ImportError as e:
        print(f"[-] Error importing scanner: {e}")
        return False


def create_directories():
    """Create necessary directories"""
    print("\n[*] Creating project directories...")
    dirs = ["reports", "logs"]
    try:
        for dir_name in dirs:
            Path(dir_name).mkdir(exist_ok=True)
            print(f"[+] Directory created/verified: {dir_name}")
        return True
    except Exception as e:
        print(f"[-] Error creating directories: {e}")
        return False


def main():
    """Main setup routine"""
    print("=" * 70)
    print("Red Team Automation Scanner - Setup Verification")
    print("=" * 70)
    print()
    
    checks = [
        ("Python version", check_python_version),
        ("Nmap installation", check_nmap),
        ("Python dependencies", install_dependencies),
        ("Scanner module", verify_import),
        ("Project directories", create_directories),
    ]
    
    results = []
    for check_name, check_func in checks:
        print(f"\n[*] Checking {check_name}...")
        try:
            result = check_func()
            results.append((check_name, result))
        except Exception as e:
            print(f"[-] Error during {check_name}: {e}")
            results.append((check_name, False))
    
    print("\n" + "=" * 70)
    print("SETUP VERIFICATION RESULTS")
    print("=" * 70)
    
    all_passed = True
    for check_name, result in results:
        status = "[+] PASS" if result else "[-] FAIL"
        print(f"{status}: {check_name}")
        if not result:
            all_passed = False
    
    print("=" * 70)
    
    if all_passed:
        print("\n[+] Setup verification complete! Ready for deployment.")
        print("\nQuick start:")
        print("  python red_team_scanner.py <target> -v")
        print("\nSee DEPLOYMENT.md for detailed deployment instructions.")
        return 0
    else:
        print("\n[-] Setup verification failed. Please resolve issues above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
