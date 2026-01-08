# Red Team Automation

```
Red-Team-Automation/
├── red_team_scanner.py          # Network reconnaissance scanner
├── requirements.txt              # Network scanner dependencies
├── setup.py                      # Installation script
├── README.md                     # Main documentation
├── DEPLOYMENT.md                 # Deployment guide
├── PRODUCTION_READY.md           # Production readiness checklist
├── logs/                         # Scan logs directory
├── reports/                      # Generated reports directory
├── Web-Vulnerability-Scanner/    # Web application security scanner
│   ├── scanner.py
│   ├── requirements.txt
│   └── README.md
├── Intrusion-Detection-System/   # Network IDS
│   ├── ids.py
│   ├── rules.json
│   ├── requirements.txt
│   └── README.md
└── Secure-Communications-Tool/   # Encrypted messaging
    ├── secure_messenger.py
    ├── requirements.txt
    └── README.md
```

A collection of production-ready cybersecurity tools for network reconnaissance, vulnerability assessment, intrusion detection, and secure communications. Built for authorized security testing and penetration testing operations.

## Projects

### 1. Network Scanner
Automated reconnaissance tool that conducts Nmap scans, parses results, identifies risky services, and generates actionable security reports.

**Location**: `red_team_scanner.py`

**Features**:
- Automated Nmap scanning with service detection
- Intelligent parsing and organization of scan results
- Risky service detection and risk categorization
- Report generation in text and JSON formats
- Enterprise-grade logging

**Usage**:
```bash
python red_team_scanner.py 192.168.1.1 -v -o report.txt
```

### 2. Web Vulnerability Scanner
Comprehensive web application security scanner that identifies common vulnerabilities including SQL injection, XSS, and security misconfigurations.

**Location**: `Web-Vulnerability-Scanner/`

**Features**:
- SQL injection detection
- Cross-site scripting (XSS) testing
- Security header analysis
- Directory traversal detection
- Automated crawling and testing

**Usage**:
```bash
cd Web-Vulnerability-Scanner
pip install -r requirements.txt
python scanner.py --url https://example.com
```

### 3. Intrusion Detection System
Network-based intrusion detection system that monitors traffic patterns and identifies suspicious activity using rule-based detection.

**Location**: `Intrusion-Detection-System/`

**Features**:
- Real-time packet capture and analysis
- Rule-based threat detection
- Anomaly detection
- Alert generation and logging
- Customizable detection rules

**Usage**:
```bash
cd Intrusion-Detection-System
pip install -r requirements.txt
sudo python ids.py --interface eth0
```

### 4. Secure Communications Tool
End-to-end encrypted messaging application with secure key exchange and authentication mechanisms.

**Location**: `Secure-Communications-Tool/`

**Features**:
- End-to-end encryption
- Secure key exchange
- Message authentication
- Forward secrecy
- User authentication

**Usage**:
```bash
cd Secure-Communications-Tool
pip install -r requirements.txt
python secure_messenger.py
```

## Installation

### Requirements
- Python 3.7+
- Nmap (for network scanner)
- Administrator/root privileges for certain operations

### Setup

1. Clone the repository:
```bash
cd Red-Team-Automation
```

2. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows
```

3. Install dependencies for specific tools:
```bash
# Network Scanner
pip install -r requirements.txt

# Web Vulnerability Scanner
cd Web-Vulnerability-Scanner && pip install -r requirements.txt

# Intrusion Detection System
cd Intrusion-Detection-System && pip install -r requirements.txt

# Secure Communications Tool
cd Secure-Communications-Tool && pip install -r requirements.txt
```

## Network Scanner Usage

### Basic Commands

```bash
# Basic scan
python red_team_scanner.py 192.168.1.1

# Scan with logging
python red_team_scanner.py 192.168.1.1 -v -l scan.log

# Custom port range
python red_team_scanner.py 192.168.1.1 -a "-sS -p 22,80,443" -v

# Generate report and JSON export
python red_team_scanner.py 192.168.1.1 -o report.txt -j findings.json -v

# Scan multiple hosts
python red_team_scanner.py 192.168.1.0/24 -v -l network_scan.log
```

### Command-line Options
- `target`: Target IP, hostname, or CIDR range (required)
- `-a, --arguments`: Custom Nmap arguments (default: `-sV -p- --open`)
- `-o, --output`: Output report file (default: `red_team_report.txt`)
- `-j, --json`: Export findings as JSON
- `-l, --log`: Log file for scan activity
- `-v, --verbose`: Enable verbose logging
- `--no-report`: Skip text report generation

## How It Works

### Network Scanner

**Enumeration Logic**:
- Performs full port scans (1-65535)
- Detects service versions
- Filters only open ports for analysis

**Risk Assessment**:
- CRITICAL: Database services, RDP, SMB
- HIGH: Web servers, email services, SNMP
- MEDIUM: DNS, NTP

**Report Generation**:
- Summary statistics
- Per-host findings
- Detailed risk descriptions
- Recommended mitigations

### Output Example

```
======================================================================
RED TEAM AUTOMATION REPORT
======================================================================
Generated: 2026-01-08 14:30:45

SUMMARY
----------------------------------------------------------------------
Total Hosts Scanned: 1
Total Open Ports Found: 5
Risky Services Found: 3
  - CRITICAL: 2
  - HIGH: 1
  - MEDIUM: 0

HOST DETAILS
----------------------------------------------------------------------

Host: 192.168.1.100
Status: up
Open Ports: 5

======================================================================
RISKY FINDINGS (Flagged Services)
======================================================================

[CRITICAL] 192.168.1.100:3306
  Service: MySQL
  Description: Database exposure
  Version: MySQL 5.7.32

[CRITICAL] 192.168.1.100:3389
  Service: RDP
  Description: Brute force & exploitation
  Version: 

[HIGH] 192.168.1.100:80
  Service: HTTP
  Description: Unencrypted web traffic
  Version: Apache 2.4.41
```

## Tools and Technologies

### Python Libraries
- **python-nmap**: Interface with Nmap scanner
- **requests**: HTTP client for web scanning
- **beautifulsoup4**: HTML parsing
- **scapy**: Packet manipulation and analysis
- **cryptography**: Encryption and secure communications

### External Tools
- **Nmap**: Network mapping and port scanning

## Ethical Disclaimer

**IMPORTANT LEGAL AND ETHICAL NOTICE**

These tools are designed for **authorized security testing and penetration testing only**. Unauthorized use is illegal in most jurisdictions.

### Legal Obligations

- **Obtain Written Authorization**: You must have explicit, written permission from the network owner or authorized representative before using these tools
- **Scope Definition**: Ensure testing is limited to authorized targets and networks
- **Compliance**: Follow applicable laws including:
  - Computer Fraud and Abuse Act (CFAA) in the USA
  - Computer Misuse Act in the UK
  - General Data Protection Regulation (GDPR) in EU
  - Similar laws in your jurisdiction

### Responsible Disclosure

If vulnerabilities are discovered:
1. Document findings thoroughly
2. Report to the organization's security team
3. Allow reasonable time for remediation (typically 90 days)
4. Do not publicly disclose until patched
5. Never access or exfiltrate data beyond scope

### Misuse Prevention

- Only use these tools in controlled environments
- Do not scan third-party networks without permission
- Do not use for unauthorized access or data theft
- Report suspicious activity to appropriate authorities

**By using these tools, you agree to use them responsibly and legally.**

## Integration Examples

### Run as a Cron Job
```bash
0 2 * * 0 /usr/bin/python3 /opt/red_team_scanner.py 192.168.1.0/24 -o /var/reports/weekly_scan_$(date +\%Y\%m\%d).txt -l /var/log/red_team_scanner.log
```

### Security Pipeline Integration
```python
from red_team_scanner import RedTeamScanner

scanner = RedTeamScanner(verbose=True, log_file="scan.log")
scanner.run_scan("10.0.0.0/8", "-sV")
scanner.parse_results()
scanner.flag_risky_services()
findings = scanner.risky_findings

for finding in findings:
    if finding["risk_level"] == "CRITICAL":
        create_incident_ticket(finding)
```

### Docker Deployment
```bash
docker build -t red-team-scanner .
docker run -v /reports:/reports red-team-scanner 192.168.1.100 -o /reports/scan.txt
```

## Troubleshooting

**Issue**: "Command 'nmap' not found"
- **Solution**: Install Nmap on your system

**Issue**: "Permission denied" error
- **Solution**: Run with appropriate privileges (sudo on Linux/macOS, Administrator on Windows)

**Issue**: No ports detected
- **Solution**: Verify target is reachable; try pinging the host first

**Issue**: Slow scanning
- **Solution**: Use more specific port ranges instead of full scan

## Production Deployment

For comprehensive deployment instructions, including Docker, scheduled scans, SIEM integration, and security considerations, see [DEPLOYMENT.md](DEPLOYMENT.md) and [PRODUCTION_READY.md](PRODUCTION_READY.md).

## License

These tools are provided for educational and authorized security testing purposes only.

---

**Remember**: With great power comes great responsibility. Use these tools ethically and legally.
