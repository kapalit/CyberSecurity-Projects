# CyberSecurity Projects

A collection of production-ready cybersecurity tools for network reconnaissance, vulnerability assessment, intrusion detection, and secure communications. Built for authorized security testing and penetration testing operations.

## Projects

### 1. Red Team Automation - Network Scanner
Automated reconnaissance tool that conducts Nmap scans, parses results, identifies risky services, and generates actionable security reports.

**Location**: `Red-Team-Automation/`

**Key Features**:
- Automated Nmap scanning with service detection
- Intelligent parsing and organization of scan results
- Risky service detection and risk categorization (CRITICAL, HIGH, MEDIUM)
- Report generation in text and JSON formats
- Enterprise-grade logging and deployment options

**Quick Start**:
```bash
cd Red-Team-Automation
pip install -r requirements.txt
python red_team_scanner.py 192.168.1.1 -v -o report.txt
```

### 2. Web Vulnerability Scanner
Comprehensive web application security scanner that identifies common vulnerabilities including SQL injection, XSS, CSRF, and security misconfigurations.

**Location**: `Web-Vulnerability-Scanner/`

**Key Features**:
- XSS and SQL injection detection
- CSRF protection verification
- Security headers analysis (CSP, X-Frame-Options, HSTS)
- Outdated library detection
- SSL/TLS analysis
- Cookie security analysis
- HTML report generation

**Quick Start**:
```bash
cd Web-Vulnerability-Scanner
pip install -r requirements.txt
python scanner.py --url https://example.com
```

### 3. Intrusion Detection System
Network-based intrusion detection system that monitors traffic patterns and identifies suspicious activity using rule-based and anomaly detection.

**Location**: `Intrusion-Detection-System/`

**Key Features**:
- Real-time packet capture and analysis
- Signature-based detection for known attack patterns
- Anomaly detection for unusual network behavior
- Protocol analysis (TCP, UDP, HTTP, DNS)
- Alert generation and comprehensive logging
- Customizable detection rules
- Threat intelligence integration

**Quick Start**:
```bash
cd Intrusion-Detection-System
pip install -r requirements.txt
sudo python ids.py --interface eth0
```

### 4. Secure Communications Tool
End-to-end encrypted messaging application demonstrating modern cryptographic techniques including RSA and AES encryption with digital signatures.

**Location**: `Secure-Communications-Tool/`

**Key Features**:
- Hybrid encryption (RSA + AES)
- Digital signatures for message authenticity
- Key management (2048-bit RSA key pairs)
- Message encryption and decryption
- Signature verification
- Password hashing with PBKDF2
- Message history tracking

**Quick Start**:
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
git clone https://github.com/kapalit/CyberSecurity-Projects.git
cd CyberSecurity-Projects
```

2. Navigate to specific project and install dependencies:
```bash
cd [project-folder]
pip install -r requirements.txt
```

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

## Technologies Used

### Python Libraries
- **python-nmap**: Interface with Nmap scanner
- **requests**: HTTP client for web scanning
- **beautifulsoup4**: HTML parsing
- **scapy**: Packet manipulation and analysis
- **cryptography**: Encryption and secure communications

### External Tools
- **Nmap**: Network mapping and port scanning

## License

These tools are provided for educational and authorized security testing purposes only.

---

**Remember**: With great power comes great responsibility. Use these tools ethically and legally.
