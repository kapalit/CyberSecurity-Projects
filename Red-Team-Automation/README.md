# Network Scanner

Automated reconnaissance tool that conducts Nmap scans, parses results, identifies risky services, and generates actionable security reports.

## Features

- Automated Nmap scanning with service detection
- Intelligent parsing and organization of scan results
- Risky service detection and risk categorization (CRITICAL, HIGH, MEDIUM)
- Report generation in text and JSON formats
- Enterprise-grade logging

## Installation

```bash
cd Red-Team-Automation
pip install -r requirements.txt
```

Ensure Nmap is installed on your system.

## Usage

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

## Command-line Options

- `target`: Target IP, hostname, or CIDR range (required)
- `-a, --arguments`: Custom Nmap arguments (default: `-sV -p- --open`)
- `-o, --output`: Output report file (default: `red_team_report.txt`)
- `-j, --json`: Export findings as JSON
- `-l, --log`: Log file for scan activity
- `-v, --verbose`: Enable verbose logging
- `--no-report`: Skip text report generation

## How It Works

**Enumeration**: Performs full port scans (1-65535), detects service versions, filters only open ports

**Risk Assessment**:
- CRITICAL: Database services, RDP, SMB
- HIGH: Web servers, email services, SNMP
- MEDIUM: DNS, NTP

**Report Generation**: Summary statistics, per-host findings, detailed risk descriptions, recommended mitigations

## Production Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) and [PRODUCTION_READY.md](PRODUCTION_READY.md) for comprehensive deployment instructions.
