# Red Team Automation Scanner - Deployment Guide

## Production Deployment Instructions

### Prerequisites

- Python 3.7+
- Nmap (5.0+)
- Administrator/root privileges
- 2GB+ RAM for large scans

### Installation

#### 1. System Setup

**Linux/macOS:**
```bash
# Install Nmap
apt-get install nmap  # Debian/Ubuntu
brew install nmap     # macOS
```

**Windows:**
- Download from https://nmap.org/download.html
- Add to system PATH

#### 2. Python Environment Setup

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt
```

#### 3. Verify Installation

```bash
python red_team_scanner.py -h
```

### Deployment Options

#### Option 1: Single Host Scan

```bash
python red_team_scanner.py 192.168.1.100 -v
```

#### Option 2: CIDR Range Scan

```bash
python red_team_scanner.py 192.168.1.0/24 -v
```

#### Option 3: Scheduled Scans (Cron/Scheduled Task)

**Linux/macOS Cron:**
```bash
# Weekly scan at 2 AM on Sunday
0 2 * * 0 /path/to/venv/bin/python /path/to/red_team_scanner.py 192.168.1.0/24 -o /var/reports/scan_$(date +\%Y\%m\%d).txt -l /var/logs/scanner.log
```

**Windows Task Scheduler:**
```batch
schtasks /create /tn "RedTeamScan" /tr "C:\path\to\venv\Scripts\python.exe C:\path\to\red_team_scanner.py 192.168.1.1 -o C:\reports\scan.txt" /sc weekly /d SUN /st 02:00
```

#### Option 4: Docker Deployment

Create `Dockerfile`:
```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3.10 \
    python3-pip \
    nmap

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "red_team_scanner.py"]
```

Build and run:
```bash
docker build -t red-team-scanner .
docker run -v /reports:/reports red-team-scanner 192.168.1.100 -o /reports/scan.txt
```

#### Option 5: Integration with Security Tools

**Send to SIEM/Splunk:**
```bash
python red_team_scanner.py 192.168.1.1 -j findings.json
# Parse findings.json and forward to SIEM
curl -X POST http://splunk-server:8088/services/collector \
  -H "Authorization: Splunk YOUR_TOKEN" \
  -d @findings.json
```

**Create Tickets:**
```python
from red_team_scanner import RedTeamScanner
import subprocess

scanner = RedTeamScanner(verbose=True, log_file="/var/log/scanner.log")
scanner.run_scan("192.168.1.0/24")
scanner.parse_results()
findings = scanner.flag_risky_services()

for finding in findings:
    if finding["risk_level"] == "CRITICAL":
        # Create ticket in your system
        subprocess.run([
            "jira", "create",
            f"Security Finding: {finding['service']} on {finding['host']}:{finding['port']}"
        ])
```

### Configuration

The scanner uses command-line arguments for configuration. Key options:

| Option | Purpose | Example |
|--------|---------|---------|
| `-a` / `--arguments` | Custom Nmap args | `-a "-sS -p 22,80"` |
| `-o` / `--output` | Report file | `-o /reports/scan.txt` |
| `-j` / `--json` | JSON export | `-j findings.json` |
| `-l` / `--log` | Log file | `-l /var/log/scan.log` |
| `-v` / `--verbose` | Verbose logging | `-v` |

### Monitoring

#### Log File Locations

- **Application logs**: Configured with `-l` flag
- **System logs**: Check OS logs for Nmap execution

#### Key Log Entries

- `Starting scan on target:` - Scan initiation
- `RISKY SERVICE FOUND:` - Risk detection
- `Report saved to` - Report generation confirmation
- `Scan complete:` - Completion status

### Performance Optimization

#### For Large Networks

```bash
# Reduce ports scanned
python red_team_scanner.py 192.168.1.0/24 -a "-sV -p 1-1000"

# Parallel scanning (requires multiple runs)
for i in {0..255}; do
  python red_team_scanner.py 192.168.1.$i -a "-sV" &
done
wait
```

#### Memory Management

- Default settings use minimal memory
- For 1000+ hosts, allocate 4GB+ RAM
- Monitor with `free -h` (Linux) or Task Manager (Windows)

### Security Considerations

#### Authorization Verification

```python
# Always verify authorization
authorized_targets = [
    "192.168.1.0/24",
    "10.0.0.0/8"
]

target = input("Enter target: ")
if target not in authorized_targets:
    print("ERROR: Unauthorized target")
    exit(1)
```

#### Audit Logging

All scans are logged with timestamps. Example audit trail:
```
2026-01-08 14:30:45,123 - __main__ - INFO - Starting scan on target: 192.168.1.100
2026-01-08 14:32:10,456 - __main__ - WARNING - RISKY SERVICE FOUND: 192.168.1.100:3306 - MySQL [CRITICAL]
2026-01-08 14:32:15,789 - __main__ - INFO - Report saved to red_team_report.txt
```

#### Data Protection

- Use encrypted storage for reports
- Restrict file permissions: `chmod 600 reports/*.txt`
- Secure log files: `chmod 600 *.log`
- Consider encrypting JSON exports

### Troubleshooting

| Issue | Solution |
|-------|----------|
| "nmap program not found" | Install Nmap and add to PATH |
| "Permission denied" | Run with sudo (Linux) or as Administrator (Windows) |
| Slow scanning | Use `-a "-sV -p 1-1000"` for faster scans |
| Large network timeout | Increase Nmap timeout with `--host-timeout` |
| No ports detected | Verify target is reachable and not firewalled |

### Backup and Recovery

```bash
# Backup reports
tar -czf reports_backup.tar.gz reports/

# Backup configuration
cp -r . backup_$(date +%Y%m%d)
```

### Support and Updates

- Check for updates: `pip install --upgrade python-nmap`
- Review logs for errors: `grep ERROR *.log`
- Test with known targets first

---

**Ready for production deployment!**
