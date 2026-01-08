# Intrusion Detection System (IDS)

A network-based Intrusion Detection System that monitors network traffic and detects malicious patterns, anomalies, and known attack signatures.

## Features

- **Real-time Packet Monitoring**: Captures and analyzes network packets
- **Signature-Based Detection**: Detects known attack patterns
- **Anomaly Detection**: Identifies unusual network behavior
- **Protocol Analysis**: Deep inspection of TCP, UDP, HTTP, DNS traffic
- **Alert System**: Real-time alerts for detected threats
- **Log Management**: Comprehensive logging of all activities
- **Statistics Dashboard**: Network traffic statistics and trends
- **Configurable Rules**: Custom detection rules
- **Threat Intelligence Integration**: Known malicious IPs and domains

## Quick Start (Step-by-Step)

### Step 1: Install Python (if not already installed)
```powershell
winget install Python.Python.3.11
```

### Step 2: Navigate to the project directory
```powershell
cd "c:\Users\[YourUsername]\source\repos\Cybersecurity project\Intrusion-Detection-System"
```

### Step 3: Install dependencies
```powershell
python -m pip install -r requirements.txt
```

### Step 4: Run the IDS (requires Administrator)
Run PowerShell as Administrator, then:
```powershell
python ids.py -v
```

### Step 5: Stop the IDS
Press `Ctrl+C` to stop monitoring and view statistics.

---

## Installation

```bash
pip install -r requirements.txt
```

Or with the full Python path on Windows:
```powershell
&"C:\Users\[YourUsername]\AppData\Local\Programs\Python\Python311\python.exe" -m pip install -r requirements.txt
```

## Usage

### Basic IDS Monitor (requires Administrator)
```bash
python ids.py
```

### Monitor Specific Interface
```bash
python ids.py -i eth0
```

### Custom Rules File
```bash
python ids.py -r custom_rules.json -v
```

### Enable Verbose Output
```bash
python ids.py -v
```

## Arguments

- `-i, --interface`: Network interface to monitor (default: auto-detect)
- `-r, --rules`: Custom rules file (JSON format)
- `-v, --verbose`: Enable verbose output
- `-l, --log`: Log file path (default: ids.log)
- `-s, --stats`: Show real-time statistics

## Detection Rules

The IDS comes with built-in detection rules for:

### Protocol-Based Attacks
- Port scanning attempts
- SYN flood attacks
- UDP floods
- ICMP floods
- DNS amplification attacks

### Application-Level Attacks
- SQL injection attempts
- XSS attack patterns
- Command injection signatures
- Path traversal attempts

### Malware Signatures
- Known botnet C&C communication patterns
- Malware download patterns
- Suspicious process behavior

### Anomalies
- Unusual port access patterns
- Suspicious geographic IPs
- High-frequency connections from single source
- Data exfiltration patterns

## Output

### Alert Format
```
[ALERT] Timestamp | Severity | Alert Type | Source IP | Destination IP | Details
```

### Log Format
```json
{
  "timestamp": "2024-01-05 10:30:45.123456",
  "event_type": "malicious_packet",
  "severity": "HIGH",
  "protocol": "TCP",
  "source_ip": "192.168.1.100",
  "source_port": 45678,
  "destination_ip": "10.0.0.1",
  "destination_port": 443,
  "signature": "SQL Injection Attempt",
  "details": "Detected SQL injection pattern in payload"
}
```

## Configuration

Edit `rules.json` to customize detection rules:

```json
{
  "rules": [
    {
      "name": "Port Scan Detection",
      "type": "port_scan",
      "threshold": 10,
      "time_window": 5,
      "severity": "MEDIUM"
    }
  ]
}
```

## Working Example

Here's an example of running the IDS with verbose output:

```powershell
PS C:\Users\Mohamed\source\repos\Cybersecurity project\Intrusion-Detection-System> python ids.py -v

======================================================================
Intrusion Detection System Started
Press Ctrl+C to stop
======================================================================

[14:32:45] [HIGH] SYN Flood Attack | 192.168.1.100:12345 -> 10.0.0.1:443 | Detected 52 SYN packets in 5 seconds
[14:33:12] [MEDIUM] Port Scan Detected | 192.168.1.50:45678 -> 192.168.1.1:22 | Source scanning 25 different ports
[14:34:01] [CRITICAL] SQL Injection Attempt | 192.168.1.75:8080 -> 10.0.0.50:3306 | Detected SQL injection pattern: union select

======================================================================
IDS Statistics
======================================================================
Total packets processed: 5432
Total alerts raised: 3

Alerts by severity:
  CRITICAL: 1
  HIGH: 1
  MEDIUM: 1
======================================================================
```

### Log File Example
The IDS also creates a detailed log file (`ids.log`):
```json
2025-01-05 14:32:45 - WARNING - {"timestamp": "2025-01-05T14:32:45.123456", "alert_type": "SYN Flood Attack", "severity": "HIGH", "source_ip": "192.168.1.100", "destination_ip": "10.0.0.1", "source_port": 12345, "destination_port": 443, "protocol": "TCP", "details": "Detected 52 SYN packets in 5 seconds"}
```

## Troubleshooting

### Administrator/Root Required
The IDS needs elevated privileges to capture network packets:

**Windows:**
```powershell
# Run PowerShell as Administrator
# Then run:
python ids.py
```

**Linux:**
```bash
sudo python ids.py
```

### Python not found
Make sure Python is installed:
```powershell
python --version
```

### No packets captured
- Check that you're running as Administrator/root
- Verify the network interface name with: `ipconfig` (Windows) or `ifconfig` (Linux)
- Use `-i` flag to specify interface: `python ids.py -i eth0`

### Too many false positives
- Adjust detection thresholds in `rules.json`
- Increase time window for detection
- Use custom rules for your environment

### Memory usage too high
- Reduce the time window for tracking
- Monitor specific ports only
- Run on a dedicated machine for production

## Performance Considerations

- Monitor traffic on high-speed networks may require tuning
- Use interface filtering to reduce false positives
- Adjust packet buffer size based on available memory
- Consider running on dedicated hardware for production use

## Disclaimer

This tool is designed for authorized network monitoring only. Ensure you have explicit permission before monitoring any network. Unauthorized network monitoring is illegal in many jurisdictions.

## Author

Created for cybersecurity portfolio
