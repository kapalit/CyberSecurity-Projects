#!/usr/bin/env python3
"""
Intrusion Detection System (IDS)
Monitors network traffic and detects malicious patterns and anomalies
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple
import socket
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
from colorama import Fore, Style, init

init(autoreset=True)


class Alert:
    """Represents a security alert"""
    
    SEVERITY_COLORS = {
        'CRITICAL': Fore.RED,
        'HIGH': Fore.YELLOW,
        'MEDIUM': Fore.BLUE,
        'LOW': Fore.GREEN,
    }
    
    def __init__(self, alert_type: str, severity: str, source_ip: str, 
                 destination_ip: str, details: str, protocol: str = 'UNKNOWN', 
                 source_port: int = None, destination_port: int = None):
        self.timestamp = datetime.now()
        self.alert_type = alert_type
        self.severity = severity
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.details = details
        self.protocol = protocol
        self.source_port = source_port
        self.destination_port = destination_port
    
    def __str__(self):
        color = self.SEVERITY_COLORS.get(self.severity, Fore.WHITE)
        time_str = self.timestamp.strftime('%H:%M:%S')
        port_info = ""
        if self.source_port and self.destination_port:
            port_info = f":{self.source_port} -> {self.destination_ip}:{self.destination_port}"
        else:
            port_info = f"-> {self.destination_ip}"
        
        return (f"{color}[{time_str}] [{self.severity}] {self.alert_type} | "
                f"{self.source_ip}{port_info} | {self.details}")
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'alert_type': self.alert_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'details': self.details
        }


class IntrusionDetectionSystem:
    """Main IDS class"""
    
    # Known malicious IPs (example list)
    KNOWN_MALICIOUS_IPS = [
        '192.168.100.50',  # Example - would be real threat intelligence
        '10.0.0.50',
    ]
    
    # Known malicious domains
    KNOWN_MALICIOUS_DOMAINS = [
        'malware.com',
        'botnet.xyz',
        'phishing.net',
    ]
    
    def __init__(self, rules_file: str = None, verbose: bool = False, log_file: str = 'ids.log'):
        self.verbose = verbose
        self.log_file = log_file
        self.alerts: List[Alert] = []
        self.packet_count = 0
        
        # Setup logging
        self.setup_logging()
        
        # Load rules
        self.rules = self.load_rules(rules_file)
        
        # Tracking for anomaly detection
        self.port_access_count = defaultdict(lambda: defaultdict(list))
        self.syn_packets = defaultdict(list)
        self.dns_queries = defaultdict(list)
        self.connection_attempts = defaultdict(list)
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_rules(self, rules_file: str = None) -> Dict:
        """Load detection rules from JSON file"""
        if rules_file is None:
            rules_file = 'rules.json'
        
        try:
            with open(rules_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self.log(f"Rules file {rules_file} not found. Using default rules.", 'WARNING')
            return self.get_default_rules()
    
    def get_default_rules(self) -> Dict:
        """Return default detection rules"""
        return {
            "rules": [
                {
                    "name": "Port Scan Detection",
                    "type": "port_scan",
                    "threshold": 10,
                    "severity": "MEDIUM"
                },
                {
                    "name": "SYN Flood",
                    "type": "syn_flood",
                    "threshold": 100,
                    "severity": "HIGH"
                },
                {
                    "name": "SQL Injection",
                    "type": "sql_injection",
                    "severity": "CRITICAL"
                }
            ]
        }
    
    def log(self, message: str, level: str = 'INFO'):
        """Log message"""
        if level == 'INFO':
            self.logger.info(message)
        elif level == 'WARNING':
            self.logger.warning(message)
        elif level == 'ERROR':
            self.logger.error(message)
        elif level == 'CRITICAL':
            self.logger.critical(message)
    
    def packet_callback(self, packet):
        """Callback function for packet processing"""
        self.packet_count += 1
        
        try:
            # Extract IP layer
            if IP in packet:
                ip_layer = packet[IP]
                source_ip = ip_layer.src
                dest_ip = ip_layer.dst
                
                # Check for known malicious IPs
                self.check_known_threats(source_ip, dest_ip, packet)
                
                # Protocol-specific analysis
                if TCP in packet:
                    self.analyze_tcp(packet, source_ip, dest_ip)
                elif UDP in packet:
                    self.analyze_udp(packet, source_ip, dest_ip)
                elif ICMP in packet:
                    self.analyze_icmp(packet, source_ip, dest_ip)
                
                # Check for payload-based attacks
                self.check_payload_attacks(packet, source_ip, dest_ip)
        
        except Exception as e:
            if self.verbose:
                self.log(f"Error processing packet: {str(e)}", 'WARNING')
    
    def check_known_threats(self, source_ip: str, dest_ip: str, packet):
        """Check packet against known threat intelligence"""
        
        # Check against known malicious IPs
        if source_ip in self.KNOWN_MALICIOUS_IPS:
            alert = Alert(
                alert_type='Known Malicious IP',
                severity='CRITICAL',
                source_ip=source_ip,
                destination_ip=dest_ip,
                details=f'Packet from known malicious IP: {source_ip}',
                protocol=packet[IP].proto
            )
            self.raise_alert(alert)
        
        if dest_ip in self.KNOWN_MALICIOUS_IPS:
            alert = Alert(
                alert_type='Connection to Malicious IP',
                severity='HIGH',
                source_ip=source_ip,
                destination_ip=dest_ip,
                details=f'Attempting to connect to known malicious IP: {dest_ip}',
                protocol=packet[IP].proto
            )
            self.raise_alert(alert)
    
    def analyze_tcp(self, packet, source_ip: str, dest_ip: str):
        """Analyze TCP packets"""
        tcp_layer = packet[TCP]
        source_port = tcp_layer.sport
        dest_port = tcp_layer.dport
        
        # SYN Flood Detection
        if tcp_layer.flags == 'S':  # SYN flag
            key = (source_ip, dest_ip, dest_port)
            self.syn_packets[key].append(time.time())
            
            # Remove old entries (older than 5 seconds)
            current_time = time.time()
            self.syn_packets[key] = [t for t in self.syn_packets[key] 
                                      if current_time - t < 5]
            
            # Check threshold
            if len(self.syn_packets[key]) > 50:
                alert = Alert(
                    alert_type='SYN Flood Attack',
                    severity='HIGH',
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    source_port=source_port,
                    destination_port=dest_port,
                    details=f'Detected {len(self.syn_packets[key])} SYN packets in 5 seconds',
                    protocol='TCP'
                )
                self.raise_alert(alert)
        
        # Port Scan Detection
        if tcp_layer.flags == 'S':  # Connection attempt
            key = source_ip
            self.port_access_count[key][dest_port].append(time.time())
            
            # Clean old entries
            current_time = time.time()
            for port in self.port_access_count[key]:
                self.port_access_count[key][port] = [
                    t for t in self.port_access_count[key][port] 
                    if current_time - t < 10
                ]
            
            # Check if accessing multiple ports (port scan detection)
            if len(self.port_access_count[key]) > 20:
                alert = Alert(
                    alert_type='Port Scan Detected',
                    severity='MEDIUM',
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    source_port=source_port,
                    destination_port=dest_port,
                    details=f'Source scanning {len(self.port_access_count[key])} different ports',
                    protocol='TCP'
                )
                self.raise_alert(alert)
    
    def analyze_udp(self, packet, source_ip: str, dest_ip: str):
        """Analyze UDP packets"""
        udp_layer = packet[UDP]
        dest_port = udp_layer.dport
        
        # DNS Amplification Detection
        if dest_port == 53:  # DNS port
            key = (source_ip, dest_ip)
            self.dns_queries[key].append(time.time())
            
            # Remove old entries
            current_time = time.time()
            self.dns_queries[key] = [t for t in self.dns_queries[key] 
                                      if current_time - t < 5]
            
            # Check for suspicious patterns
            if len(self.dns_queries[key]) > 100:
                alert = Alert(
                    alert_type='DNS Amplification Attack',
                    severity='HIGH',
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    source_port=udp_layer.sport,
                    destination_port=dest_port,
                    details=f'Detected {len(self.dns_queries[key])} DNS queries in 5 seconds',
                    protocol='UDP'
                )
                self.raise_alert(alert)
    
    def analyze_icmp(self, packet, source_ip: str, dest_ip: str):
        """Analyze ICMP packets"""
        icmp_layer = packet[ICMP]
        
        # ICMP Flood Detection
        key = (source_ip, dest_ip)
        if key not in self.dns_queries:
            self.dns_queries[key] = []
        
        self.dns_queries[key].append(time.time())
        
        # Clean old entries
        current_time = time.time()
        self.dns_queries[key] = [t for t in self.dns_queries[key] 
                                  if current_time - t < 5]
        
        if len(self.dns_queries[key]) > 100:
            alert = Alert(
                alert_type='ICMP Flood Attack',
                severity='HIGH',
                source_ip=source_ip,
                destination_ip=dest_ip,
                details=f'Detected {len(self.dns_queries[key])} ICMP packets in 5 seconds',
                protocol='ICMP'
            )
            self.raise_alert(alert)
    
    def check_payload_attacks(self, packet, source_ip: str, dest_ip: str):
        """Check packet payload for attack signatures"""
        
        # Extract payload if available
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            try:
                payload_str = payload.decode('utf-8', errors='ignore').lower()
            except:
                return
            
            # SQL Injection patterns
            sql_patterns = ['union select', 'or 1=1', 'drop table', 'exec(', 
                           'select * from', '--', '/*', '*/']
            for pattern in sql_patterns:
                if pattern in payload_str:
                    alert = Alert(
                        alert_type='SQL Injection Attempt',
                        severity='CRITICAL',
                        source_ip=source_ip,
                        destination_ip=dest_ip,
                        details=f'Detected SQL injection pattern: {pattern}',
                        protocol='UNKNOWN'
                    )
                    self.raise_alert(alert)
                    return
            
            # XSS patterns
            xss_patterns = ['<script>', 'onclick=', 'onerror=', 'javascript:']
            for pattern in xss_patterns:
                if pattern in payload_str:
                    alert = Alert(
                        alert_type='XSS Attempt',
                        severity='HIGH',
                        source_ip=source_ip,
                        destination_ip=dest_ip,
                        details=f'Detected XSS pattern: {pattern}',
                        protocol='UNKNOWN'
                    )
                    self.raise_alert(alert)
                    return
            
            # Command Injection patterns
            cmd_patterns = ['; cat ', '; ls ', '| nc ', '&& wget', '| bash']
            for pattern in cmd_patterns:
                if pattern in payload_str:
                    alert = Alert(
                        alert_type='Command Injection Attempt',
                        severity='CRITICAL',
                        source_ip=source_ip,
                        destination_ip=dest_ip,
                        details=f'Detected command injection pattern: {pattern}',
                        protocol='UNKNOWN'
                    )
                    self.raise_alert(alert)
                    return
    
    def raise_alert(self, alert: Alert):
        """Raise and log an alert"""
        self.alerts.append(alert)
        print(alert)
        self.log(json.dumps(alert.to_dict()), 'WARNING')
    
    def print_statistics(self):
        """Print IDS statistics"""
        print(f"\n{'='*70}")
        print(f"{Fore.CYAN}IDS Statistics")
        print(f"{'='*70}")
        print(f"Total packets processed: {self.packet_count}")
        print(f"Total alerts raised: {len(self.alerts)}")
        
        # Alerts by severity
        severity_count = defaultdict(int)
        for alert in self.alerts:
            severity_count[alert.severity] += 1
        
        print(f"\nAlerts by severity:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_count:
                print(f"  {severity}: {severity_count[severity]}")
        
        print(f"{'='*70}\n")
    
    def start_monitoring(self, interface: str = None, packet_count: int = 0):
        """Start monitoring network traffic"""
        self.log("Starting Intrusion Detection System...")
        self.log(f"Monitoring interface: {interface if interface else 'auto-detect'}")
        self.log(f"Loaded {len(self.rules.get('rules', []))} detection rules")
        
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}Intrusion Detection System Started")
        print(f"{Fore.CYAN}Press Ctrl+C to stop")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        try:
            # Start sniffing packets
            sniff(
                prn=self.packet_callback,
                iface=interface,
                filter="ip",
                store=False,
                count=packet_count if packet_count > 0 else 0
            )
        except KeyboardInterrupt:
            self.print_statistics()
            self.log("IDS stopped by user")
        except PermissionError:
            self.log("Error: This tool requires administrator/root privileges", 'ERROR')
            sys.exit(1)
        except Exception as e:
            self.log(f"Error during monitoring: {str(e)}", 'ERROR')
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Intrusion Detection System - Monitor network traffic for threats',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ids.py
  python ids.py -i eth0
  python ids.py -r custom_rules.json -v
  python ids.py -l /var/log/ids.log
        """
    )
    
    parser.add_argument('-i', '--interface', default=None,
                        help='Network interface to monitor (default: auto-detect)')
    parser.add_argument('-r', '--rules', default='rules.json',
                        help='Rules file (JSON format)')
    parser.add_argument('-l', '--log', default='ids.log',
                        help='Log file path')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('-c', '--count', type=int, default=0,
                        help='Number of packets to capture (0 = infinite)')
    
    args = parser.parse_args()
    
    # Create IDS instance
    ids = IntrusionDetectionSystem(
        rules_file=args.rules,
        verbose=args.verbose,
        log_file=args.log
    )
    
    # Start monitoring
    ids.start_monitoring(interface=args.interface, packet_count=args.count)


if __name__ == '__main__':
    main()
