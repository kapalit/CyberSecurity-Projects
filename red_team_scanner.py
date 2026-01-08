#!/usr/bin/env python3
"""
Red Team Automation Script
Runs Nmap scans, parses results, flags risky services, and generates reports.
Production-ready for enterprise deployment.
"""

import nmap
import json
import argparse
import sys
import logging
import os
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from pathlib import Path

# Risky services database: port/service -> risk level & description
RISKY_SERVICES = {
    21: {"name": "FTP", "risk": "CRITICAL", "note": "Unencrypted credentials"},
    23: {"name": "Telnet", "risk": "CRITICAL", "note": "Unencrypted remote access"},
    25: {"name": "SMTP", "risk": "HIGH", "note": "Mail server - potential relay"},
    53: {"name": "DNS", "risk": "MEDIUM", "note": "Zone transfer vulnerabilities"},
    80: {"name": "HTTP", "risk": "HIGH", "note": "Unencrypted web traffic"},
    110: {"name": "POP3", "risk": "HIGH", "note": "Unencrypted email"},
    123: {"name": "NTP", "risk": "MEDIUM", "note": "NTP amplification attacks"},
    143: {"name": "IMAP", "risk": "HIGH", "note": "Unencrypted email"},
    161: {"name": "SNMP", "risk": "HIGH", "note": "Weak community strings"},
    389: {"name": "LDAP", "risk": "MEDIUM", "note": "Information disclosure"},
    445: {"name": "SMB", "risk": "CRITICAL", "note": "Ransomware & lateral movement"},
    3306: {"name": "MySQL", "risk": "CRITICAL", "note": "Database exposure"},
    3389: {"name": "RDP", "risk": "CRITICAL", "note": "Brute force & exploitation"},
    5432: {"name": "PostgreSQL", "risk": "CRITICAL", "note": "Database exposure"},
    5900: {"name": "VNC", "risk": "CRITICAL", "note": "Weak encryption"},
    6379: {"name": "Redis", "risk": "CRITICAL", "note": "No authentication"},
    8080: {"name": "HTTP-ALT", "risk": "HIGH", "note": "Unencrypted web traffic"},
    27017: {"name": "MongoDB", "risk": "CRITICAL", "note": "Database exposure"},
}


class RedTeamScanner:
    """Main Red Team Scanner class for conducting Nmap scans and analysis."""

    def __init__(self, verbose: bool = False, log_file: Optional[str] = None):
        """
        Initialize the scanner.
        
        Args:
            verbose: Enable verbose logging
            log_file: Optional log file path
        """
        self.nm = nmap.PortScanner()
        self.verbose = verbose
        self.scan_results = {}
        self.risky_findings = []
        self.logger = self._setup_logging(verbose, log_file)

    def _setup_logging(self, verbose: bool, log_file: Optional[str]) -> logging.Logger:
        """Configure logging for the scanner."""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler
        if log_file:
            try:
                Path(log_file).parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
            except Exception as e:
                print(f"[-] Warning: Could not create log file {log_file}: {e}", file=sys.stderr)
        
        return logger

    def run_scan(self, target: str, arguments: str = "-sV -p- --open") -> bool:
        """
        Run Nmap scan against target.
        
        Args:
            target: Target IP or hostname
            arguments: Nmap arguments (default: service detection, all ports, open only)
        
        Returns:
            bool: True if scan successful, False otherwise
        """
        try:
            self.logger.info(f"Starting scan on target: {target}")
            self.logger.debug(f"Nmap arguments: {arguments}")

            self.nm.scan(hosts=target, arguments=arguments)
            
            self.logger.info(f"Scan completed successfully")
            return True
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during scan: {e}", exc_info=True)
            return False

    def parse_results(self) -> Dict:
        """
        Parse Nmap scan results and identify open ports/services.
        
        Returns:
            dict: Parsed results organized by host
        """
        results = {}
        hosts_found = 0

        for host in self.nm.all_hosts():
            if self.nm[host].state() != "up":
                continue

            hosts_found += 1
            results[host] = {
                "status": self.nm[host].state(),
                "hostname": self.nm[host].hostname(),
                "ports": []
            }

            # Iterate through protocols (tcp, udp)
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()

                for port in ports:
                    port_info = self.nm[host][proto][port]
                    port_data = {
                        "port": port,
                        "protocol": proto,
                        "state": port_info["state"],
                        "service": port_info.get("name", "unknown"),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                    }
                    results[host]["ports"].append(port_data)

            self.logger.debug(f"Parsed host {host}: {len(results[host]['ports'])} ports")
            self.scan_results = results

        self.logger.info(f"Parse complete: {hosts_found} host(s) analyzed")
        return results

    def flag_risky_services(self) -> List[Dict]:
        """
        Identify and flag risky services from scan results.
        
        Returns:
            list: List of risky findings
        """
        self.risky_findings = []

        for host, data in self.scan_results.items():
            for port_info in data["ports"]:
                port = port_info["port"]

                # Check if port is in risky services database
                if port in RISKY_SERVICES:
                    risk_data = RISKY_SERVICES[port]
                    finding = {
                        "host": host,
                        "port": port,
                        "service": risk_data["name"],
                        "risk_level": risk_data["risk"],
                        "description": risk_data["note"],
                        "detected_version": f"{port_info['product']} {port_info['version']}".strip(),
                    }
                    self.risky_findings.append(finding)

                    self.logger.warning(
                        f"RISKY SERVICE FOUND: {host}:{port} - {risk_data['name']} "
                        f"[{risk_data['risk']}]"
                    )

        self.logger.info(f"Risk assessment complete: {len(self.risky_findings)} risky services flagged")
        return self.risky_findings

    def generate_report(self, output_file: str = None) -> str:
        """
        Generate a mini report of findings.
        
        Args:
            output_file: Optional file path to save report
        
        Returns:
            str: Formatted report
        """
        report = []
        report.append("=" * 70)
        report.append("RED TEAM AUTOMATION REPORT")
        report.append("=" * 70)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # Summary
        total_hosts = len(self.scan_results)
        total_ports = sum(len(data["ports"]) for data in self.scan_results.values())
        critical_count = len([f for f in self.risky_findings if f["risk_level"] == "CRITICAL"])
        high_count = len([f for f in self.risky_findings if f["risk_level"] == "HIGH"])
        medium_count = len([f for f in self.risky_findings if f["risk_level"] == "MEDIUM"])

        report.append("SUMMARY")
        report.append("-" * 70)
        report.append(f"Total Hosts Scanned: {total_hosts}")
        report.append(f"Total Open Ports Found: {total_ports}")
        report.append(f"Risky Services Found: {len(self.risky_findings)}")
        report.append(f"  - CRITICAL: {critical_count}")
        report.append(f"  - HIGH: {high_count}")
        report.append(f"  - MEDIUM: {medium_count}\n")

        # Host Details
        report.append("HOST DETAILS")
        report.append("-" * 70)
        for host, data in self.scan_results.items():
            report.append(f"\nHost: {host}")
            report.append(f"Status: {data['status']}")
            if data["hostname"]:
                report.append(f"Hostname: {data['hostname']}")
            report.append(f"Open Ports: {len(data['ports'])}")

        # Risky Findings
        if self.risky_findings:
            report.append("\n" + "=" * 70)
            report.append("RISKY FINDINGS (Flagged Services)")
            report.append("=" * 70)

            for finding in sorted(self.risky_findings, key=lambda x: ("CRITICAL", "HIGH", "MEDIUM").index(x["risk_level"])):
                report.append(f"\n[{finding['risk_level']}] {finding['host']}:{finding['port']}")
                report.append(f"  Service: {finding['service']}")
                report.append(f"  Description: {finding['description']}")
                if finding["detected_version"]:
                    report.append(f"  Version: {finding['detected_version']}")
        else:
            report.append("\n[+] No critical risky services detected")

        report.append("\n" + "=" * 70)

        report_text = "\n".join(report)

        # Save to file if requested
        if output_file:
            try:
                Path(output_file).parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, "w") as f:
                    f.write(report_text)
                self.logger.info(f"Report saved to {output_file}")
            except Exception as e:
                self.logger.error(f"Error saving report: {e}")

        return report_text

    def export_json(self, output_file: str) -> bool:
        """
        Export findings as JSON.
        
        Args:
            output_file: Path to save JSON file
        
        Returns:
            bool: True if successful
        """
        try:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            data = {
                "timestamp": datetime.now().isoformat(),
                "scan_results": self.scan_results,
                "risky_findings": self.risky_findings,
                "summary": {
                    "total_hosts": len(self.scan_results),
                    "total_ports": sum(len(data["ports"]) for data in self.scan_results.values()),
                    "risky_count": len(self.risky_findings),
                }
            }
            with open(output_file, "w") as f:
                json.dump(data, f, indent=2)
            self.logger.info(f"JSON export saved to {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Error exporting JSON: {e}")
            return False


def main():
    """Main entry point for the Red Team Automation Script."""
    parser = argparse.ArgumentParser(
        description="Red Team Automation Script - Nmap Scanner with Risky Service Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with default settings
  %(prog)s 192.168.1.1
  
  # Scan specific ports with verbose logging
  %(prog)s 192.168.1.1 -a "-sS -p 22,80,443" -v
  
  # Generate report and JSON export
  %(prog)s 192.168.1.1 -o scan_report.txt -j scan_findings.json
  
  # Scan with custom logging
  %(prog)s 192.168.1.1 -l scan.log -v
        """
    )
    parser.add_argument("target", help="Target IP address, hostname, or CIDR range to scan")
    parser.add_argument(
        "-a", "--arguments",
        default="-sV -p- --open",
        help="Nmap arguments (default: '-sV -p- --open')"
    )
    parser.add_argument(
        "-o", "--output",
        default="red_team_report.txt",
        help="Output report file (default: 'red_team_report.txt')"
    )
    parser.add_argument(
        "-j", "--json",
        help="Export results as JSON"
    )
    parser.add_argument(
        "-l", "--log",
        help="Log file path for scan activity"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip text report generation"
    )

    args = parser.parse_args()

    # Validate target
    if not args.target:
        parser.print_help()
        return 1

    # Initialize scanner with logging
    scanner = RedTeamScanner(verbose=args.verbose, log_file=args.log)
    scanner.logger.info("=" * 70)
    scanner.logger.info("Red Team Automation Script Started")
    scanner.logger.info("=" * 70)

    # Run scan
    if not scanner.run_scan(args.target, args.arguments):
        scanner.logger.error("Scan failed - aborting")
        return 1

    # Parse results
    scanner.parse_results()

    # Flag risky services
    scanner.flag_risky_services()

    # Generate report
    if not args.no_report:
        report = scanner.generate_report(args.output)
        print(report)

    # Export JSON if requested
    if args.json:
        if not scanner.export_json(args.json):
            scanner.logger.error("JSON export failed")
            return 1

    scanner.logger.info("=" * 70)
    scanner.logger.info("Red Team Automation Script Completed Successfully")
    scanner.logger.info("=" * 70)
    
    if not args.no_report:
        print(f"\n[+] Report saved to {args.output}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
