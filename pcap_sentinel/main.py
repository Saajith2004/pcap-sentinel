"""
PCAP Sentinel
A Python command-line tool for summarising packet captures and flagging
simple indicators that warrant further investigation.

This tool is intended for defensive analysis and education. Findings are
heuristics, not proof of malicious activity.
"""

import argparse
import csv
from collections import Counter
from pathlib import Path
from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

PORTS_OF_INTEREST = {22, 23, 445, 3389, 4444}
PORT_SCAN_THRESHOLD = 10
REPEATED_DNS_THRESHOLD = 10

PROTOCOL_CSV_HEADER = ["protocol", "packet_count"]
IP_CSV_HEADER = ["source_ip", "destination_ip", "packet_count"]
DNS_CSV_HEADER = ["domain", "query_count"]
FINDINGS_CSV_HEADER = [
    "rule", "severity", "source_ip", "destination_ip", "evidence",
    "recommendation",
]


def analyse_pcap(pcap_path: Path) -> dict[str, Any]:
    """Analyse a PCAP/PCAPNG file and return counters plus heuristic findings."""
    packet_count = 0
    ip_pairs: Counter[tuple[str, str]] = Counter()
    protocols: Counter[str] = Counter()
    dns_queries: Counter[str] = Counter()
    tcp_ports_by_pair: dict[tuple[str, str], set[int]] = {}
    port_findings: Counter[tuple[str, str, int, str]] = Counter()

    with PcapReader(str(pcap_path)) as capture:
        for packet in capture:
            packet_count += 1

            if IP in packet:
                protocols["IPv4"] += 1
                ip_pairs[(packet[IP].src, packet[IP].dst)] += 1
            elif IPv6 in packet:
                protocols["IPv6"] += 1
                ip_pairs[(packet[IPv6].src, packet[IPv6].dst)] += 1

            if TCP in packet:
                protocols["TCP"] += 1
            if UDP in packet:
                protocols["UDP"] += 1
            if ICMP in packet:
                protocols["ICMP"] += 1

            if IP in packet and TCP in packet:
                src, dst = packet[IP].src, packet[IP].dst
                port = int(packet[TCP].dport)
                tcp_ports_by_pair.setdefault((src, dst), set()).add(port)
                if port in PORTS_OF_INTEREST:
                    port_findings[(src, dst, port, "TCP")] += 1
            elif IP in packet and UDP in packet:
                src, dst = packet[IP].src, packet[IP].dst
                port = int(packet[UDP].dport)
                if port in PORTS_OF_INTEREST:
                    port_findings[(src, dst, port, "UDP")] += 1

            if DNS in packet:
                protocols["DNS"] += 1
                dns = packet[DNS]
                if dns.qr == 0 and DNSQR in dns:
                    query = dns[DNSQR].qname
                    if isinstance(query, bytes):
                        query = query.decode("utf-8", errors="replace")
                    dns_queries[query.rstrip(".")] += 1

    findings: list[dict[str, str]] = []

    for (src, dst), ports in tcp_ports_by_pair.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            findings.append({
                "rule": "possible_tcp_port_scan",
                "severity": "medium",
                "source_ip": src,
                "destination_ip": dst,
                "evidence": f"Contacted {len(ports)} distinct TCP destination ports",
                "recommendation": (
                    "Review the connection pattern and destination ports. "
                    "This is an indicator, not proof, of scanning."
                ),
            })

    for domain, count in dns_queries.items():
        if count >= REPEATED_DNS_THRESHOLD:
            findings.append({
                "rule": "repeated_dns_query",
                "severity": "low",
                "source_ip": "",
                "destination_ip": "",
                "evidence": f"Domain queried {count} times: {domain}",
                "recommendation": "Verify whether repeated lookups are expected.",
            })

    for (src, dst, port, protocol), count in port_findings.items():
        findings.append({
            "rule": "traffic_to_port_of_interest",
            "severity": "informational",
            "source_ip": src,
            "destination_ip": dst,
            "evidence": (
                f"Observed {count} packet(s) to "
                f"{protocol} destination port {port}"
            ),
            "recommendation": (
                "Validate whether the service is expected in the environment."
            ),
        })

    return {
        "packet_count": packet_count,
        "ip_pairs": ip_pairs,
        "protocols": protocols,
        "dns_queries": dns_queries,
        "findings": findings,
    }


def export_csv(results: dict[str, Any], output_dir: Path, capture_name: str) -> list[Path]:
    """Export protocol, IP communication, DNS query, and findings CSV reports."""
    output_dir.mkdir(parents=True, exist_ok=True)
    report_paths = [
        output_dir / f"{capture_name}_protocols.csv",
        output_dir / f"{capture_name}_ip_communications.csv",
        output_dir / f"{capture_name}_dns_queries.csv",
        output_dir / f"{capture_name}_findings.csv",
    ]

    with report_paths[0].open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(PROTOCOL_CSV_HEADER)
        for protocol, count in sorted(results["protocols"].items()):
            writer.writerow([protocol, count])

    with report_paths[1].open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(IP_CSV_HEADER)
        for (source, destination), count in results["ip_pairs"].most_common():
            writer.writerow([source, destination, count])

    with report_paths[2].open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(DNS_CSV_HEADER)
        for domain, count in results["dns_queries"].most_common():
            writer.writerow([domain, count])

    with report_paths[3].open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(FINDINGS_CSV_HEADER)
        for finding in results["findings"]:
            writer.writerow([finding[key] for key in FINDINGS_CSV_HEADER])

    return report_paths


def main() -> None:
    """Parse arguments, analyse the capture, display results, and export CSVs."""
    parser = argparse.ArgumentParser(
        description="PCAP Sentinel - Network Packet Analysis Tool",
        epilog=(
            "Note: findings are heuristic indicators and do not prove malicious "
            "activity. Analyse only captures you are authorised to inspect."
        ),
    )
    parser.add_argument("pcap_file", help="Path to a PCAP or PCAPNG capture")
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for CSV reports (default: reports)",
    )
    args = parser.parse_args()
    pcap_path = Path(args.pcap_file)

    if not pcap_path.is_file():
        parser.error(f"File not found: {pcap_path}")

    try:
        results = analyse_pcap(pcap_path)
    except Exception as error:
        parser.error(f"Unable to read capture file: {error}")

    print("=" * 48)
    print("                 PCAP SENTINEL")
    print("=" * 48)
    print(f"File analysed: {pcap_path.name}")
    print(f"Total packets: {results['packet_count']}")

    print("\nPROTOCOL SUMMARY")
    print("-" * 48)
    if results["protocols"]:
        for protocol, count in sorted(results["protocols"].items()):
            print(f"{protocol}: {count}")
    else:
        print("No supported protocols decoded.")

    print("\nIP COMMUNICATION SUMMARY")
    print("-" * 48)
    if results["ip_pairs"]:
        for (source, destination), count in results["ip_pairs"].most_common():
            print(f"{source} -> {destination} (packets: {count})")
    else:
        print("No decodable IPv4 or IPv6 packets found.")

    print("\nDNS QUERY SUMMARY")
    print("-" * 48)
    if results["dns_queries"]:
        for domain, count in results["dns_queries"].most_common():
            print(f"{domain} (queries: {count})")
    else:
        print("No decodable DNS queries found.")

    print("\nHEURISTIC FINDINGS")
    print("-" * 48)
    if results["findings"]:
        for finding in results["findings"]:
            print(f"Rule: {finding['rule']}")
            print(f"Severity: {finding['severity']}")
            if finding["source_ip"] or finding["destination_ip"]:
                print(f"{finding['source_ip']} -> {finding['destination_ip']}")
            print(f"Evidence: {finding['evidence']}")
            print(f"Recommendation: {finding['recommendation']}")
            print("-" * 48)
    else:
        print("No configured rules triggered. This does not prove the capture is benign.")

    try:
        report_paths = export_csv(results, Path(args.output_dir), pcap_path.stem)
    except OSError as error:
        parser.error(f"Unable to export CSV reports: {error}")

    print("\nCSV REPORTS")
    print("-" * 48)
    for report_path in report_paths:
        print(f"Created: {report_path}")
    print("\nStatus: Analysis completed")
    print("=" * 48)


if __name__ == "__main__":
    main()
