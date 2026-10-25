"""
ThreatNexus - PCAP/PCAPNG Network Traffic Analyzer

Features:
- Reads PCAP and PCAPNG captures supported by Scapy.
- Counts common network protocols.
- Summarizes IP communication pairs.
- Extracts DNS queries.
- Flags possible TCP port scans using a simple heuristic.
- Flags repeated DNS queries using a simple heuristic.
- Highlights traffic to selected TCP/UDP ports.
- Exports four CSV reports.

Usage:
    python threat_nexus/main.py path/to/capture.pcap
    python threat_nexus/main.py path/to/capture.pcap --output-dir reports

This tool is intended for authorized network analysis and educational use.
The detections are heuristic indicators, not proof of malicious activity.
"""

import argparse
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

from scapy.all import DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, rdpcap


PROJECT_NAME = "ThreatNexus"

PORTS_OF_INTEREST = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    4444: "Commonly used alternate service port",
}

PORT_SCAN_THRESHOLD = 10
REPEATED_DNS_THRESHOLD = 10


def _packet_protocol(packet):
    """Return a readable top-level protocol label for a packet."""
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    if DNS in packet:
        return "DNS"
    if IP in packet:
        return "IPv4"
    if IPv6 in packet:
        return "IPv6"
    return "Other"


def analyse_packets(packets):
    """
    Analyse an iterable of Scapy packets and return structured results.

    The returned dictionary contains:
        packet_count: total packets analysed
        protocol_counts: counts by protocol
        communications: packet counts for each source/destination IP pair
        dns_queries: count for each extracted DNS query name
        findings: heuristic findings
    """
    packet_count = 0
    protocol_counts = Counter()
    communications = Counter()
    dns_queries = Counter()
    tcp_destination_ports = defaultdict(set)
    port_traffic = Counter()
    findings = []

    for packet in packets:
        packet_count += 1

        protocol = _packet_protocol(packet)
        protocol_counts[protocol] += 1

        source_ip = None
        destination_ip = None

        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst

        if source_ip and destination_ip:
            communications[(source_ip, destination_ip)] += 1

        # Record TCP destination ports by source/destination IP pair.
        if TCP in packet and source_ip and destination_ip:
            destination_port = int(packet[TCP].dport)
            tcp_destination_ports[(source_ip, destination_ip)].add(
                destination_port
            )

        # Track traffic to selected TCP and UDP destination ports.
        if TCP in packet:
            destination_port = int(packet[TCP].dport)
            if destination_port in PORTS_OF_INTEREST:
                port_traffic[
                    (source_ip or "Unknown", destination_port, "TCP")
                ] += 1

        if UDP in packet:
            destination_port = int(packet[UDP].dport)
            if destination_port in PORTS_OF_INTEREST:
                port_traffic[
                    (source_ip or "Unknown", destination_port, "UDP")
                ] += 1

        # Robust DNS query extraction. DNS qname is commonly bytes in Scapy.
        if DNS in packet:
            dns_layer = packet[DNS]
            query_flag = getattr(dns_layer, "qr", None)
            query_layer = getattr(dns_layer, "qd", None)

            if query_flag == 0 and query_layer is not None:
                query_name = getattr(query_layer, "qname", None)

                # Handle a DNS question list if the capture has multiple
                # questions in a single DNS message.
                questions = []
                if query_name:
                    questions.append(query_name)
                else:
                    try:
                        for question in query_layer:
                            name = getattr(question, "qname", None)
                            if name:
                                questions.append(name)
                    except (TypeError, AttributeError):
                        pass

                for query_name in questions:
                    if isinstance(query_name, bytes):
                        query_name = query_name.decode(
                            "utf-8", errors="replace"
                        )

                    query_name = str(query_name).rstrip(".").strip()
                    if query_name:
                        dns_queries[query_name] += 1

    # Heuristic: a single source/destination pair touching many TCP
    # destination ports may indicate port scanning.
    for (source_ip, destination_ip), destination_ports in (
        tcp_destination_ports.items()
    ):
        if len(destination_ports) >= PORT_SCAN_THRESHOLD:
            findings.append(
                {
                    "severity": "Medium",
                    "rule": "possible_tcp_port_scan",
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "details": (
                        f"{len(destination_ports)} distinct TCP destination "
                        f"ports observed from {source_ip} to {destination_ip}."
                    ),
                    "evidence_count": len(destination_ports),
                }
            )

    # Heuristic: many occurrences of the same DNS query may be noteworthy.
    for query_name, count in dns_queries.items():
        if count >= REPEATED_DNS_THRESHOLD:
            findings.append(
                {
                    "severity": "Low",
                    "rule": "repeated_dns_query",
                    "source_ip": "",
                    "destination_ip": "",
                    "details": (
                        f"DNS query '{query_name}' occurred {count} times."
                    ),
                    "evidence_count": count,
                }
            )

    # Informational finding for traffic targeting selected service ports.
    for (source_ip, destination_port, transport), count in port_traffic.items():
        service_name = PORTS_OF_INTEREST[destination_port]
        findings.append(
            {
                "severity": "Informational",
                "rule": "traffic_to_interesting_port",
                "source_ip": source_ip,
                "destination_ip": "",
                "details": (
                    f"{count} {transport} packet(s) from {source_ip} targeted "
                    f"port {destination_port} ({service_name})."
                ),
                "evidence_count": count,
            }
        )

    # Stable, predictable output order makes reports easier to compare.
    findings.sort(
        key=lambda finding: (
            finding["severity"],
            finding["rule"],
            finding["source_ip"],
            finding["destination_ip"],
            finding["details"],
        )
    )

    return {
        "packet_count": packet_count,
        "protocol_counts": dict(protocol_counts),
        "communications": dict(communications),
        "dns_queries": dict(dns_queries),
        "findings": findings,
    }


def write_csv(file_path, fieldnames, rows):
    """Write rows to a CSV file, including headers for empty reports."""
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with file_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


def export_reports(results, output_dir="reports"):
    """Export analysis results to four CSV files and return their paths."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    protocol_rows = [
        {"protocol": protocol, "packet_count": count}
        for protocol, count in sorted(
            results["protocol_counts"].items(),
            key=lambda item: item[0],
        )
    ]

    communication_rows = [
        {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "packet_count": count,
        }
        for (source_ip, destination_ip), count in sorted(
            results["communications"].items(),
            key=lambda item: (item[0][0], item[0][1]),
        )
    ]

    dns_rows = [
        {"query_name": query_name, "query_count": count}
        for query_name, count in sorted(
            results["dns_queries"].items(),
            key=lambda item: item[0].lower(),
        )
    ]

    finding_fields = [
        "severity",
        "rule",
        "source_ip",
        "destination_ip",
        "details",
        "evidence_count",
    ]

    report_paths = {
        "protocols": output_path / "protocols.csv",
        "communications": output_path / "ip_communications.csv",
        "dns_queries": output_path / "dns_queries.csv",
        "findings": output_path / "findings.csv",
    }

    write_csv(
        report_paths["protocols"],
        ["protocol", "packet_count"],
        protocol_rows,
    )
    write_csv(
        report_paths["communications"],
        ["source_ip", "destination_ip", "packet_count"],
        communication_rows,
    )
    write_csv(
        report_paths["dns_queries"],
        ["query_name", "query_count"],
        dns_rows,
    )
    write_csv(
        report_paths["findings"],
        finding_fields,
        results["findings"],
    )

    return report_paths


def analyse_capture(capture_path, output_dir="reports"):
    """Read a capture file, analyse it, export reports, and return results."""
    capture_path = Path(capture_path)

    if not capture_path.is_file():
        raise FileNotFoundError(f"Capture file not found: {capture_path}")

    try:
        packets = rdpcap(str(capture_path))
    except Exception as exc:
        raise ValueError(
            f"Could not read capture file '{capture_path}': {exc}"
        ) from exc

    results = analyse_packets(packets)
    results["capture_file"] = str(capture_path)
    results["report_paths"] = export_reports(results, output_dir)
    return results


def print_summary(results):
    """Print a readable summary of the analysis."""
    print(f"\n{PROJECT_NAME} - Network Capture Analysis")
    print("=" * 46)
    print(f"Capture: {results.get('capture_file', '(in-memory packets)')}")
    print(f"Packets analysed: {results['packet_count']}")

    print("\nProtocol counts:")
    if results["protocol_counts"]:
        for protocol, count in sorted(results["protocol_counts"].items()):
            print(f"  {protocol:<10} {count}")
    else:
        print("  No packets found.")

    print("\nTop IP communication pairs:")
    communications = sorted(
        results["communications"].items(),
        key=lambda item: item[1],
        reverse=True,
    )
    if communications:
        for (source_ip, destination_ip), count in communications[:10]:
            print(f"  {source_ip} -> {destination_ip}: {count} packet(s)")
    else:
        print("  No IP communication pairs found.")

    print("\nDNS queries:")
    if results["dns_queries"]:
        for query_name, count in sorted(
            results["dns_queries"].items(),
            key=lambda item: item[1],
            reverse=True,
        )[:20]:
            print(f"  {query_name}: {count}")
    else:
        print("  No DNS queries extracted.")

    print("\nFindings:")
    if results["findings"]:
        for finding in results["findings"]:
            print(
                f"  [{finding['severity']}] {finding['rule']}: "
                f"{finding['details']}"
            )
    else:
        print("  No heuristic findings generated.")

    if results.get("report_paths"):
        print("\nCSV reports written:")
        for name, path in results["report_paths"].items():
            print(f"  {name}: {path}")

    print(
        "\nNote: findings are heuristic indicators and require validation; "
        "they are not proof of malicious activity."
    )


def build_argument_parser():
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="threat-nexus",
        description="Analyse a PCAP/PCAPNG capture with ThreatNexus.",
    )
    parser.add_argument(
        "capture",
        help="Path to a PCAP or PCAPNG capture file.",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for CSV reports (default: reports).",
    )
    return parser


def main(argv=None):
    """CLI entry point."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    try:
        results = analyse_capture(args.capture, args.output_dir)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"Permission error: {exc}", file=sys.stderr)
        return 1

    print_summary(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

