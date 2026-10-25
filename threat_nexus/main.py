#!/usr/bin/env python3
"""
ThreatNexus - Network Traffic Analysis and Threat Detection.

Analyses PCAP/PCAPNG files, summarises protocols and IP communications,
extracts DNS queries, applies lightweight detection heuristics, and
exports CSV reports.
"""

import argparse
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, IPv6, TCP, UDP, ICMP, rdpcap


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


def analyse_packets(packets):
    """Analyse packets and return protocol counts, communications, DNS, findings."""

    protocol_counts = Counter()
    communications = Counter()
    dns_queries = Counter()
    tcp_destination_ports = defaultdict(set)
    port_traffic = Counter()
    findings = []

    for packet in packets:
        if IP in packet:
            protocol_counts["IPv4"] += 1
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

        elif IPv6 in packet:
            protocol_counts["IPv6"] += 1
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst

        else:
            continue

        communications[(source_ip, destination_ip)] += 1

        if TCP in packet:
            protocol_counts["TCP"] += 1
            tcp = packet[TCP]

            tcp_destination_ports[
                (source_ip, destination_ip)
            ].add(int(tcp.dport))

            if int(tcp.dport) in PORTS_OF_INTEREST:
                port_traffic[
                    (
                        source_ip,
                        destination_ip,
                        int(tcp.dport),
                    )
                ] += 1

        if UDP in packet:
            protocol_counts["UDP"] += 1
            udp = packet[UDP]

            if int(udp.dport) in PORTS_OF_INTEREST:
                port_traffic[
                    (
                        source_ip,
                        destination_ip,
                        int(udp.dport),
                    )
                ] += 1

        if ICMP in packet:
            protocol_counts["ICMP"] += 1

        if DNS in packet and packet[DNS].qd is not None:
            dns_layer = packet[DNS]

            if dns_layer.qr == 0:
                query_layer = dns_layer.qd

                if isinstance(query_layer, DNSQR):
                    query_name = query_layer.qname.decode(
                        "utf-8", errors="replace"
                    ).rstrip(".")

                    if query_name:
                        dns_queries[query_name] += 1

                        if "DNS" not in protocol_counts:
                            protocol_counts["DNS"] = 0

                        protocol_counts["DNS"] += 1

    # Possible TCP port scan heuristic.
    for (source_ip, destination_ip), ports in tcp_destination_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            findings.append({
                "rule": "possible_tcp_port_scan",
                "severity": "medium",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "evidence": (
                    f"{len(ports)} distinct TCP destination ports observed"
                ),
                "recommendation": (
                    "Investigate the source, destination, and connection pattern."
                ),
            })

    # Repeated DNS query heuristic.
    for query_name, count in dns_queries.items():
        if count >= REPEATED_DNS_THRESHOLD:
            findings.append({
                "rule": "repeated_dns_query",
                "severity": "low",
                "source_ip": "",
                "destination_ip": "",
                "evidence": (
                    f"DNS query '{query_name}' appeared {count} times"
                ),
                "recommendation": (
                    "Review the query frequency and the surrounding DNS traffic."
                ),
            })

    # Traffic to configured ports of interest.
    for (source_ip, destination_ip, port), count in port_traffic.items():
        findings.append({
            "rule": "traffic_to_port_of_interest",
            "severity": "informational",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "evidence": (
                f"{count} packet(s) observed to destination port "
                f"{port} ({PORTS_OF_INTEREST[port]})"
            ),
            "recommendation": (
                "Verify whether the destination service is expected and authorised."
            ),
        })

    return {
        "protocol_counts": protocol_counts,
        "communications": communications,
        "dns_queries": dns_queries,
        "findings": findings,
    }


def write_csv(path, fieldnames, rows):
    """Write dictionaries to a CSV file."""

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def export_reports(results, capture_path, output_dir):
    """Export analysis results to four CSV reports."""

    output_dir.mkdir(parents=True, exist_ok=True)
    prefix = capture_path.stem

    protocol_rows = [
        {"protocol": protocol, "packet_count": count}
        for protocol, count in sorted(
            results["protocol_counts"].items()
        )
    ]

    communication_rows = [
        {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "packet_count": count,
        }
        for (source_ip, destination_ip), count
        in sorted(results["communications"].items())
    ]

    dns_rows = [
        {"query_name": query_name, "query_count": count}
        for query_name, count in sorted(
            results["dns_queries"].items()
        )
    ]

    finding_rows = results["findings"]

    report_paths = {
        "protocols": output_dir / f"{prefix}_protocols.csv",
        "communications": output_dir / f"{prefix}_ip_communications.csv",
        "dns": output_dir / f"{prefix}_dns_queries.csv",
        "findings": output_dir / f"{prefix}_findings.csv",
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
        report_paths["dns"],
        ["query_name", "query_count"],
        dns_rows,
    )

    write_csv(
        report_paths["findings"],
        [
            "rule",
            "severity",
            "source_ip",
            "destination_ip",
            "evidence",
            "recommendation",
        ],
        finding_rows,
    )

    return report_paths


def analyse_capture(capture_path, output_dir):
    """Load a capture, analyse it, and generate reports."""

    capture_path = Path(capture_path)

    if not capture_path.is_file():
        raise FileNotFoundError(
            f"Capture file not found: {capture_path}"
        )

    packets = rdpcap(str(capture_path))
    results = analyse_packets(packets)
    report_paths = export_reports(
        results,
        capture_path,
        Path(output_dir),
    )

    return packets, results, report_paths


def print_summary(capture_path, packets, results, report_paths):
    """Display a readable analysis summary."""

    print(f"\n{'=' * 60}")
    print(f"{PROJECT_NAME} - Network Traffic Analysis")
    print(f"{'=' * 60}")
    print(f"Capture file: {capture_path}")
    print(f"Total packets: {len(packets)}")

    print("\nProtocol Summary")
    print("-" * 40)

    for protocol, count in sorted(
        results["protocol_counts"].items()
    ):
        print(f"{protocol:<15} {count}")

    print("\nTop IP Communications")
    print("-" * 40)

    for (source_ip, destination_ip), count in (
        results["communications"].most_common(10)
    ):
        print(
            f"{source_ip} -> {destination_ip}: {count} packet(s)"
        )

    print("\nDNS Queries")
    print("-" * 40)

    if results["dns_queries"]:
        for query_name, count in sorted(
            results["dns_queries"].items()
        ):
            print(f"{query_name}: {count}")
    else:
        print("No DNS queries found.")

    print("\nFindings")
    print("-" * 40)

    if results["findings"]:
        for finding in results["findings"]:
            print(
                f"[{finding['severity'].upper()}] "
                f"{finding['rule']}: {finding['evidence']}"
            )
    else:
        print("No findings triggered by the configured rules.")

    print("\nGenerated Reports")
    print("-" * 40)

    for report_path in report_paths.values():
        print(report_path)

    print(f"\n{PROJECT_NAME} analysis completed.")


def main(argv=None):
    """Command-line entry point."""

    parser = argparse.ArgumentParser(
        description=(
            "ThreatNexus: analyse PCAP/PCAPNG network captures "
            "and generate CSV reports."
        )
    )

    parser.add_argument(
        "capture",
        help="Path to the PCAP or PCAPNG capture file.",
    )

    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for generated CSV reports (default: reports).",
    )

    args = parser.parse_args(argv)

    try:
        packets, results, report_paths = analyse_capture(
            args.capture,
            args.output_dir,
        )

        print_summary(
            args.capture,
            packets,
            results,
            report_paths,
        )

        return 0

    except FileNotFoundError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    except Exception as error:
        print(
            f"Error analysing capture: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
