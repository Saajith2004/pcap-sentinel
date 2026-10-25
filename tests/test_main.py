"""Automated tests for ThreatNexus."""

import csv
import tempfile
import unittest
from pathlib import Path

from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap

from threat_nexus.main import (
    analyse_capture,
    analyse_packets,
)


class ThreatNexusTests(unittest.TestCase):

    def test_counts_ipv4_and_udp_packets(self):
        packets = [
            Ether() / IP(
                src="192.168.1.10",
                dst="192.168.1.20",
            ) / UDP(sport=50000, dport=53),
        ]

        results = analyse_packets(packets)

        self.assertEqual(results["protocol_counts"]["IPv4"], 1)
        self.assertEqual(results["protocol_counts"]["UDP"], 1)

    def test_detects_possible_tcp_port_scan(self):
        packets = []

        for port in range(20, 32):
            packets.append(
                Ether() / IP(
                    src="192.168.1.10",
                    dst="192.168.1.20",
                ) / TCP(
                    sport=50000,
                    dport=port,
                    flags="S",
                )
            )

        results = analyse_packets(packets)

        rules = {
            finding["rule"]
            for finding in results["findings"]
        }

        self.assertIn("possible_tcp_port_scan", rules)

    def test_detects_repeated_dns_queries(self):
        packets = []

        for _ in range(10):
            packets.append(
                Ether() / IP(
                    src="192.168.1.10",
                    dst="192.168.1.1",
                ) / UDP(sport=50000, dport=53) / DNS(
                    rd=1,
                    qd=DNSQR(qname="example.org"),
                )
            )

        results = analyse_packets(packets)

        rules = {
            finding["rule"]
            for finding in results["findings"]
        }

        self.assertIn("repeated_dns_query", rules)

    def test_detects_tcp_traffic_to_port_23(self):
        packets = [
            Ether() / IP(
                src="192.168.1.10",
                dst="192.168.1.20",
            ) / TCP(sport=50000, dport=23)
        ]

        results = analyse_packets(packets)

        findings = [
            finding
            for finding in results["findings"]
            if finding["rule"] == "traffic_to_port_of_interest"
        ]

        self.assertEqual(len(findings), 1)
        self.assertIn("23", findings[0]["evidence"])

    def test_empty_capture_has_no_findings(self):
        results = analyse_packets([])

        self.assertEqual(len(results["findings"]), 0)
        self.assertEqual(len(results["communications"]), 0)
        self.assertEqual(len(results["dns_queries"]), 0)

    def test_exports_four_csv_reports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            capture = root / "test-capture.pcap"
            reports_dir = root / "reports"

            packets = [
                Ether() / IP(
                    src="192.168.1.10",
                    dst="192.168.1.20",
                ) / UDP(sport=50000, dport=53) / DNS(
                    rd=1,
                    qd=DNSQR(qname="example.org"),
                )
            ]

            wrpcap(str(capture), packets)

            _, _, report_paths = analyse_capture(
                capture,
                reports_dir,
            )

            self.assertEqual(len(report_paths), 4)

            for report_path in report_paths.values():
                self.assertTrue(report_path.is_file())

                with report_path.open(
                    newline="",
                    encoding="utf-8",
                ) as csv_file:
                    rows = list(csv.reader(csv_file))

                self.assertGreaterEqual(len(rows), 1)

    def test_extracts_dns_query(self):
        packets = [
            Ether() / IP(
                src="192.168.1.10",
                dst="192.168.1.1",
            ) / UDP(sport=50000, dport=53) / DNS(
                rd=1,
                qd=DNSQR(qname="example.org"),
            )
        ]

        results = analyse_packets(packets)

        self.assertEqual(
            results["dns_queries"]["example.org"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
