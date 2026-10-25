import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap

from threat_nexus.main import analyse_pcap, export_csv, main


class ThreatNexusTests(unittest.TestCase):

    def write_capture(self, directory, filename, packets):
        """Create a temporary PCAP file for testing."""
        path = Path(directory) / filename
        wrpcap(str(path), packets)
        return path

    def test_analyse_pcap_counts_packets_and_protocols(self):
        """Test packet counting and protocol identification."""
        packets = [
            Ether()
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / UDP(sport=12345, dport=53),

            Ether()
            / IP(src="192.0.2.2", dst="192.0.2.1")
            / TCP(sport=80, dport=50000),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            capture = self.write_capture(
                temp_dir, "basic.pcap", packets
            )
            results = analyse_pcap(capture)

        self.assertEqual(results["packet_count"], 2)
        self.assertEqual(results["protocols"]["IPv4"], 2)
        self.assertEqual(results["protocols"]["UDP"], 1)
        self.assertEqual(results["protocols"]["TCP"], 1)

        self.assertEqual(
            results["ip_pairs"][("192.0.2.1", "192.0.2.2")],
            1,
        )

    def test_extracts_dns_query(self):
        """Test DNS query extraction."""
        packets = [
            Ether()
            / IP(src="192.0.2.1", dst="192.0.2.53")
            / UDP(sport=53000, dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname="example.org"),
            )
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            capture = self.write_capture(
                temp_dir, "dns.pcap", packets
            )
            results = analyse_pcap(capture)

        self.assertEqual(
            results["dns_queries"]["example.org"],
            1,
        )
        self.assertEqual(results["protocols"]["DNS"], 1)

    def test_detects_repeated_dns_query(self):
        """Test repeated DNS query detection."""
        packets = [
            Ether()
            / IP(src="192.0.2.1", dst="192.0.2.53")
            / UDP(sport=53000 + i, dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname="repeat.example"),
            )
            for i in range(10)
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            capture = self.write_capture(
                temp_dir, "repeated_dns.pcap", packets
            )
            results = analyse_pcap(capture)

        self.assertEqual(
            results["dns_queries"]["repeat.example"],
            10,
        )

        matching = [
            finding
            for finding in results["findings"]
            if finding["rule"] == "repeated_dns_query"
        ]

        self.assertEqual(len(matching), 1)
        self.assertIn("10 times", matching[0]["evidence"])

    def test_detects_possible_tcp_port_scan(self):
        """Test detection of connections to multiple TCP ports."""
        packets = [
            Ether()
            / IP(src="192.0.2.10", dst="192.0.2.20")
            / TCP(sport=40000, dport=port)
            for port in range(20, 30)
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            capture = self.write_capture(
                temp_dir, "port_scan.pcap", packets
            )
            results = analyse_pcap(capture)

        matching = [
            finding
            for finding in results["findings"]
            if finding["rule"] == "possible_tcp_port_scan"
        ]

        self.assertEqual(len(matching), 1)
        self.assertIn("10 distinct", matching[0]["evidence"])

    def test_detects_traffic_to_port_of_interest(self):
        """Test detection of TCP traffic to Telnet port 23."""
        packets = [
            Ether()
            / IP(src="192.0.2.10", dst="192.0.2.20")
            / TCP(sport=40000, dport=23)
            for _ in range(3)
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            capture = self.write_capture(
                temp_dir, "telnet.pcap", packets
            )
            results = analyse_pcap(capture)

        matching = [
            finding
            for finding in results["findings"]
            if finding["rule"] == "traffic_to_port_of_interest"
        ]

        self.assertEqual(len(matching), 1)
        self.assertIn("3 packet(s)", matching[0]["evidence"])
        self.assertIn("port 23", matching[0]["evidence"])

    def test_exports_four_csv_reports(self):
        """Test creation of the four CSV reports."""
        packets = [
            Ether()
            / IP(src="192.0.2.1", dst="192.0.2.53")
            / UDP(sport=53000, dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname="csv-test.example"),
            )
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            capture = self.write_capture(
                temp_dir, "export_test.pcap", packets
            )

            results = analyse_pcap(capture)
            output_dir = Path(temp_dir) / "reports"

            report_paths = export_csv(
                results,
                output_dir,
                capture.stem,
            )

            self.assertEqual(len(report_paths), 4)

            for report_path in report_paths:
                self.assertTrue(Path(report_path).is_file())

            dns_report = (
                output_dir / "export_test_dns_queries.csv"
            )

            with dns_report.open(
                "r",
                newline="",
                encoding="utf-8",
            ) as file:
                rows = list(csv.DictReader(file))

            self.assertEqual(
                rows[0]["domain"],
                "csv-test.example",
            )
            self.assertEqual(rows[0]["query_count"], "1")

    def test_empty_capture_has_no_packets_or_findings(self):
        """Test handling of an empty capture."""
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = self.write_capture(
                temp_dir, "empty.pcap", []
            )
            results = analyse_pcap(capture)

        self.assertEqual(results["packet_count"], 0)
        self.assertEqual(results["protocols"], {})
        self.assertEqual(results["ip_pairs"], {})
        self.assertEqual(results["dns_queries"], {})
        self.assertEqual(results["findings"], [])

    def test_cli_missing_capture_exits_with_error(self):
        """Test CLI behaviour when the capture file is missing."""
        with patch(
            "sys.argv",
            [
                "threat-nexus",
                "missing-file-that-does-not-exist.pcap",
            ],
        ):
            with self.assertRaises(SystemExit) as error:
                main()

        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
