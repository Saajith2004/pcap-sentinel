import csv
import tempfile
import unittest
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap

from pcap_sentinel.main import analyse_pcap, export_csv


class TestPcapSentinel(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.pcap_path = Path(self.temp_dir.name) / "test_capture.pcap"

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_capture(self, packets):
        wrpcap(str(self.pcap_path), packets)
        return analyse_pcap(self.pcap_path)

    def ether(self):
        return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")

    def test_counts_ipv4_and_udp_packets(self):
        packet = (
            self.ether()
            / IP(src="192.168.1.10", dst="192.168.1.1")
            / UDP(sport=50000, dport=12345)
        )
        results = self.create_capture([packet])
        self.assertEqual(results["packet_count"], 1)
        self.assertEqual(results["protocols"]["IPv4"], 1)
        self.assertEqual(results["protocols"]["UDP"], 1)

    def test_detects_tcp_traffic_to_port_23(self):
        packet = (
            self.ether()
            / IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=50000, dport=23)
        )
        results = self.create_capture([packet])
        findings = [
            item for item in results["findings"]
            if item["rule"] == "traffic_to_port_of_interest"
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "informational")
        self.assertIn("port 23", findings[0]["evidence"])

    def test_extracts_dns_query(self):
        packet = (
            self.ether()
            / IP(src="192.168.1.10", dst="192.168.1.1")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com"))
        )
        results = self.create_capture([packet])
        self.assertEqual(results["dns_queries"]["example.com"], 1)
        self.assertEqual(results["protocols"]["DNS"], 1)

    def test_detects_repeated_dns_queries(self):
        packets = [
            (
                self.ether()
                / IP(src="192.168.1.10", dst="192.168.1.1")
                / UDP(sport=53000 + index, dport=53)
                / DNS(rd=1, qd=DNSQR(qname="example.com"))
            )
            for index in range(10)
        ]
        results = self.create_capture(packets)
        self.assertEqual(results["dns_queries"]["example.com"], 10)
        findings = [
            item for item in results["findings"]
            if item["rule"] == "repeated_dns_query"
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "low")
        self.assertIn("queried 10 times: example.com", findings[0]["evidence"])

    def test_detects_possible_tcp_port_scan(self):
        packets = [
            (
                self.ether()
                / IP(src="192.168.1.10", dst="192.168.1.20")
                / TCP(sport=50000 + port, dport=port, flags="S")
            )
            for port in range(1000, 1010)
        ]
        results = self.create_capture(packets)
        findings = [
            item for item in results["findings"]
            if item["rule"] == "possible_tcp_port_scan"
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("10 distinct TCP destination ports", findings[0]["evidence"])

    def test_exports_four_csv_reports(self):
        packet = (
            self.ether()
            / IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=50000, dport=23)
        )
        results = self.create_capture([packet])
        output_dir = Path(self.temp_dir.name) / "reports"
        report_paths = export_csv(results, output_dir, "test_capture")

        self.assertEqual(len(report_paths), 4)
        self.assertTrue(all(path.is_file() for path in report_paths))
        expected_headers = [
            ["protocol", "packet_count"],
            ["source_ip", "destination_ip", "packet_count"],
            ["domain", "query_count"],
            ["rule", "severity", "source_ip", "destination_ip", "evidence", "recommendation"],
        ]
        for report_path, expected_header in zip(report_paths, expected_headers):
            with report_path.open(newline="", encoding="utf-8") as file:
                self.assertEqual(next(csv.reader(file)), expected_header)

    def test_empty_capture_has_no_findings(self):
        results = self.create_capture([])
        self.assertEqual(results["packet_count"], 0)
        self.assertEqual(results["findings"], [])
        self.assertEqual(results["protocols"], {})


if __name__ == "__main__":
    unittest.main()
