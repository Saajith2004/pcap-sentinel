# PCAP Sentinel

**PCAP Sentinel** is a Python command-line tool for inspecting PCAP/PCAPNG network captures, summarising observed traffic, and flagging simple indicators for further investigation. It is designed as a defensive cybersecurity learning and portfolio project.

> **Important:** Findings are heuristic indicators, not proof of malicious activity. Only analyse packet captures you are authorised to inspect. The tool does not replace a full packet-analysis platform or a professional incident-response process.

## Features

- Reads PCAP/PCAPNG captures through Scapy.
- Summarises total packets and observed IPv4, IPv6, TCP, UDP, ICMP, and DNS layers.
- Summarises source-to-destination IP communication.
- Extracts DNS query names.
- Flags TCP conversations involving at least 10 distinct destination ports as a **possible** port scan.
- Flags a DNS name queried at least 10 times in a capture.
- Reports traffic directed to a configurable-in-code set of ports of interest: TCP/UDP 22, 23, 445, 3389, and 4444.
- Exports four CSV reports.
- Includes automated unit tests using synthetic packets; tests do not send traffic onto a network.

## Project structure

```text
pcap-sentinel/
├── pcap_sentinel/
│   ├── __init__.py
│   └── main.py
├── samples/                 # Place authorised sample captures here
├── reports/                 # Generated CSV reports
├── tests/
│   └── test_main.py
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

## Requirements

- Python 3.10 or newer
- pip
- Scapy

## Setup

Clone your repository and enter the project directory:

```bash
git clone https://github.com/Saajith2004/pcap-sentinel.git
cd pcap-sentinel
```

Create and activate a virtual environment.

**macOS/Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows PowerShell:**

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

Install the dependency:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

Run the tool with a capture file:

```bash
python pcap_sentinel/main.py samples/example.pcap
```

Choose a different output directory:

```bash
python pcap_sentinel/main.py samples/example.pcap --output-dir reports/example-run
```

The program prints a protocol summary, IP communication summary, DNS queries, heuristic findings, and the paths of generated reports.

### Generated CSV reports

For a capture named `example.pcap`, the default output directory contains:

- `example_protocols.csv`
- `example_ip_communications.csv`
- `example_dns_queries.csv`
- `example_findings.csv`

Generated reports may contain IP addresses and queried domain names from the capture. Review them for sensitive information before sharing or committing them.

## Detection rules

| Rule | Default threshold / scope | Severity | Interpretation |
|---|---|---|---|
| `possible_tcp_port_scan` | At least 10 distinct TCP destination ports for a source/destination IP pair | Medium | May indicate scanning; legitimate tools and applications can produce similar patterns. |
| `repeated_dns_query` | At least 10 queries for the same domain in the capture | Low | May be normal retry or application behaviour; investigate context. |
| `traffic_to_port_of_interest` | Traffic to TCP/UDP ports 22, 23, 445, 3389, or 4444 | Informational | These ports can host legitimate services; a port match alone is not suspicious proof. |

Thresholds are constants near the top of `pcap_sentinel/main.py`. Adjust them to suit a documented analysis context.

## Run automated tests

From the project root with the virtual environment activated:

```bash
python -m unittest discover -s tests -v
```

The tests generate temporary PCAP files containing synthetic packets and verify packet/protocol counts, DNS extraction, the heuristic rules, and CSV report headers. They do not generate live network traffic.

## Limitations

- This is a lightweight learning tool, not a full intrusion-detection system.
- Port-based findings do not establish that a service is vulnerable or malicious.
- Repeated DNS queries are counted across the capture; the tool does not currently group them by source IP or time window.
- The port-scan heuristic counts distinct TCP destination ports per source/destination IP pair and does not distinguish all scanning patterns.
- Captures with unsupported link-layer formats may not expose decodable IP layers in Scapy.
- The program exports CSV summaries, not a complete forensic chain-of-custody report.

## Responsible use

Use only captures you own or have explicit permission to analyse. Treat captured IP addresses, DNS names, and exported reports as potentially sensitive data. Validate every alert against surrounding traffic and environmental context.

## Roadmap

Possible future improvements include source-aware DNS thresholds, time-window analysis, JSON output, configurable rule thresholds, richer IPv6 transport handling, and CI testing.

## Author

**Saajith** — cybersecurity student and developer.

Project repository: https://github.com/Saajith2004/pcap-sentinel
