# Septum V2: PCI DSS Segmentation Tester

**PCI-Compliant Two-Stage Segmentation Tester (Masscan + Nmap)**

Septum is an asynchronous, high-speed network segmentation testing tool designed for PCI DSS compliance audits. It solves the problem of scanning large Enterprise environments (e.g., /16s, /21s) from isolated testing subnets (VLANs, Guest WiFi) rapidly while maintaining strict QSA evidence requirements.

## Architecture & Workflow

Septum utilizes a highly optimized Two-Stage methodology:

1.  **Stage 1: Asynchronous Sweep (Masscan)**
    - Performs an extremely fast, asynchronous sweep of targets across all 65,535 ports (or the top 1,000) using a custom TCP/IP stack.
    - Operates safely within configurable packet-per-second (pps) rate limits to avoid toppling network infrastructure.
    - Output is written to an intermediary XML file.

2.  **Stage 2: Validation & QSA Evidence (Nmap + PCAP)**
    - An embedded Python orchestrator dynamically parses the Masscan results.
    - For any target where Masscan found an open port (indicating a segmentation failure), the orchestrator automatically launches a targeted `nmap -sS -sV` scan against those specific IP/Port combinations.
    - Nmap retrieves the state, `--reason` flag, and service banner required for PCI DSS 11.4 evidence.
    - **PCAP Evidence**: Optionally runs a background `tcpdump` process bound to the testing interface. This provides undeniable cryptographic proof (raw PCAPs) to QSAs that packets were sent into the CDE and subsequently dropped (no SYN-ACK), validating the firewall rules.

## Features

- **Massive Scope Support**: Designed to scan tens of thousands of IPs without crashing.
- **Interactive Pause/Resume**: Masscan can be paused via `Ctrl+C` and safely resumed via the interactive menu using `paused.conf`.
- **PCAP Evidence Generation**: Automatically manages `tcpdump` to capture proof of segmentation isolation.
- **CSV Output**: Consolidates the results into a QSA-friendly `_PCI_Report.csv` clearly marking "Segmentation Passed" or "Segmentation Failed."

## Installation

### Prerequisites

Septum requires `masscan`, `nmap`, and `python3` to operate.

```bash
sudo apt-get update
sudo apt-get install -y masscan nmap python3 tcpdump
```

### Clone and Setup

```bash
git clone https://github.com/yourusername/Septum.git
cd Septum
chmod +x septum.sh
```

## Usage

Create a file containing your target CDE IPs or subnets (e.g., `ips.txt`). You can include individual IPs, IP ranges, or CIDR blocks.

```text
10.50.10.15
10.50.11.0/24
10.100.0.0/16
```

Execute Septum as root:

```bash
sudo ./septum.sh
```

### Interactive Example

```text
======================================
  Septum Segmentation Tester (v2.0)
======================================

Select Mode:
1) Start a New Scan
2) Resume an Interrupted Masscan
Choice [1/2]: 1

Enter a name for this test: PCI_VLAN_200_TEST

Enter the path to the target IP list file (ips.txt): /home/kali/targets.txt

Available Network Interfaces:
eth0             UP
eth0.200         UP

Enter the interface to test from: eth0.200

Select Port Scan Scope:
1) Full 65,535 Ports
2) Top 1,000 Ports
Choice [1/2]: 1

Set max packet rate (pps) [Default: 2000]: 5000

Enable PCAP capture for QSA evidence? (y/n) [y]: y
Starting tcpdump on eth0.200 to PCI_VLAN_200_TEST_eth0.200_Evidence.pcap...

Starting Stage 1: Masscan...
...
```

### Output Files

Upon completion, Septum generates two critical pieces of evidence:
1.  **`PCI_VLAN_200_TEST_eth0.200_PCI_Report.csv`**: The parsed, human-readable report.
2.  **`PCI_VLAN_200_TEST_eth0.200_Evidence.pcap`**: The raw packet capture proving the packets left the interface.
