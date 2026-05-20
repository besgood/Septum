# Septum

**PCI-Compliant Two-Stage Segmentation Tester (Masscan + Nmap)**

Septum is an asynchronous, high-speed network segmentation testing tool designed for PCI DSS compliance audits. It solves the problem of scanning large Enterprise environments (e.g., /16s, /21s) from isolated testing subnets (VLANs, Guest WiFi) rapidly while maintaining strict QSA evidence requirements.

## Architecture & Workflow

Septum utilizes a highly optimized Two-Stage methodology:

1.  **Stage 1: Asynchronous Sweep (Masscan)**
    - Performs an extremely fast, asynchronous sweep of targets across a configurable port scope using a custom TCP/IP stack.
    - Operates safely within packet-per-second (pps) rate limits to avoid toppling network infrastructure.
    - Output is written to an intermediary XML file.

2.  **Stage 2: Validation & QSA Evidence (Nmap + PCAP)**
    - An embedded Python orchestrator dynamically parses the Masscan results.
    - For any target where Masscan found an open port (indicating a segmentation failure), the orchestrator automatically launches a targeted `nmap -sS -sV` scan against those specific IP/Port combinations.
    - Nmap retrieves the state, `--reason` flag, and service banner required for PCI DSS 11.4 evidence.
    - **PCAP Evidence**: Optionally runs a background `tcpdump` process bound to the testing interface. This provides undeniable cryptographic proof (raw PCAPs) to QSAs that packets were sent into the CDE and subsequently dropped (no SYN-ACK), validating the firewall rules.

## New Features (v2.1)

- **Interactive Menu System**: No more manual typing for common paths. Numbered menus for mode, resume files, target lists, and network interfaces.
- **Workflow-Aware Target Lists**: Automatically scans the `targets/` directory for `.txt` files and presents them as options.
- **Granular Port Selection**:
  - Top 100, 1,000, 5,000, or 10,000 ports.
  - All 65,535 ports.
  - Custom manual port ranges.
- **Secure Processing**: Utilizes randomized, permission-locked temporary directories for backend processing to prevent symlink attacks and race conditions.
- **Massive Scope Support**: Designed to scan tens of thousands of IPs without crashing.
- **Interactive Pause/Resume**: Masscan can be paused via `Ctrl+C` and easily resumed via the interactive menu.
- **CSV Output**: Consolidates results into a QSA-friendly `_PCI_Report.csv` clearly marking "Segmentation Passed" or "Segmentation Failed."
- **Known False-Positive Filtering**: Automatically flags known firewall tarpits (e.g., tcpwrapped ports like 5060 or 2000) as "Verify Manual (Known FP)" to ensure clean, accurate evidence without omitting the data.

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
mkdir targets
chmod +x septum.sh
```

## Usage

Place your target CDE IPs or subnets (e.g., `ips.txt`) in the `targets/` folder. You can include individual IPs, IP ranges, or CIDR blocks.

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

Enter a name for this test (no spaces): PCI_VLAN_200_TEST

Available Target Lists:
1) targets/guest_wifi.txt
2) targets/internal_cde.txt
3) Enter a path manually
Select a target list [1-3]: 2

Available Network Interfaces:
1) eth0 (UP)
2) eth0.200 (UP)
Select the interface to test from [1-2]: 2

Select Port Scan Scope:
1) Top 100 Ports
2) Top 1,000 Ports
3) Top 5,000 Ports
4) Top 10,000 Ports
5) All Ports (1-65535)
6) Manually Enter Ports
Choice [1-6]: 5

Set max packet rate (pps) [Default: 2000]: 5000

Enable PCAP capture for QSA evidence? (y/n) [y]: y
Starting tcpdump on eth0.200 to PCI_VLAN_200_TEST_eth0.200_Evidence.pcap...

Starting Stage 1: Masscan...
...
```

### Output Files

Upon completion, Septum creates an isolated evidence folder (e.g., `PCI_VLAN_200_TEST_eth0.200_Evidence/`) containing all critical pieces of evidence:
1.  **`..._PCI_Report.csv`**: The parsed, human-readable PCI DSS report showing segmentation passes and failures.
2.  **`..._Evidence.pcap`**: The raw packet capture proving packets left the interface but were dropped by the firewall.
3.  **`..._nmap_<IP>.xml`**: The raw Nmap output files for any verified false positives or failures.
4.  **`...xml`**: The raw Masscan sweep evidence file.
