# Septum V2: PCI DSS Segmentation Tester

Septum is a specialized, asynchronous network scanning wrapper designed to prove PCI DSS network segmentation (Requirement 11.4) across massive enterprise subnets (e.g., 60,000+ IPs).

## The Methodology
Septum uses a highly optimized Two-Stage approach to safely scan entire `/16` networks without causing Denial of Service (DoS) conditions on stateful firewalls:

1. **Stage 1 (Masscan):** Conducts a high-speed, asynchronous sweep across the target IP list to prove a negative (that ports are closed/filtered). It runs at a throttled, configurable rate (default 2000 pps).
2. **Stage 2 (Nmap):** If Stage 1 detects any segmentation failures (open ports), Septum dynamically extracts those specific IP/Port combinations and runs a surgical Nmap scan against them. This grabs the necessary Service Banners and `--reason` codes required for PCI evidence.

## Installation
Septum requires `masscan` and `nmap`.

```bash
sudo apt-get update && sudo apt-get install -y masscan nmap
chmod +x septum.sh
```

## Usage

### 1. Start a New Scan
```bash
./septum.sh
```
The script will interactively ask for:
- A Test Name (e.g., `UserVLAN_to_CDE`)
- A target IP list file (e.g., `ips.txt`)
- The source network interface (e.g., `eth0`)
- The Port Scope (Full 65k or Top 1,000)
- The Packet Rate

### 2. Pause and Resume
If a scan is taking too long or you need to pause testing during business hours:
- Press `Ctrl+C` while Stage 1 is running.
- Masscan will safely halt and generate a `paused.conf` file in the current directory.
- To resume exactly where you left off, run `./septum.sh` and select Option 2.

## Reporting Output
Septum automatically generates two artifacts in the current working directory:

1. **`[TestName]_[Interface].xml`**: The raw Masscan XML data for technical audit trailing.
2. **`[TestName]_[Interface]_PCI_Report.csv`**: The clean, final evidence file for QSAs.

### CSV Report Format
The final report includes the Source IP of the interface you scanned from.
- If the firewall successfully dropped all traffic, the report will explicitly state:
  `Source_IP,Segmentation Passed,N/A,N/A,Filtered/Closed,No Response,N/A`
- If the firewall failed, it will list every specific Destination IP, Port, Protocol, State, Reason, and Service discovered.
