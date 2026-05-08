# Septum V2: PCI DSS Segmentation Tester

Septum is a specialized, asynchronous network scanning wrapper designed to prove PCI DSS network segmentation (Requirement 11.4) across massive enterprise subnets (e.g., 60,000+ IPs).

## The Methodology
Septum uses a highly optimized Two-Stage approach to safely scan entire networks without causing Denial of Service (DoS) conditions on stateful firewalls:

1. **Stage 1 (Masscan):** Conducts a high-speed, asynchronous sweep across the target IP list to prove a negative (that ports are closed/filtered).
2. **Stage 2 (Nmap):** If failures are detected, Septum automatically runs surgical Nmap scans against those specific IP/Port combinations to grab Service Banners and `--reason` codes for PCI evidence.

---

## Walkthrough: Running a Scan

### 1. Prepare your Target List
Create a file named `ips.txt` containing the networks or IPs you want to test.
```text
192.168.1.0/24
10.50.10.5
172.16.0.0/16
```

### 2. Execute Septum
```bash
./septum.sh
```

### 3. Interactive Inputs
- **Test Name:** `VLAN10_to_CDE` (Used for filenames)
- **Target List:** `ips.txt`
- **Interface:** `eth1.10` (The restricted VLAN interface)
- **Port Scope:** `1` (Full 65,535 ports)
- **Packet Rate:** `2000` (Safe for enterprise firewalls)

### 4. Interactive Controls
- **[Ctrl+C]**: Pause the scan. Masscan saves progress to `paused.conf`.
- **Resume**: Run `./septum.sh` again and select **Option 2** to pick up exactly where you left off.

---

## Expected Output

### Terminal Workflow
```text
Stage 1 Complete. Generating PCI Report...
[*] Validating failure on 192.168.1.50...
======================================
Septum Scan & Report Complete.
Final Report: VLAN10_to_CDE_eth1.10_PCI_Report.csv
======================================
```

### Final Report Structure (`_PCI_Report.csv`)
The report is designed to be concise and audit-ready.

**Scenario:** You tested a `/24`, a single IP, and a `/16`. Only one IP (`192.168.1.50`) had open ports.

| Source_IP | Destination_Target | Segmentation_Status | Port | Protocol | State | Reason | Service |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 10.10.10.10 | **192.168.1.50** | **Segmentation Failed** | 22 | tcp | open | syn-ack | ssh |
| 10.10.10.10 | **192.168.1.50** | **Segmentation Failed** | 443 | tcp | open | syn-ack | https |
| 10.10.10.10 | **192.168.1.0/24** | **Segmentation Failed (Partial)** | N/A | N/A | Multiple | See IP entries | N/A |
| 10.10.10.10 | **10.50.10.5** | **Segmentation Passed** | N/A | N/A | Filtered | No Response | N/A |
| 10.10.10.10 | **172.16.0.0/16** | **Segmentation Passed** | N/A | N/A | Filtered | No Response | N/A |

**Logic Rules:**
- **Clean Pass:** If a network or IP has zero open ports, it gets one single "Segmentation Passed" row.
- **Failures:** If an IP within a network fails, each open port is listed individually.
- **Summarization:** A network containing a failed IP is marked as "Segmentation Failed (Partial)" to provide context without listing every other passing IP in that block.
