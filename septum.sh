#!/bin/bash

# Septum - Masscan + Nmap Two-Stage Segmentation Tester
# Enforces PCI-compliant scanning with safe rate limits across massive subnets.

echo "======================================"
echo "  Septum Segmentation Tester (v2.0)   "
echo "======================================"

if ! command -v masscan &> /dev/null; then
    echo "[-] Error: masscan is required for Stage 1 discovery."
    echo "[*] Please install it: sudo apt-get update && sudo apt-get install -y masscan"
    exit 1
fi

echo ""
echo "Select Mode:"
echo "1) Start a New Scan"
echo "2) Resume an Interrupted Masscan"
read -p "Choice [1/2]: " MODE

if [ "$MODE" == "2" ]; then
    echo ""
    echo "Available paused.conf files in current directory:"
    ls -1 paused.conf* 2>/dev/null || echo "No paused.conf files found."
    echo ""
    read -p "Enter the name of the paused file to resume (default: paused.conf): " RESUME_FILE
    RESUME_FILE=${RESUME_FILE:-paused.conf}
    if [ ! -f "$RESUME_FILE" ]; then
        echo "Error: File $RESUME_FILE not found."
        exit 1
    fi
    echo ""

    OUTPUT_XML=$(grep "^output-filename" "$RESUME_FILE" | cut -d= -f2 | tr -d " " | tr -d "\r")
    if [ -z "$OUTPUT_XML" ]; then
        echo "Could not determine output file from $RESUME_FILE. Using default resume_output.xml."
        OUTPUT_XML="resume_output.xml"
    fi
    OUTPUT_PREFIX="${OUTPUT_XML%.xml}"

    SOURCE_IP=$(grep "^source-ip" "$RESUME_FILE" | cut -d= -f2 | tr -d " " | tr -d "\r")
    # Capture the original IP_LIST from the masscan command line if possible, or ask
    IP_LIST=$(grep "^# masscan" "$RESUME_FILE" | grep -o "\-iL [^ ]*" | cut -d" " -f2)
    if [ -z "$IP_LIST" ]; then
        read -p "Enter the path to the target IP list file used in the original scan: " IP_LIST
    fi

    echo "Resuming masscan from $RESUME_FILE..."
    sudo masscan --resume "$RESUME_FILE"

    STAGE2=1
elif [ "$MODE" == "1" ]; then
    echo ""
    read -p "Enter a name for this test: " TEST_NAME
    if [ -z "$TEST_NAME" ]; then echo "Test name required."; exit 1; fi

    echo ""
    read -p "Enter the path to the target IP list file (ips.txt): " IP_LIST
    if [ ! -f "$IP_LIST" ]; then echo "Error: File $IP_LIST not found!"; exit 1; fi

    echo ""
    echo "Available Network Interfaces:"
    ip -br link show | awk "{print \$1, \$2}"
    echo ""

    read -p "Enter the interface to test from: " INTERFACE
    if ! ip link show "$INTERFACE" > /dev/null 2>&1; then echo "Interface error."; exit 1; fi

    SOURCE_IP=$(ip -4 addr show "$INTERFACE" | awk "/inet/ {print \$2}" | cut -d/ -f1 | head -n 1)

    echo ""
    echo "Select Port Scan Scope:"
    echo "1) Full 65,535 Ports"
    echo "2) Top 1,000 Ports"
    read -p "Choice [1/2]: " SCOPE_CHOICE
    case $SCOPE_CHOICE in
        2) PORT_ARGS="1-1024,3389,8000,8080,8443,9000" ;;
        *) PORT_ARGS="1-65535" ;;
    esac

    echo ""
    read -p "Set max packet rate (pps) [Default: 2000]: " RATE
    RATE=${RATE:-2000}

    OUTPUT_PREFIX="${TEST_NAME}_${INTERFACE}"
    OUTPUT_XML="${OUTPUT_PREFIX}.xml"

    echo ""
    read -p "Enable PCAP capture for QSA evidence? (y/n) [y]: " ENABLE_PCAP
    ENABLE_PCAP=${ENABLE_PCAP:-y}

    if [[ "$ENABLE_PCAP" =~ ^[Yy]$ ]]; then
        PCAP_FILE="${OUTPUT_PREFIX}_Evidence.pcap"
        echo "Starting tcpdump on $INTERFACE to $PCAP_FILE..."
        sudo tcpdump -i "$INTERFACE" -n -w "$PCAP_FILE" >/dev/null 2>&1 &
        TCPDUMP_PID=$!
        trap "sudo kill $TCPDUMP_PID 2>/dev/null" EXIT
    fi

    echo ""
    echo "Starting Stage 1: Masscan..."
    sudo masscan -iL "$IP_LIST" -p"$PORT_ARGS" -e "$INTERFACE" --source-ip "$SOURCE_IP" --rate "$RATE" -oX "$OUTPUT_XML"

    STAGE2=1
else
    echo "Invalid choice."; exit 1
fi

if [ "$STAGE2" == "1" ]; then
    echo "--------------------------------------"
    echo "Stage 1 Complete. Generating PCI Report..."

    FINAL_CSV="${OUTPUT_PREFIX}_PCI_Report.csv"
    echo "Source_IP,Destination_Target,Segmentation_Status,Port,Protocol,State,Reason,Service" > "$FINAL_CSV"

    # Stage 2 Orchestrator (Python)
    cat << "EOF_PY" > /tmp/septum_orchestrator.py
import sys
import xml.etree.ElementTree as ET
import ipaddress
import subprocess
import os

masscan_xml = sys.argv[1]
ip_list_file = sys.argv[2]
source_ip = sys.argv[3]
final_csv = sys.argv[4]

# 1. Parse Masscan for failures
failed_hosts = {} # ip -> [ports]
if os.path.exists(masscan_xml) and os.path.getsize(masscan_xml) > 0:
    try:
        tree = ET.parse(masscan_xml)
        root = tree.getroot()
        for host in root.findall("host"):
            addr = host.find("address").get("addr")
            ports = []
            for p in host.find("ports").findall("port"):
                if p.find("state").get("state") == "open":
                    ports.append(p.get("portid"))
            if ports:
                failed_hosts[addr] = ports
    except:
        pass

# 2. Iterate through Target List
with open(ip_list_file, "r") as f:
    targets = [line.strip() for line in f if line.strip()]

for target in targets:
    try:
        # Check if target is a range/network
        is_failed = False
        failures_in_range = []

        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            for f_ip in failed_hosts:
                if ipaddress.ip_address(f_ip) in net:
                    is_failed = True
                    failures_in_range.append(f_ip)
        else:
            if target in failed_hosts:
                is_failed = True
                failures_in_range.append(target)

        if not is_failed:
            # Segmentation Passed
            with open(final_csv, "a") as f_out:
                f_out.write(f"{source_ip},{target},Segmentation Passed,N/A,N/A,Filtered/Closed,No Response,N/A\n")
        else:
            # Segmentation Failed - Run Nmap on those IPs
            for ip in failures_in_range:
                port_list = ",".join(failed_hosts[ip])
                print(f"[*] Validating failure on {ip}...")

                nmap_xml = f"/tmp/nmap_{ip}.xml"
                subprocess.run(["sudo", "nmap", "-Pn", "-sS", "-sV", "-p", port_list, ip, "-oX", nmap_xml], capture_output=True)

                if os.path.exists(nmap_xml):
                    try:
                        n_tree = ET.parse(nmap_xml)
                        n_root = n_tree.getroot()
                        for h in n_root.findall("host"):
                            p_elem = h.find("ports")
                            if p_elem is None: continue
                            for p in p_elem.findall("port"):
                                pid = p.get("portid")
                                proto = p.get("protocol")
                                state_elem = p.find("state")
                                st = state_elem.get("state")
                                reas = state_elem.get("reason")
                                s_elem = p.find("service")
                                sv = s_elem.get("name") if s_elem is not None else "unknown"
                                with open(final_csv, "a") as f_out:
                                    f_out.write(f"{source_ip},{ip},Segmentation Failed,{pid},{proto},{st},{reas},{sv}\n")
                    except:
                        pass
                    if os.path.exists(nmap_xml): os.remove(nmap_xml)

            # Also record the original range as "Failed" for context
            if "/" in target:
                with open(final_csv, "a") as f_out:
                    f_out.write(f"{source_ip},{target},Segmentation Failed (Partial),N/A,N/A,Multiple,See IP entries,N/A\n")

    except Exception as e:
        print(f"Error processing {target}: {e}")

EOF_PY

    python3 /tmp/septum_orchestrator.py "$OUTPUT_XML" "$IP_LIST" "$SOURCE_IP" "$FINAL_CSV"
    rm -f /tmp/septum_orchestrator.py

    if [[ "$ENABLE_PCAP" =~ ^[Yy]$ ]] && [ -n "$TCPDUMP_PID" ]; then
        echo "Stopping PCAP capture..."
        sudo kill $TCPDUMP_PID 2>/dev/null
        trap - EXIT
        echo "Evidence PCAP: $PCAP_FILE"
    fi

    echo "======================================"
    echo "Septum Scan & Report Complete."
    echo "Final Report: $FINAL_CSV"
    echo "======================================"
fi
