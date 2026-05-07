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

    echo "Resuming masscan from $RESUME_FILE..."
    echo "Output will be appended/saved to $OUTPUT_XML"

    sudo masscan --resume "$RESUME_FILE"

    STAGE2=1
elif [ "$MODE" == "1" ]; then
    echo ""
    read -p "Enter a name for this test (e.g., UserVLAN_to_CDE): " TEST_NAME
    if [ -z "$TEST_NAME" ]; then
        echo "Test name cannot be empty."
        exit 1
    fi

    echo ""
    read -p "Enter the path to the target IP list file (e.g., ips.txt): " IP_LIST
    if [ ! -f "$IP_LIST" ]; then
        echo "Error: File $IP_LIST not found!"
        exit 1
    fi

    echo ""
    echo "Available Network Interfaces:"
    ip -br link show | awk "{print \$1, \$2}"
    echo ""

    read -p "Enter the interface to test from (e.g., eth0): " INTERFACE
    if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
        echo "Error: Interface $INTERFACE does not exist."
        exit 1
    fi

    SOURCE_IP=$(ip -4 addr show "$INTERFACE" | awk "/inet/ {print \$2}" | cut -d/ -f1 | head -n 1)

    echo ""
    echo "Select Port Scan Scope:"
    echo "1) Full 65,535 Ports (Recommended for PCI Segmentation)"
    echo "2) Top 1,000 Ports"
    read -p "Choice [1/2]: " SCOPE_CHOICE

    case $SCOPE_CHOICE in
        2)
            PORT_ARGS="1-1024,3389,8000,8080,8443,9000"
            ;;
        *)
            PORT_ARGS="1-65535"
            ;;
    esac

    echo ""
    echo "Set max packet rate (pps). For enterprise firewalls, 2000-5000 is safe."
    read -p "Rate [Default: 2000]: " RATE
    RATE=${RATE:-2000}

    OUTPUT_PREFIX="${TEST_NAME}_${INTERFACE}"
    OUTPUT_XML="${OUTPUT_PREFIX}.xml"

    echo ""
    echo "======================================"
    echo "       INTERACTIVE CONTROLS           "
    echo "--------------------------------------"
    echo "[Ctrl+C] - Pause (Creates paused.conf)"
    echo "======================================"
    echo "Starting Stage 1: Masscan (Asynchronous Discovery)"
    echo "Command: masscan -iL $IP_LIST -p$PORT_ARGS -e $INTERFACE --source-ip $SOURCE_IP --rate $RATE -oX $OUTPUT_XML"

    sudo masscan -iL "$IP_LIST" -p"$PORT_ARGS" -e "$INTERFACE" --source-ip "$SOURCE_IP" --rate "$RATE" -oX "$OUTPUT_XML"

    STAGE2=1
else
    echo "Invalid choice."
    exit 1
fi

if [ "$STAGE2" == "1" ]; then
    echo "--------------------------------------"
    echo "Stage 1 Complete. Analyzing Masscan results..."

    cat << "EOF_PY" > /tmp/parse_masscan.py
import sys
import xml.etree.ElementTree as ET

if len(sys.argv) < 3:
    sys.exit(1)

xml_file = sys.argv[1]
out_file = sys.argv[2]

try:
    tree = ET.parse(xml_file)
    root = tree.getroot()
except Exception as e:
    print("Error parsing XML (might be empty): " + str(e))
    sys.exit(0)

targets = {}
for host in root.findall("host"):
    addr_elem = host.find("address")
    if addr_elem is None: continue
    ip = addr_elem.get("addr")

    ports_elem = host.find("ports")
    if ports_elem is None: continue

    for port in ports_elem.findall("port"):
        state_elem = port.find("state")
        if state_elem is not None and state_elem.get("state") == "open":
            portid = port.get("portid")
            if ip not in targets:
                targets[ip] = []
            targets[ip].append(portid)

with open(out_file, "w") as f:
    for ip, ports in targets.items():
        f.write(ip + " " + ",".join(ports) + "\n")
EOF_PY

    NMAP_TARGETS="${OUTPUT_PREFIX}_nmap_targets.txt"
    python3 /tmp/parse_masscan.py "$OUTPUT_XML" "$NMAP_TARGETS"
    rm -f /tmp/parse_masscan.py

    if [ ! -f "$NMAP_TARGETS" ] || [ ! -s "$NMAP_TARGETS" ]; then
        echo "======================================"
        echo "SUCCESS: No open ports found!"
        echo "The segmentation is intact. Proof saved in $OUTPUT_XML"
        echo "======================================"
        exit 0
    fi

    echo "WARNING: Found open ports! Moving to Stage 2: Nmap Validation..."
    echo "Running surgical Nmap scans on the specific open ports to grab PCI evidence..."

    FINAL_CSV="${OUTPUT_PREFIX}_PCI_Report.csv"
    echo "IP,Port,Protocol,State,Reason,Service" > "$FINAL_CSV"

    cat << "EOF_NMAP_PY" > /tmp/parse_nmap.py
import sys
import xml.etree.ElementTree as ET

xml_file = sys.argv[1]
csv_file = sys.argv[2]
ip = sys.argv[3]

try:
    tree = ET.parse(xml_file)
    root = tree.getroot()
except:
    sys.exit(0)

with open(csv_file, "a") as f:
    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None: continue
        for port in ports.findall("port"):
            portid = port.get("portid")
            proto = port.get("protocol")
            state_elem = port.find("state")
            state = state_elem.get("state") if state_elem is not None else ""
            reason = state_elem.get("reason") if state_elem is not None else ""
            service_elem = port.find("service")
            service = service_elem.get("name") if service_elem is not None else ""
            f.write(f"{ip},{portid},{proto},{state},{reason},{service}\n")
EOF_NMAP_PY

    TOTAL_HOSTS=$(wc -l < "$NMAP_TARGETS")
    CURRENT=0

    while read -r line; do
        CURRENT=$((CURRENT+1))
        IP=$(echo "$line" | awk "{print \$1}")
        PORT_LIST=$(echo "$line" | awk "{print \$2}")

        echo "[$CURRENT/$TOTAL_HOSTS] Validating $IP on ports $PORT_LIST..."
        sudo nmap -Pn -sS -sV -p "$PORT_LIST" "$IP" -oX "/tmp/nmap_$IP.xml" > /dev/null 2>&1

        python3 /tmp/parse_nmap.py "/tmp/nmap_$IP.xml" "$FINAL_CSV" "$IP"
        rm -f "/tmp/nmap_$IP.xml"
    done < "$NMAP_TARGETS"

    rm -f /tmp/parse_nmap.py

    echo "======================================"
    echo "Stage 2 Complete."
    echo "Detailed PCI evidence generated: $FINAL_CSV"
    echo "======================================"
fi
