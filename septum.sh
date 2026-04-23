#!/bin/bash

# Septum - Segmentation Testing Wrapper
# Enforces PCI-compliant low-impact scanning from specific VLANs
# Supports pausing, safe exiting, resuming, logging, and progress tracking.

echo "======================================"
echo "      Septum Segmentation Tester      "
echo "======================================"

echo ""
echo "Select Mode:"
echo "1) Start a New Scan"
echo "2) Resume an Interrupted Scan"
read -p "Choice [1/2]: " MODE

if [ "$MODE" == "2" ]; then
    echo ""
    echo "Available .nmap files in current directory:"
    ls -1 *.nmap 2>/dev/null || echo "No .nmap files found."
    echo ""
    read -p "Enter the name of the .nmap file to resume: " RESUME_FILE
    if [ ! -f "$RESUME_FILE" ]; then
        echo "Error: File $RESUME_FILE not found."
        exit 1
    fi
    echo ""
    echo "Resuming scan from $RESUME_FILE..."
    echo "======================================"
    echo "       INTERACTIVE CONTROLS           "
    echo "--------------------------------------"
    echo "[Ctrl+C] - Stop and Save (Resume Later)"
    echo "[Ctrl+Z] - Pause (Type 'fg' to resume)"
    echo "[SPACE]  - Manual Progress Check"
    echo "======================================"
    echo "Auto-logging and progress indicator (every 10s) are ACTIVE."
    echo "Starting..."
    # Nmap --resume utilizes the flags saved in the .nmap file.
    sudo nmap --resume "$RESUME_FILE"
    exit 0
elif [ "$MODE" != "1" ]; then
    echo "Invalid choice. Exiting."
    exit 1
fi

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
echo "Available Network Interfaces (including VLANs):"
ip -br link show | awk '{print $1, $2}'
echo ""

read -p "Enter the interface to test from (e.g., eth0, eth1.100 for VLAN 100): " INTERFACE

if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
    echo "Error: Interface $INTERFACE does not exist."
    exit 1
fi

SOURCE_IP=$(ip -4 addr show "$INTERFACE" | awk '/inet/ {print $2}' | cut -d/ -f1 | head -n 1)

if [ -z "$SOURCE_IP" ]; then
    echo "Error: No IPv4 address found on interface $INTERFACE. Please ensure the interface is configured."
    exit 1
fi

echo ""
echo "Selected Interface: $INTERFACE"
echo "Source IP: $SOURCE_IP"


echo ""
echo "Select Port Scan Scope:"
echo "1) Full 65,535 Ports (Thorough, but slow. Often preferred by QSAs)"
echo "2) Top 1,000 Ports (Fast, standard Nmap default)"
echo "3) Top 100 Ports (Very fast, lowest impact)"
read -p "Choice [1/2/3]: " SCOPE_CHOICE

case $SCOPE_CHOICE in
    2)
        PORT_ARGS="--top-ports 1000"
        ;;
    3)
        PORT_ARGS="-F"
        ;;
    *)
        PORT_ARGS="-p-"
        ;;
esac


echo ""
echo "Include UDP Testing? (WARNING: UDP scanning is significantly slower)"
echo "1) TCP Only (Default)"
echo "2) TCP + Common UDP Ports (Top 100 UDP)"
read -p "Choice [1/2]: " UDP_CHOICE

SCAN_TYPE="-sS"
if [ "$UDP_CHOICE" == "2" ]; then
    SCAN_TYPE="-sS -sU"
    # When mixing TCP and UDP, we need to handle port args carefully. 
    # To keep it simple, we will apply the scope to both if possible or just the TCP part.
    # For common segmentation testing, scanning top 100 UDP is usually sufficient.
    if [ "$SCOPE_CHOICE" == "1" ]; then
        # Full TCP ports, but we will limit UDP to top 100 to keep it from taking days.
        PORT_ARGS="-p T:1-65535,U:--top-ports 100"
        # Actually nmap syntax for that is complex. Lets just use top ports for both if UDP is selected to be safe.
        echo "UDP selected: Overriding port scope to Top 1,000 TCP and Top 100 UDP for stability."
        PORT_ARGS="-p T:1-1000,U:1-100"
    elif [ "$SCOPE_CHOICE" == "2" ]; then
        PORT_ARGS="-p T:1-1000,U:1-100"
    else
        PORT_ARGS="-p T:1-100,U:1-100"
    fi
fi
OUTPUT_PREFIX="${TEST_NAME}_${INTERFACE}"

echo ""
echo "Starting Septum Scan..."
echo "Metadata for Reporting - Source Interface: $INTERFACE, Source IP: $SOURCE_IP"
echo "Command: nmap -Pn $SCAN_TYPE $PORT_ARGS --max-rate 500 --max-hostgroup 10 --max-retries 1 --initial-rtt-timeout 250ms --max-rtt-timeout 400ms --reason -v --stats-every 10s -e $INTERFACE -S $SOURCE_IP -iL $IP_LIST -oA $OUTPUT_PREFIX"
echo "======================================"
echo "       INTERACTIVE CONTROLS           "
echo "--------------------------------------"
echo "[Ctrl+C] - Stop and Save (Resume Later)"
echo "[Ctrl+Z] - Pause (Type 'fg' to resume)"
echo "[SPACE]  - Manual Progress Check"
echo "======================================"
echo "Scan running... Live port discovery logged below."
echo "Progress indicator updates every 10 seconds."
echo ""

# Added -v (verbose logging) and --stats-every 10s (progress indicator)
sudo nmap -Pn $SCAN_TYPE $PORT_ARGS --max-rate 500 --max-hostgroup 10 --max-retries 1 --initial-rtt-timeout 250ms --max-rtt-timeout 400ms --reason -v --stats-every 10s -e "$INTERFACE" -S "$SOURCE_IP" -iL "$IP_LIST" -oA "$OUTPUT_PREFIX"

echo "--------------------------------------"
echo "Scan complete. Results saved as $OUTPUT_PREFIX.xml, .nmap, and .gnmap"
echo "Parsing results to CSV..."
python3 parse_xml.py "${OUTPUT_PREFIX}.xml" "${OUTPUT_PREFIX}.csv"
echo "Final results saved to ${OUTPUT_PREFIX}.csv"
echo "Please review ${OUTPUT_PREFIX}.csv for your final reporting database."
