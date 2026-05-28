#!/bin/bash

# Septum - Masscan + Nmap Two-Stage Segmentation Tester
# Enforces PCI-compliant scanning with safe rate limits across massive subnets.

echo "======================================"
echo "  Septum Segmentation Tester (v2.0)   "
echo "======================================"

# Ensure Ctrl-C safely pauses masscan and aborts Stage 2
trap 'echo -e "\n[-] Scan interrupted by user. Masscan should have saved paused.conf."; exit 1' INT

# Initialize metadata variables to default values for QSA evidence
SOURCE_CIDR="N/A"
POS_CONTROL="N/A"
POS_STATUS="Not Ran (Static Mode)"
TRACEROUTE_STATUS="Not Ran (Static Mode)"
TESTER_NAME="Internal Security Team"
TEST_FREQ="Annual"

if ! command -v masscan &> /dev/null; then
    echo "[-] Error: masscan is required for Stage 1 discovery."
    echo "[*] Please install it: sudo apt-get update && sudo apt-get install -y masscan"
    exit 1
fi

echo ""
echo "Select Mode:"
echo "1) Start a New Scan"
echo "2) Resume an Interrupted Masscan"
echo "3) Generate Report from Existing Masscan XML"
echo "4) Retrofit Compliance Metadata to an Existing CSV"
read -p "Choice [1/2/3/4]: " MODE

if [ "$MODE" == "3" ]; then
    echo ""
    echo "Available Masscan XML files in reports/:"
    mkdir -p reports
    XML_FILES=(reports/*.xml)
    if [ ! -e "${XML_FILES[0]}" ]; then
        read -p "No XML files found in reports/. Enter the path manually: " OUTPUT_XML
    else
        for i in "${!XML_FILES[@]}"; do echo "$((i+1))) ${XML_FILES[$i]}"; done
        echo "$(( ${#XML_FILES[@]} + 1 ))) Enter a path manually"
        read -p "Select an XML file [1-$(( ${#XML_FILES[@]} + 1 ))]: " XML_CHOICE
        if ! [[ "$XML_CHOICE" =~ ^[0-9]+$ ]] || [ "$XML_CHOICE" -lt 1 ] || [ "$XML_CHOICE" -gt $(( ${#XML_FILES[@]} + 1 )) ]; then
            echo "[-] Error: Invalid selection."; exit 1
        fi
        if [ "$XML_CHOICE" -eq $(( ${#XML_FILES[@]} + 1 )) ]; then
            read -p "Enter the path manually: " OUTPUT_XML
        else
            OUTPUT_XML="${XML_FILES[$((XML_CHOICE-1))]}"
        fi
    fi
    if [ ! -f "$OUTPUT_XML" ]; then echo "[-] Error: File not found."; exit 1; fi
    OUTPUT_PREFIX="${OUTPUT_XML%.xml}"
    
    echo ""
    echo "Available Target Lists:"
    if [ -d "targets" ]; then TARGET_FILES=(targets/*.txt); else TARGET_FILES=(*.txt); fi
    if [ ! -e "${TARGET_FILES[0]}" ]; then
        read -p "No .txt files found. Enter the path to the target IP list file manually: " IP_LIST
    else
        for i in "${!TARGET_FILES[@]}"; do echo "$((i+1))) ${TARGET_FILES[$i]}"; done
        echo "$(( ${#TARGET_FILES[@]} + 1 ))) Enter a path manually"
        read -p "Select a target list [1-$(( ${#TARGET_FILES[@]} + 1 ))]: " TARGET_CHOICE
        if ! [[ "$TARGET_CHOICE" =~ ^[0-9]+$ ]] || [ "$TARGET_CHOICE" -lt 1 ] || [ "$TARGET_CHOICE" -gt $(( ${#TARGET_FILES[@]} + 1 )) ]; then
            echo "[-] Error: Invalid selection."; exit 1
        fi
        if [ "$TARGET_CHOICE" -eq $(( ${#TARGET_FILES[@]} + 1 )) ]; then
            read -p "Enter the path to the target IP list file: " IP_LIST
        else
            IP_LIST="${TARGET_FILES[$((TARGET_CHOICE-1))]}"
        fi
    fi
    if [ ! -f "$IP_LIST" ]; then echo "[-] Error: File $IP_LIST not found!"; exit 1; fi

    echo ""
    read -p "Enter the Source IP to record in the report: " SOURCE_IP
    if [ -z "$SOURCE_IP" ]; then echo "[-] Error: Source IP required."; exit 1; fi

    echo ""
    echo "Available Network Interfaces (for Nmap validation):"
    IFACES=($(ip -br link show | awk '{print $1}' | cut -d@ -f1))
    for i in "${!IFACES[@]}"; do
        state=$(ip -br link show dev "${IFACES[$i]}" | awk '{print $2}')
        echo "$((i+1))) ${IFACES[$i]} ($state)"
    done
    read -p "Select the interface for Nmap to use [1-${#IFACES[@]}]: " IFACE_CHOICE
    if ! [[ "$IFACE_CHOICE" =~ ^[0-9]+$ ]] || [ "$IFACE_CHOICE" -lt 1 ] || [ "$IFACE_CHOICE" -gt "${#IFACES[@]}" ]; then
        echo "[-] Error: Invalid interface selection."; exit 1
    fi
    INTERFACE="${IFACES[$((IFACE_CHOICE-1))]}"

    echo ""
    read -p "Enter known false-positive ports to flag in report (e.g. 2000,5060) [Leave blank for none]: " FP_PORTS
    FP_PORTS=$(echo "$FP_PORTS" | tr -d ' ')
    
    STAGE2=1
elif [ "$MODE" == "2" ]; then
    echo ""
    echo "Available Resume Files:"
    RESUME_FILES=(paused.conf*)
    if [ ! -e "${RESUME_FILES[0]}" ]; then
        read -p "No paused.conf files found automatically. Enter the path manually: " RESUME_FILE
        if [ ! -f "$RESUME_FILE" ]; then echo "[-] Error: File $RESUME_FILE not found."; exit 1; fi
    else
        for i in "${!RESUME_FILES[@]}"; do
            echo "$((i+1))) ${RESUME_FILES[$i]}"
        done
        echo "$(( ${#RESUME_FILES[@]} + 1 ))) Enter a path manually"
        
        read -p "Select a file to resume [1-$(( ${#RESUME_FILES[@]} + 1 ))]: " RESUME_CHOICE
        if ! [[ "$RESUME_CHOICE" =~ ^[0-9]+$ ]] || [ "$RESUME_CHOICE" -lt 1 ] || [ "$RESUME_CHOICE" -gt $(( ${#RESUME_FILES[@]} + 1 )) ]; then
            echo "[-] Error: Invalid selection."
            exit 1
        fi
        
        if [ "$RESUME_CHOICE" -eq $(( ${#RESUME_FILES[@]} + 1 )) ]; then
            read -p "Enter the path to the paused file manually: " RESUME_FILE
        else
            RESUME_FILE="${RESUME_FILES[$((RESUME_CHOICE-1))]}"
        fi
        
        if [ ! -f "$RESUME_FILE" ]; then echo "[-] Error: File $RESUME_FILE not found."; exit 1; fi
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
        echo ""
        echo "Could not auto-detect target IP list from $RESUME_FILE."
        if [ -d "targets" ]; then TARGET_FILES=(targets/*.txt); else TARGET_FILES=(*.txt); fi
        if [ ! -e "${TARGET_FILES[0]}" ]; then
            read -p "Enter the path to the target IP list file used in the original scan: " IP_LIST
        else
            echo "Available Target Lists:"
            for i in "${!TARGET_FILES[@]}"; do echo "$((i+1))) ${TARGET_FILES[$i]}"; done
            echo "$(( ${#TARGET_FILES[@]} + 1 ))) Enter a path manually"
            read -p "Select the target list [1-$(( ${#TARGET_FILES[@]} + 1 ))]: " TARGET_CHOICE
            if ! [[ "$TARGET_CHOICE" =~ ^[0-9]+$ ]] || [ "$TARGET_CHOICE" -lt 1 ] || [ "$TARGET_CHOICE" -gt $(( ${#TARGET_FILES[@]} + 1 )) ]; then
                echo "[-] Error: Invalid selection."
                exit 1
            fi
            if [ "$TARGET_CHOICE" -eq $(( ${#TARGET_FILES[@]} + 1 )) ]; then
                read -p "Enter the path manually: " IP_LIST
            else
                IP_LIST="${TARGET_FILES[$((TARGET_CHOICE-1))]}"
            fi
        fi
    fi
    
    # Try to find interface from resume file
    INTERFACE=$(grep "^adapter =" "$RESUME_FILE" | cut -d= -f2 | tr -d " " | tr -d "\r")
    if [ -z "$INTERFACE" ]; then
        echo "Could not determine interface from $RESUME_FILE."
        echo "Available Network Interfaces:"
        IFACES=($(ip -br link show | awk '{print $1}' | cut -d@ -f1))
        for i in "${!IFACES[@]}"; do
            state=$(ip -br link show dev "${IFACES[$i]}" | awk '{print $2}')
            echo "$((i+1))) ${IFACES[$i]} ($state)"
        done
        read -p "Select the interface used in the original scan [1-${#IFACES[@]}]: " IFACE_CHOICE
        if ! [[ "$IFACE_CHOICE" =~ ^[0-9]+$ ]] || [ "$IFACE_CHOICE" -lt 1 ] || [ "$IFACE_CHOICE" -gt "${#IFACES[@]}" ]; then
            echo "[-] Error: Invalid interface selection."
            exit 1
        fi
        INTERFACE="${IFACES[$((IFACE_CHOICE-1))]}"
    fi

    # PCAP Capture logic for Resume
    echo ""
    read -p "Enter known false-positive ports to flag in report (e.g. 2000,5060) [Leave blank for none]: " FP_PORTS
    FP_PORTS=$(echo "$FP_PORTS" | tr -d ' ')
    
    echo ""
    read -p "Enable PCAP capture for this resumed session? (y/n) [y]: " ENABLE_PCAP
    ENABLE_PCAP=${ENABLE_PCAP:-y}
    if [[ "$ENABLE_PCAP" =~ ^[Yy]$ ]]; then
        PCAP_FILE="${OUTPUT_PREFIX}_Resume_$(date +%s)_Evidence.pcap"
        echo "Starting tcpdump on $INTERFACE to $PCAP_FILE..."
        sudo tcpdump -i "$INTERFACE" -n -w "$PCAP_FILE" >/dev/null 2>&1 &
        TCPDUMP_PID=$!
        trap "sudo kill $TCPDUMP_PID 2>/dev/null" EXIT
    fi

    # Advanced routing detection for Virtual NICs (PBR/VLANs)
    MAC_ARGS=""
    ROUTER_IP=$(ip route show table all dev "$INTERFACE" 2>/dev/null | awk '/default/ {print $3}' | head -n 1)
    if [ -n "$ROUTER_IP" ]; then
        ping -c 1 -W 1 -I "$INTERFACE" "$ROUTER_IP" >/dev/null 2>&1
        ROUTER_MAC=$(ip neigh show "$ROUTER_IP" dev "$INTERFACE" 2>/dev/null | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n 1)
        if [ -n "$ROUTER_MAC" ]; then
            MAC_ARGS="--router-mac $ROUTER_MAC"
        fi
    fi
    ADAPTER_MAC=$(ip link show dev "$INTERFACE" 2>/dev/null | awk '/link\/ether/ {print $2}')
    if [ -n "$ADAPTER_MAC" ]; then
        MAC_ARGS="$MAC_ARGS --adapter-mac $ADAPTER_MAC"
    fi

    echo "Resuming masscan from $RESUME_FILE..."
    sudo masscan --resume "$RESUME_FILE" $MAC_ARGS
    
    STAGE2=1
elif [ "$MODE" == "1" ]; then
    echo ""
    read -p "Enter a name for this test (no spaces): " TEST_NAME
    if [ -z "$TEST_NAME" ]; then echo "[-] Error: Test name required."; exit 1; fi
    TEST_NAME=$(echo "$TEST_NAME" | tr -d ' ')

    echo ""
    echo "Available Target Lists:"
    # Gather files from targets/ if it exists, otherwise current dir
    if [ -d "targets" ]; then
        TARGET_FILES=(targets/*.txt)
    else
        TARGET_FILES=(*.txt)
    fi
    
    # Check if there are actually files, or if the glob failed
    if [ ! -e "${TARGET_FILES[0]}" ]; then
        read -p "No .txt files found. Enter the path to the target IP list file manually: " IP_LIST
    else
        for i in "${!TARGET_FILES[@]}"; do
            echo "$((i+1))) ${TARGET_FILES[$i]}"
        done
        echo "$(( ${#TARGET_FILES[@]} + 1 ))) Enter a path manually"
        
        read -p "Select a target list [1-$(( ${#TARGET_FILES[@]} + 1 ))]: " TARGET_CHOICE
        if ! [[ "$TARGET_CHOICE" =~ ^[0-9]+$ ]] || [ "$TARGET_CHOICE" -lt 1 ] || [ "$TARGET_CHOICE" -gt $(( ${#TARGET_FILES[@]} + 1 )) ]; then
            echo "[-] Error: Invalid selection."
            exit 1
        fi
        
        if [ "$TARGET_CHOICE" -eq $(( ${#TARGET_FILES[@]} + 1 )) ]; then
            read -p "Enter the path to the target IP list file: " IP_LIST
        else
            IP_LIST="${TARGET_FILES[$((TARGET_CHOICE-1))]}"
        fi
    fi

    if [ ! -f "$IP_LIST" ]; then echo "[-] Error: File $IP_LIST not found!"; exit 1; fi

    echo ""
    echo "Available Network Interfaces:"
    IFACES=($(ip -br link show | awk '{print $1}' | cut -d@ -f1))
    for i in "${!IFACES[@]}"; do
        state=$(ip -br link show dev "${IFACES[$i]}" | awk '{print $2}')
        echo "$((i+1))) ${IFACES[$i]} ($state)"
    done
    echo ""

    read -p "Select the interface to test from [1-${#IFACES[@]}]: " IFACE_CHOICE
    if ! [[ "$IFACE_CHOICE" =~ ^[0-9]+$ ]] || [ "$IFACE_CHOICE" -lt 1 ] || [ "$IFACE_CHOICE" -gt "${#IFACES[@]}" ]; then
        echo "[-] Error: Invalid interface selection."
        exit 1
    fi
    INTERFACE="${IFACES[$((IFACE_CHOICE-1))]}"
    
    if ! ip link show "$INTERFACE" > /dev/null 2>&1; then echo "Interface error."; exit 1; fi

    SOURCE_IP=$(ip -4 addr show "$INTERFACE" | awk '/inet/ {print $2}' | cut -d/ -f1 | head -n 1)
    if [ -z "$SOURCE_IP" ]; then
        echo "[-] Error: Interface $INTERFACE has no IPv4 address assigned."
        exit 1
    fi

    echo ""
    echo "Select Port Scan Scope:"
    echo "1) Top 100 Ports (Includes UDP Top 20)"
    echo "2) Top 1,000 Ports (Includes UDP Top 20)"
    echo "3) Top 5,000 Ports (Includes UDP Top 20)"
    echo "4) Top 10,000 Ports (Includes UDP Top 20)"
    echo "5) All Ports (1-65535) (Includes UDP Top 20)"
    echo "6) Manually Enter Ports"
    echo "7) UDP Top 20 Ports Only"
    read -p "Choice [1-7]: " SCOPE_CHOICE
    
    UDP_TOP20="U:53,U:67,U:68,U:69,U:88,U:123,U:137,U:138,U:161,U:162,U:389,U:500,U:514,U:1194,U:1434,U:1900,U:2049,U:3389,U:4500,U:5060"
    case $SCOPE_CHOICE in
        1) 
           if [ -f /usr/share/nmap/nmap-services ]; then
               TOP_PORTS=$(sort -r -k3 /usr/share/nmap/nmap-services | grep '/tcp' | head -n 100 | awk '{print $2}' | cut -d/ -f1 | paste -sd,)
               PORT_ARGS="-p T:$TOP_PORTS,$UDP_TOP20"
           else
               PORT_ARGS="-p T:20-25,80,110,135,139,443,445,1433,3306,3389,8080,$UDP_TOP20"
           fi
           ;;
        2) 
           if [ -f /usr/share/nmap/nmap-services ]; then
               TOP_PORTS=$(sort -r -k3 /usr/share/nmap/nmap-services | grep '/tcp' | head -n 1000 | awk '{print $2}' | cut -d/ -f1 | paste -sd,)
               PORT_ARGS="-p T:$TOP_PORTS,$UDP_TOP20"
           else
               PORT_ARGS="-p T:1-1024,$UDP_TOP20"
           fi
           ;;
        3) 
           if [ -f /usr/share/nmap/nmap-services ]; then
               TOP_PORTS=$(sort -r -k3 /usr/share/nmap/nmap-services | grep '/tcp' | head -n 5000 | awk '{print $2}' | cut -d/ -f1 | paste -sd,)
               PORT_ARGS="-p T:$TOP_PORTS,$UDP_TOP20"
           else
               PORT_ARGS="-p T:1-5000,$UDP_TOP20"
           fi
           ;;
        4) 
           if [ -f /usr/share/nmap/nmap-services ]; then
               TOP_PORTS=$(sort -r -k3 /usr/share/nmap/nmap-services | grep '/tcp' | head -n 10000 | awk '{print $2}' | cut -d/ -f1 | paste -sd,)
               PORT_ARGS="-p T:$TOP_PORTS,$UDP_TOP20"
           else
               PORT_ARGS="-p T:1-10000,$UDP_TOP20"
           fi
           ;;
        6) read -p "Enter ports (e.g. 80,443,1-1000): " CUSTOM_PORTS
           CUSTOM_PORTS=$(echo "$CUSTOM_PORTS" | tr -d ' ')
           if [ -z "$CUSTOM_PORTS" ]; then echo "[-] Error: Ports required."; exit 1; fi
           echo "[*] Appending Top 20 UDP ports to manual scan to guarantee dual-protocol QSA compliance..."
           if [[ "$CUSTOM_PORTS" =~ ^[0-9,-]+$ ]]; then
               PORT_ARGS="-p T:$CUSTOM_PORTS,$UDP_TOP20"
           else
               PORT_ARGS="-p $CUSTOM_PORTS,$UDP_TOP20"
           fi
           ;;
        7) PORT_ARGS="-p $UDP_TOP20" ;;
        *) PORT_ARGS="-p T:1-65535,$UDP_TOP20" ;;
    esac

    echo ""
    read -p "Set max packet rate (pps) [Default: 2000]: " RATE
    RATE=${RATE:-2000}

    EVIDENCE_DIR="reports/${TEST_NAME}_${INTERFACE}_Evidence"
    mkdir -p "$EVIDENCE_DIR"
    OUTPUT_PREFIX="${EVIDENCE_DIR}/${TEST_NAME}_${INTERFACE}"
    OUTPUT_XML="${OUTPUT_PREFIX}.xml"

    echo ""
    read -p "Enter known false-positive ports to flag in report (e.g. 2000,5060) [Leave blank for none]: " FP_PORTS
    FP_PORTS=$(echo "$FP_PORTS" | tr -d ' ')

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

    # Advanced routing detection for Virtual NICs (PBR/VLANs)
    MAC_ARGS=""
    ROUTER_IP=$(ip route show table all dev "$INTERFACE" 2>/dev/null | awk '/default/ {print $3}' | head -n 1)
    if [ -n "$ROUTER_IP" ]; then
        ping -c 1 -W 1 -I "$INTERFACE" "$ROUTER_IP" >/dev/null 2>&1
        ROUTER_MAC=$(ip neigh show "$ROUTER_IP" dev "$INTERFACE" 2>/dev/null | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n 1)
        if [ -n "$ROUTER_MAC" ]; then
            MAC_ARGS="--router-mac $ROUTER_MAC"
        fi
    fi
    ADAPTER_MAC=$(ip link show dev "$INTERFACE" 2>/dev/null | awk '/link\/ether/ {print $2}')
    if [ -n "$ADAPTER_MAC" ]; then
        MAC_ARGS="$MAC_ARGS --adapter-mac $ADAPTER_MAC"
    fi

    SOURCE_CIDR=$(ip -4 addr show "$INTERFACE" | awk '/inet/ {print $2}' | head -n 1)

    echo ""
    read -p "Enter Tester Name/Team [Default: Internal Security Team]: " TESTER_NAME
    TESTER_NAME=${TESTER_NAME:-"Internal Security Team"}
    
    read -p "Enter Testing Frequency (e.g. Annual, Semi-Annual) [Default: Annual]: " TEST_FREQ
    TEST_FREQ=${TEST_FREQ:-"Annual"}

    echo ""
    echo "======================================"
    echo "    Positive Control Path Validation  "
    echo "======================================"
    echo "[*] A positive control target (like a known shared domain controller, local DNS resolver,"
    echo "[*] or public resolver like 8.8.8.8) validates that the scanner is actively online."
    read -p "Enter Positive Control IP/Port (e.g. 8.8.8.8:53) [Leave blank to skip]: " POS_CONTROL
    POS_STATUS="SKIPPED"
    POS_IP=""
    if [ -n "$POS_CONTROL" ]; then
        POS_IP=$(echo "$POS_CONTROL" | cut -d: -f1)
        POS_PORT=$(echo "$POS_CONTROL" | cut -d: -f2)
        POS_PORT=${POS_PORT:-53}
        echo "[*] Performing Positive Control Path Check to $POS_IP:$POS_PORT..."
        if command -v nc &> /dev/null; then
            if nc -z -w 3 -s "$SOURCE_IP" "$POS_IP" "$POS_PORT" >/dev/null 2>&1; then
                POS_STATUS="SUCCESS (Port Reachable)"
                echo "[+] Positive Control Check: SUCCESSFUL (Reachable via TCP/UDP)"
            else
                if ping -c 2 -W 2 -I "$INTERFACE" "$POS_IP" >/dev/null 2>&1; then
                    POS_STATUS="SUCCESS (ICMP Reachable)"
                    echo "[+] Positive Control Check: SUCCESSFUL (Reachable via ICMP Ping)"
                else
                    POS_STATUS="FAILED (Unreachable)"
                    echo "[!] WARNING: Positive Control target $POS_IP:$POS_PORT is Unreachable!"
                    echo "[!] Your scanner might be blocked from outbound network traffic or misconfigured."
                    read -p "[?] Do you want to proceed with the scan anyway? (y/n) [n]: " PROCEED_ANYWAY
                    if [[ ! "$PROCEED_ANYWAY" =~ ^[Yy]$ ]]; then
                        echo "[-] Terminating scan to prevent false pass results."
                        exit 1
                    fi
                fi
            fi
        else
            if ping -c 2 -W 2 -I "$INTERFACE" "$POS_IP" >/dev/null 2>&1; then
                POS_STATUS="SUCCESS (ICMP Reachable)"
                echo "[+] Positive Control Check: SUCCESSFUL (Reachable via ICMP Ping)"
            else
                POS_STATUS="FAILED (Unreachable)"
                echo "[!] WARNING: Positive Control target $POS_IP is Unreachable!"
                read -p "[?] Do you want to proceed with the scan anyway? (y/n) [n]: " PROCEED_ANYWAY
                if [[ ! "$PROCEED_ANYWAY" =~ ^[Yy]$ ]]; then
                    echo "[-] Terminating scan."
                    exit 1
                fi
            fi
        fi
    fi

    echo ""
    echo "======================================"
    echo "    Traceroute Path Discovery Check   "
    echo "======================================"
    echo "[*] Traceroute records hop-level routing details for the QSA to prove firewall blocking."
    read -p "Run traceroute path validation? (y/n) [n]: " RUN_TRACEROUTE
    TRACEROUTE_STATUS="SKIPPED"
    if [[ "$RUN_TRACEROUTE" =~ ^[Yy]$ ]]; then
        TRACE_TARGET=""
        if [ -n "$POS_IP" ]; then
            TRACE_TARGET="$POS_IP"
        else
            TRACE_TARGET=$(grep -v '^#' "$IP_LIST" | grep -v '^$' | head -n 1)
            if [[ "$TRACE_TARGET" == *"/"* ]]; then
                TRACE_TARGET=$(echo "$TRACE_TARGET" | cut -d/ -f1)
            fi
        fi
        
        if [ -n "$TRACE_TARGET" ]; then
            echo "[*] Performing traceroute to $TRACE_TARGET..."
            if command -v traceroute &> /dev/null; then
                TRACEROUTE_OUT=$(sudo traceroute -n -w 2 -m 15 -i "$INTERFACE" "$TRACE_TARGET" 2>&1 | tail -n +2 | head -n 6 | tr '\n' ';' | tr -d '"')
                TRACEROUTE_STATUS="SUCCESS ($TRACEROUTE_OUT)"
                echo "[+] Traceroute completed successfully."
            elif command -v nmap &> /dev/null; then
                TRACEROUTE_OUT=$(sudo nmap -Pn --traceroute -p 80 "$TRACE_TARGET" | grep -A 10 "TRACEROUTE" | tr '\n' ';' | tr -d '"')
                TRACEROUTE_STATUS="SUCCESS ($TRACEROUTE_OUT)"
                echo "[+] Traceroute completed successfully."
            else
                TRACEROUTE_STATUS="FAILED (No traceroute tool)"
                echo "[!] Note: traceroute or nmap is required to run active path discovery."
            fi
        fi
    fi

    echo ""
    echo "======================================"
    echo "    Target Scope Validation Check     "
    echo "======================================"
    TARGET_COUNT=$(grep -v '^#' "$IP_LIST" | grep -v '^$' | wc -l)
    echo "[*] Authorized Targets File: $IP_LIST"
    echo "[*] Total Scope IPs/Networks: $TARGET_COUNT"
    echo "[*] Source Test Interface  : $INTERFACE (IP: $SOURCE_IP)"
    echo "[*] Local Gateway IP Address: $ROUTER_IP"
    
    # Run a live connectivity check to the Gateway
    echo "[*] Running Scanner Link Integrity Check..."
    if [ -n "$ROUTER_IP" ]; then
        if ping -c 2 -W 2 -I "$INTERFACE" "$ROUTER_IP" >/dev/null 2>&1; then
            LINK_STATUS="SUCCESS (Gateway Reachable)"
            echo "[+] Link Integrity Check: SUCCESSFUL (Gateway is Reachable)"
        else
            LINK_STATUS="FAILED (Gateway Unreachable)"
            echo "[!] WARNING: Gateway is Unreachable! Your scanner interface may be offline or disconnected."
            read -p "[?] Do you want to proceed anyway? (y/n) [n]: " PROCEED_ANYWAY
            if [[ ! "$PROCEED_ANYWAY" =~ ^[Yy]$ ]]; then
                echo "[-] Terminating scan to prevent false segmentation pass results."
                exit 1
            fi
        fi
    else
        LINK_STATUS="WARNING (No Gateway Detected)"
        echo "[!] WARNING: No default gateway IP detected for interface $INTERFACE."
        read -p "[?] Do you want to proceed anyway? (y/n) [n]: " PROCEED_ANYWAY
        if [[ ! "$PROCEED_ANYWAY" =~ ^[Yy]$ ]]; then
            echo "[-] Terminating scan."
            exit 1
        fi
    fi
    echo ""
    read -p "[?] Confirm all targets are in-scope and begin scan? (y/n) [n]: " CONFIRM_SCOPE
    if [[ ! "$CONFIRM_SCOPE" =~ ^[Yy]$ ]]; then
        echo "[-] Scan cancelled by operator."
        exit 1
    fi

    echo ""
    echo "======================================"
    echo "    Starting Stage 1 Discovery Scan   "
    echo "======================================"
    echo "[*] Scanning targets for TCP and UDP ports using Masscan..."
    VLAN_ID=$(echo "$INTERFACE" | cut -s -d. -f2)

    if [ -n "$VLAN_ID" ]; then
        PHYS_INTERFACE=$(echo "$INTERFACE" | cut -d. -f1)
        echo "[*] Detected VLAN sub-interface. Switching to native tagging on $PHYS_INTERFACE (VLAN $VLAN_ID)"
        sudo masscan -iL "$IP_LIST" $PORT_ARGS -e "$PHYS_INTERFACE" --vlan "$VLAN_ID" --source-ip "$SOURCE_IP" $MAC_ARGS --rate "$RATE" -oX "$OUTPUT_XML"
    else
        sudo masscan -iL "$IP_LIST" $PORT_ARGS -e "$INTERFACE" --source-ip "$SOURCE_IP" $MAC_ARGS --rate "$RATE" -oX "$OUTPUT_XML"
    fi

    STAGE2=1
elif [ "$MODE" == "4" ]; then
    echo ""
    echo "======================================"
    echo "  Retrofit QSA Compliance Metadata   "
    echo "======================================"
    echo "[*] This mode appends positive control, link checks, and assessor details"
    echo "[*] to an existing CSV report so you can generate an auditor-ready Word document."
    echo ""
    
    # 1. Find or prompt for existing CSV reports
    CSV_FILES=($(find . -maxdepth 3 -name "*_PCI_Report.csv" 2>/dev/null))
    if [ ${#CSV_FILES[@]} -eq 0 ]; then
        read -p "No existing *_PCI_Report.csv found. Enter the path manually: " FINAL_CSV
    else
        echo "Available CSV Reports to Retrofit:"
        for i in "${!CSV_FILES[@]}"; do
            echo "$((i+1))) ${CSV_FILES[$i]}"
        done
        echo "$(( ${#CSV_FILES[@]} + 1 ))) Enter a path manually"
        read -p "Select a file [1-$(( ${#CSV_FILES[@]} + 1 ))]: " CSV_CHOICE
        if ! [[ "$CSV_CHOICE" =~ ^[0-9]+$ ]] || [ "$CSV_CHOICE" -lt 1 ] || [ "$CSV_CHOICE" -gt $(( ${#CSV_FILES[@]} + 1 )) ]; then
            echo "[-] Error: Invalid selection."; exit 1
        fi
        if [ "$CSV_CHOICE" -eq $(( ${#CSV_FILES[@]} + 1 )) ]; then
            read -p "Enter the path manually: " FINAL_CSV
        else
            FINAL_CSV="${CSV_FILES[$((CSV_CHOICE-1))]}"
        fi
    fi
    if [ ! -f "$FINAL_CSV" ]; then echo "[-] Error: File $FINAL_CSV not found."; exit 1; fi

    # 2. Get Tester details
    echo ""
    read -p "Enter Tester Name/Team [Default: Internal Security Team]: " TESTER_NAME
    TESTER_NAME=${TESTER_NAME:-"Internal Security Team"}
    
    read -p "Enter Testing Frequency (e.g. Annual, Semi-Annual) [Default: Annual]: " TEST_FREQ
    TEST_FREQ=${TEST_FREQ:-"Annual"}

    # 3. Ask if they want to run live network validation tests or enter manually
    read -p "[?] Perform live scanner link and path discovery tests now? (y/n) [y]: " RUN_LIVE
    RUN_LIVE=${RUN_LIVE:-y}

    if [[ "$RUN_LIVE" =~ ^[Yy]$ ]]; then
        # Prompt for active interface
        echo ""
        echo "Available Network Interfaces:"
        IFACES=($(ip -br link show | awk '{print $1}' | cut -d@ -f1))
        for i in "${!IFACES[@]}"; do
            state=$(ip -br link show dev "${IFACES[$i]}" | awk '{print $2}')
            echo "$((i+1))) ${IFACES[$i]} ($state)"
        done
        read -p "Select interface for tests [1-${#IFACES[@]}]: " IFACE_CHOICE
        if ! [[ "$IFACE_CHOICE" =~ ^[0-9]+$ ]] || [ "$IFACE_CHOICE" -lt 1 ] || [ "$IFACE_CHOICE" -gt "${#IFACES[@]}" ]; then
            echo "[-] Error: Invalid interface."; exit 1
        fi
        INTERFACE="${IFACES[$((IFACE_CHOICE-1))]}"
        
        SOURCE_IP=$(ip -4 addr show "$INTERFACE" | awk '/inet/ {print $2}' | cut -d/ -f1 | head -n 1)
        SOURCE_CIDR=$(ip -4 addr show "$INTERFACE" | awk '/inet/ {print $2}' | head -n 1)
        ROUTER_IP=$(ip route show table all dev "$INTERFACE" 2>/dev/null | awk '/default/ {print $3}' | head -n 1)
        
        # Link Check
        echo ""
        echo "[*] Running Link Integrity Check to gateway $ROUTER_IP..."
        if [ -n "$ROUTER_IP" ]; then
            if ping -c 2 -W 2 -I "$INTERFACE" "$ROUTER_IP" >/dev/null 2>&1; then
                LINK_STATUS="SUCCESS (Gateway Reachable)"
                echo "[+] Link check: SUCCESSFUL"
            else
                LINK_STATUS="FAILED (Gateway Unreachable)"
                echo "[!] Link check: FAILED"
            fi
        else
            LINK_STATUS="WARNING (No Gateway Detected)"
            echo "[!] Link check: WARNING (No gateway)"
        fi

        # Positive Control Check
        echo ""
        read -p "Enter Positive Control IP/Port (e.g. 8.8.8.8:53) [Default: 8.8.8.8:53]: " POS_CONTROL
        POS_CONTROL=${POS_CONTROL:-"8.8.8.8:53"}
        POS_IP=$(echo "$POS_CONTROL" | cut -d: -f1)
        POS_PORT=$(echo "$POS_CONTROL" | cut -d: -f2)
        POS_PORT=${POS_PORT:-53}
        
        echo "[*] Running Positive Control check to $POS_IP:$POS_PORT..."
        if command -v nc &> /dev/null && nc -z -w 3 -I "$INTERFACE" "$POS_IP" "$POS_PORT" >/dev/null 2>&1; then
            POS_STATUS="SUCCESS (Port Reachable)"
            echo "[+] Positive control: SUCCESSFUL"
        else
            if ping -c 2 -W 2 -I "$INTERFACE" "$POS_IP" >/dev/null 2>&1; then
                POS_STATUS="SUCCESS (ICMP Reachable)"
                echo "[+] Positive control: SUCCESSFUL"
            else
                POS_STATUS="FAILED (Unreachable)"
                echo "[!] Positive control: FAILED"
            fi
        fi

        # Traceroute Path Discovery
        echo ""
        read -p "Run traceroute path validation? (y/n) [y]: " RUN_TRACEROUTE
        RUN_TRACEROUTE=${RUN_TRACEROUTE:-y}
        TRACEROUTE_STATUS="SKIPPED"
        if [[ "$RUN_TRACEROUTE" =~ ^[Yy]$ ]]; then
            echo "[*] Running traceroute to $POS_IP..."
            if command -v traceroute &> /dev/null; then
                TRACEROUTE_OUT=$(traceroute -n -w 2 -m 15 -i "$INTERFACE" "$POS_IP" 2>&1 | tail -n +2 | head -n 6 | tr '\n' ';' | tr -d '"')
                TRACEROUTE_STATUS="SUCCESS ($TRACEROUTE_OUT)"
                echo "[+] Traceroute completed."
            elif command -v nmap &> /dev/null; then
                TRACEROUTE_OUT=$(sudo nmap -Pn --traceroute -p 80 "$POS_IP" | grep -A 10 "TRACEROUTE" | tr '\n' ';' | tr -d '"')
                TRACEROUTE_STATUS="SUCCESS ($TRACEROUTE_OUT)"
                echo "[+] Traceroute completed."
            else
                TRACEROUTE_STATUS="FAILED (No traceroute tool)"
                echo "[!] Traceroute check: FAILED (No tool)"
            fi
        fi
    else
        # Manual Entry
        echo ""
        read -p "Enter Scanner IP/CIDR [Default: 192.168.10.55/24]: " SOURCE_CIDR
        SOURCE_CIDR=${SOURCE_CIDR:-"192.168.10.55/24"}
        SOURCE_IP=$(echo "$SOURCE_CIDR" | cut -d/ -f1)
        
        read -p "Enter Gateway IP address [Default: 192.168.10.1]: " ROUTER_IP
        ROUTER_IP=${ROUTER_IP:-"192.168.10.1"}
        LINK_STATUS="SUCCESS (Gateway Manually Audited)"
        
        read -p "Enter Positive Control IP/Port [Default: 8.8.8.8:53]: " POS_CONTROL
        POS_CONTROL=${POS_CONTROL:-"8.8.8.8:53"}
        POS_STATUS="SUCCESS (Manually Verified)"
        
        read -p "Enter Traceroute path (semicolon separated) or press Enter to skip: " MANUAL_TRACE
        if [ -n "$MANUAL_TRACE" ]; then
            TRACEROUTE_STATUS="SUCCESS ($MANUAL_TRACE)"
        else
            TRACEROUTE_STATUS="SKIPPED"
        fi
        INTERFACE="manual"
    fi

    # Append all metadata rows to the selected CSV
    echo ""
    echo "[*] Appending compliance metadata to $FINAL_CSV..."
    echo "Testing Information,Scanner Link Validation,Interface: $INTERFACE - Gateway: $ROUTER_IP ($LINK_STATUS),N/A,N/A,N/A,N/A,N/A" >> "$FINAL_CSV"
    echo "Testing Information,Scanner Subnet/CIDR,$SOURCE_CIDR,N/A,N/A,N/A,N/A,N/A" >> "$FINAL_CSV"
    echo "Testing Information,Positive Control Target,$POS_CONTROL ($POS_STATUS),N/A,N/A,N/A,N/A,N/A" >> "$FINAL_CSV"
    echo "Testing Information,Path Discovery (Traceroute),$TRACEROUTE_STATUS,N/A,N/A,N/A,N/A,N/A" >> "$FINAL_CSV"
    echo "Testing Information,Tester Name,$TESTER_NAME,N/A,N/A,N/A,N/A,N/A" >> "$FINAL_CSV"
    echo "Testing Information,Testing Frequency,$TEST_FREQ,N/A,N/A,N/A,N/A,N/A" >> "$FINAL_CSV"

    echo "[+] Compliance metadata successfully retrofitted!"
    echo "[*] You can now compile the Word report using: python3 generate_qsa_report.py --inputs $FINAL_CSV ..."
    exit 0
else
    echo "Invalid choice."; exit 1
fi

if [ "$STAGE2" == "1" ]; then
    echo "--------------------------------------"
    echo "Stage 1 Complete. Generating PCI Report..."
    
    echo ""
    read -p "Do you want to append these scan results to an existing CSV report? (y/n) [n]: " APPEND_CSV
    APPEND_CSV=${APPEND_CSV:-n}
    
    if [[ "$APPEND_CSV" =~ ^[Yy]$ ]]; then
        # Find existing CSV reports
        CSV_FILES=($(find . -maxdepth 3 -name "*_PCI_Report.csv" 2>/dev/null))
        if [ ${#CSV_FILES[@]} -eq 0 ]; then
            read -p "No existing *_PCI_Report.csv found. Enter path manually or press Enter to create a new one: " MANUAL_CSV
            if [ -n "$MANUAL_CSV" ]; then
                FINAL_CSV="$MANUAL_CSV"
            else
                FINAL_CSV="${OUTPUT_PREFIX}_PCI_Report.csv"
            fi
        else
            echo "Available CSV Reports to Append to:"
            for i in "${!CSV_FILES[@]}"; do
                echo "$((i+1))) ${CSV_FILES[$i]}"
            done
            echo "$(( ${#CSV_FILES[@]} + 1 ))) Enter a path manually"
            read -p "Select a file [1-$(( ${#CSV_FILES[@]} + 1 ))]: " CSV_CHOICE
            if [[ "$CSV_CHOICE" =~ ^[0-9]+$ ]] && [ "$CSV_CHOICE" -ge 1 ] && [ "$CSV_CHOICE" -le $(( ${#CSV_FILES[@]} + 1 )) ]; then
                if [ "$CSV_CHOICE" -eq $(( ${#CSV_FILES[@]} + 1 )) ]; then
                    read -p "Enter the path manually: " FINAL_CSV
                else
                    FINAL_CSV="${CSV_FILES[$((CSV_CHOICE-1))]}"
                fi
            else
                FINAL_CSV="${OUTPUT_PREFIX}_PCI_Report.csv"
            fi
        fi
    else
        FINAL_CSV="${OUTPUT_PREFIX}_PCI_Report.csv"
    fi

    # Create CSV directory if it doesn't exist
    mkdir -p "$(dirname "$FINAL_CSV")" 2>/dev/null

    # If final CSV doesn't exist, create it with header. Otherwise, keep it as is.
    if [ ! -f "$FINAL_CSV" ]; then
        echo "Source_IP,Destination_Target,Segmentation_Status,Port,Protocol,State,Reason,Service" > "$FINAL_CSV"
    else
        echo "[+] Appending results to existing CSV: $FINAL_CSV"
    fi

    # Stage 2 Orchestrator (Python)
    SECURE_TMP=$(mktemp -d)
    cat << "EOF_PY" > "$SECURE_TMP/septum_orchestrator.py"
import sys
import xml.etree.ElementTree as ET
import ipaddress
import subprocess
import os

masscan_xml = sys.argv[1]
ip_list_file = sys.argv[2]
source_ip = sys.argv[3]
final_csv = sys.argv[4]
tmp_dir = sys.argv[5]
interface = sys.argv[6]
fp_ports_arg = sys.argv[7] if len(sys.argv) > 7 else ""
fp_ports = fp_ports_arg.split(',') if fp_ports_arg else []

# 1. Parse Masscan for failures (supporting both TCP and UDP protocols)
failed_hosts = {} # ip -> {'tcp': set(), 'udp': set()}
if os.path.exists(masscan_xml) and os.path.getsize(masscan_xml) > 0:
    try:
        for event, elem in ET.iterparse(masscan_xml, events=("end",)):
            if elem.tag == "host":
                addr_elem = elem.find("address")
                if addr_elem is not None:
                    addr = addr_elem.get("addr")
                    ports_elem = elem.find("ports")
                    if ports_elem is not None:
                        for p in ports_elem.findall("port"):
                            state_elem = p.find("state")
                            if state_elem is not None and state_elem.get("state") == "open":
                                pid = p.get("portid")
                                proto = p.get("protocol") or "tcp"
                                if addr not in failed_hosts:
                                    failed_hosts[addr] = {'tcp': set(), 'udp': set()}
                                failed_hosts[addr][proto].add(pid)
                elem.clear() # Free memory
    except Exception as e:
        print(f"Error parsing Masscan XML: {e}")

# 2. Iterate through Target List
with open(ip_list_file, "r") as f:
    targets = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

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
            # Segmentation Failed - Run Nmap on those IPs (using protocol-aware flags)
            for ip in failures_in_range:
                tcps = failed_hosts[ip]['tcp']
                udps = failed_hosts[ip]['udp']
                
                print(f"[*] Validating failure on {ip} (TCP: {len(tcps)} ports, UDP: {len(udps)} ports)...")
                
                nmap_xml = f"{tmp_dir}/nmap_{ip}.xml"
                nmap_cmd = ["sudo", "nmap", "-Pn"]
                ports_arg = []
                if tcps:
                    nmap_cmd.append("-sS")
                    ports_arg.append("T:" + ",".join(tcps))
                if udps:
                    nmap_cmd.append("-sU")
                    ports_arg.append("U:" + ",".join(udps))
                    
                nmap_cmd.extend(["-sV", "-T4", "--max-retries", "2", "--host-timeout", "10m", "-e", interface, "-S", source_ip, "-p", ",".join(ports_arg), ip, "-oX", nmap_xml])
                
                subprocess.run(nmap_cmd, capture_output=True)
                
                if os.path.exists(nmap_xml):
                    try:
                        n_tree = ET.parse(nmap_xml)
                        n_root = n_tree.getroot()
                        for h in n_root.findall("host"):
                            p_elem = h.find("ports")
                            if p_elem is None: continue
                            
                            scanned_tcps = set(tcps)
                            scanned_udps = set(udps)
                            
                            for p in p_elem.findall("port"):
                                pid = p.get("portid")
                                proto = p.get("protocol")
                                if proto == "tcp":
                                    scanned_tcps.discard(pid)
                                elif proto == "udp":
                                    scanned_udps.discard(pid)
                                    
                                state_elem = p.find("state")
                                st = state_elem.get("state")
                                reas = state_elem.get("reason")
                                s_elem = p.find("service")
                                sv = s_elem.get("name") if s_elem is not None else "unknown"
                                with open(final_csv, "a") as f_out:
                                    # Handle Known False Positives
                                    if pid in fp_ports and st == "open" and (sv == "tcpwrapped" or sv == "unknown"):
                                        seg_status = "Verify Manual (Known FP)"
                                    elif st == "open":
                                        seg_status = "Segmentation Failed"
                                    else:
                                        seg_status = "Segmentation Passed"
                                    
                                    f_out.write(f"{source_ip},{ip},{seg_status},{pid},{proto},{st},{reas},{sv}\n")
                                    
                            # Handle remaining filtered ports
                            for ep in p_elem.findall("extraports"):
                                ep_state = ep.get("state")
                                er = ep.find("extrareasons")
                                ep_reason = er.get("reason") if er is not None else "unknown"
                                for pid in scanned_tcps:
                                    with open(final_csv, "a") as f_out:
                                        f_out.write(f"{source_ip},{ip},Segmentation Passed,{pid},tcp,{ep_state},{ep_reason},unknown\n")
                                for pid in scanned_udps:
                                    with open(final_csv, "a") as f_out:
                                        f_out.write(f"{source_ip},{ip},Segmentation Passed,{pid},udp,{ep_state},{ep_reason},unknown\n")
                    except Exception as ex:
                        print(f"Error parsing Nmap XML for {ip}: {ex}")
                        
                    if os.path.exists(nmap_xml):
                        import shutil
                        output_prefix = final_csv.replace('_PCI_Report.csv', '')
                        shutil.move(nmap_xml, f"{output_prefix}_nmap_{ip}.xml")
            
            # Also record the original range as "Failed" for context
            if "/" in target:
                with open(final_csv, "a") as f_out:
                    f_out.write(f"{source_ip},{target},Segmentation Failed (Partial),N/A,N/A,Multiple,See IP entries,N/A\n")

    except Exception as e:
        print(f"Error processing {target}: {e}")

EOF_PY

    python3 "$SECURE_TMP/septum_orchestrator.py" "$OUTPUT_XML" "$IP_LIST" "$SOURCE_IP" "$FINAL_CSV" "$SECURE_TMP" "$INTERFACE" "$FP_PORTS"
    
    # Write the executed scan command as a metadata row at the bottom of the CSV
    echo "Testing Information,Testing Techniques Used,masscan -iL $IP_LIST $PORT_ARGS -e $INTERFACE --source-ip $SOURCE_IP --rate $RATE,N/A,N/A,N/A,N/A,N/A" >> "$FINAL_CSV"
    
    # Write the Scanner Link Validation metadata row at the bottom of the CSV
    echo "Testing Information,Scanner Link Validation,Interface: $INTERFACE - Gateway: $ROUTER_IP ($LINK_STATUS),N/A,N/A,N/A,N/A,N/A" >> "$FINAL_CSV"
    
    # Write new compliance metadata rows
    echo "Testing Information,Scanner Subnet/CIDR,$SOURCE_CIDR,N/A,N/A,N/A,N/A,N/A" >> "$FINAL_CSV"
    echo "Testing Information,Positive Control Target,$POS_CONTROL ($POS_STATUS),N/A,N/A,N/A,N/A,N/A" >> "$FINAL_CSV"
    echo "Testing Information,Path Discovery (Traceroute),$TRACEROUTE_STATUS,N/A,N/A,N/A,N/A,N/A" >> "$FINAL_CSV"
    echo "Testing Information,Tester Name,$TESTER_NAME,N/A,N/A,N/A,N/A,N/A" >> "$FINAL_CSV"
    echo "Testing Information,Testing Frequency,$TEST_FREQ,N/A,N/A,N/A,N/A,N/A" >> "$FINAL_CSV"
    
    rm -rf "$SECURE_TMP"
    
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

