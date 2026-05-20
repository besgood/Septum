#!/bin/bash

# Septum - Masscan + Nmap Two-Stage Segmentation Tester
# Enforces PCI-compliant scanning with safe rate limits across massive subnets.

echo "======================================"
echo "  Septum Segmentation Tester (v2.0)   "
echo "======================================"

# Ensure Ctrl-C safely pauses masscan and aborts Stage 2
trap 'echo -e "\n[-] Scan interrupted by user. Masscan should have saved paused.conf."; exit 1' INT

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
read -p "Choice [1/2/3]: " MODE

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
    echo "1) Top 100 Ports"
    echo "2) Top 1,000 Ports"
    echo "3) Top 5,000 Ports"
    echo "4) Top 10,000 Ports"
    echo "5) All Ports (1-65535)"
    echo "6) Manually Enter Ports"
    read -p "Choice [1-6]: " SCOPE_CHOICE
    case $SCOPE_CHOICE in
        1) PORT_ARGS="--top-ports 100" ;;
        2) PORT_ARGS="--top-ports 1000" ;;
        3)
           TOP_PORTS=$(sort -r -k3 /usr/share/nmap/nmap-services | grep '/tcp' | head -n 5000 | awk '{print $2}' | cut -d/ -f1 | paste -sd,)
           PORT_ARGS="-p $TOP_PORTS"
           ;;
        4)
           TOP_PORTS=$(sort -r -k3 /usr/share/nmap/nmap-services | grep '/tcp' | head -n 10000 | awk '{print $2}' | cut -d/ -f1 | paste -sd,)
           PORT_ARGS="-p $TOP_PORTS"
           ;;
        6) read -p "Enter ports (e.g. 80,443,1-1000): " CUSTOM_PORTS
           CUSTOM_PORTS=$(echo "$CUSTOM_PORTS" | tr -d ' ')
           if [ -z "$CUSTOM_PORTS" ]; then echo "[-] Error: Ports required."; exit 1; fi
           PORT_ARGS="-p $CUSTOM_PORTS" ;;
        *) PORT_ARGS="-p 1-65535" ;;
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

    echo "Starting Stage 1: Masscan..."
    sudo masscan -iL "$IP_LIST" $PORT_ARGS -e "$INTERFACE" --source-ip "$SOURCE_IP" $MAC_ARGS --rate "$RATE" -oX "$OUTPUT_XML"

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

# 1. Parse Masscan for failures
failed_hosts = {} # ip -> [ports]
if os.path.exists(masscan_xml) and os.path.getsize(masscan_xml) > 0:
    try:
        for event, elem in ET.iterparse(masscan_xml, events=("end",)):
            if elem.tag == "host":
                addr_elem = elem.find("address")
                if addr_elem is not None:
                    addr = addr_elem.get("addr")
                    ports = []
                    ports_elem = elem.find("ports")
                    if ports_elem is not None:
                        for p in ports_elem.findall("port"):
                            state_elem = p.find("state")
                            if state_elem is not None and state_elem.get("state") == "open":
                                ports.append(p.get("portid"))
                    if ports:
                        if addr not in failed_hosts:
                            failed_hosts[addr] = set()
                        failed_hosts[addr].update(ports)
                elem.clear() # Free memory
    except:
        pass

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
            # Segmentation Failed - Run Nmap on those IPs
            for ip in failures_in_range:
                port_list = ",".join(failed_hosts[ip])
                print(f"[*] Validating failure on {ip}...")

                nmap_xml = f"{tmp_dir}/nmap_{ip}.xml"
                subprocess.run(["sudo", "nmap", "-Pn", "-sS", "-sV", "-T4", "--max-retries", "2", "--host-timeout", "10m", "-e", interface, "-S", source_ip, "-p", port_list, ip, "-oX", nmap_xml], capture_output=True)

                if os.path.exists(nmap_xml):
                    try:
                        n_tree = ET.parse(nmap_xml)
                        n_root = n_tree.getroot()
                        for h in n_root.findall("host"):
                            p_elem = h.find("ports")
                            if p_elem is None: continue

                            scanned_ports = set(failed_hosts[ip])

                            for p in p_elem.findall("port"):
                                pid = p.get("portid")
                                scanned_ports.discard(pid)
                                proto = p.get("protocol")
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

                            for ep in p_elem.findall("extraports"):
                                ep_state = ep.get("state")
                                er = ep.find("extrareasons")
                                ep_reason = er.get("reason") if er is not None else "unknown"
                                for pid in scanned_ports:
                                    with open(final_csv, "a") as f_out:
                                        f_out.write(f"{source_ip},{ip},Segmentation Passed,{pid},tcp,{ep_state},{ep_reason},unknown\n")
                    except:
                        pass
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
