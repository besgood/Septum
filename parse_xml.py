import xml.etree.ElementTree as ET
import csv
import sys
import os

def parse_nmap_xml(xml_file, output_csv):
    """Parses an Nmap XML file and extracts relevant port state data into a CSV."""
    if not os.path.exists(xml_file):
        print(f"Error: File '{xml_file}' not found.")
        sys.exit(1)

    print(f"Parsing '{xml_file}'...")
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        sys.exit(1)


    # Try to extract Source IP from the nmap command arguments in the XML
    import re
    nmap_args = root.get("args", "")
    source_ip = "See_Nmap_Command_Log"
    source_ip_match = re.search(r"-S\s+([\d\.]+)", nmap_args)
    if source_ip_match:
        source_ip = source_ip_match.group(1)
    # Count for progress/summary
    total_hosts = 0
    total_ports_logged = 0

    with open(output_csv, mode='w', newline='') as csv_file:
        fieldnames = ['Source_IP', 'Target_IP', 'Port', 'Protocol', 'Service', 'State', 'Reason']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        # Assuming the scan source IP isn't reliably in the XML root, we look at the host data.
        # However, for segmentation testing, the target state is what matters.
        for host in root.findall('host'):
            total_hosts += 1
            
            # Find target IP
            target_ip = ""
            for address in host.findall('address'):
                if address.get('addrtype') == 'ipv4':
                    target_ip = address.get('addr')
                    break
            
            if not target_ip:
                continue

            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    state_elem = port.find('state')
                    state = state_elem.get('state') if state_elem is not None else "unknown"
                    reason = state_elem.get('reason') if state_elem is not None else "unknown"
                    
                    service_elem = port.find('service')
                    service_name = service_elem.get('name') if service_elem is not None else "unknown"

                    writer.writerow({
                        'Source_IP': source_ip,
                        'Target_IP': target_ip,
                        'Port': port_id,
                        'Protocol': protocol,
                        'Service': service_name,
                        'State': state,
                        'Reason': reason
                    })
                    total_ports_logged += 1

    print(f"Parsing complete!")
    print(f"Processed {total_hosts} hosts.")
    print(f"Extracted {total_ports_logged} port records.")
    print(f"Data saved to: {output_csv}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 parse_xml.py <input.xml> <output.csv>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    parse_nmap_xml(input_file, output_file)
