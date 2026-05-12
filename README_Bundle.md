# Secure Evidence Bundler

A simple, secure post-engagement utility for remote Linux machines (like Kali) to aggregate, encrypt, and securely purge engagement evidence.

This tool is designed to solve the problem of managing scattered CSV reports and massive PCAP files after a PCI DSS segmentation or vulnerability validation test. It allows you to package all findings into a single encrypted bundle for easy exfiltration while ensuring no sensitive raw data remains on the remote testing machine.

## Features
- **Auto-Discovery**: Recursively finds all `.csv` reports and `.pcap` evidence files in the current working directory and subdirectories.
- **AES-256 Encryption**: Leverages `zip` encryption to password-protect the evidence bundle, ensuring sensitive CDE traffic captures are protected during transit.
- **Secure Data Destruction**: Includes an optional (but recommended) step to `shred` the original unencrypted evidence files using the `shred -u` command, which overwrites the data on disk before deletion.
- **Minimal Footprint**: A lightweight, standalone bash script with minimal dependencies.

## Installation

### Prerequisites
The script requires the `zip` utility to be installed:
```bash
sudo apt-get update
sudo apt-get install -y zip
```

### Setup
```bash
git clone https://github.com/yourusername/secure-evidence-bundler.git
chmod +x bundle-evidence.sh
```

## Usage

Simply execute the script in your main project or testing directory:

```bash
./bundle-evidence.sh
```

### Interactive Prompts
1. **Bundle Name**: Provide a descriptive name for the client or engagement (e.g., `Client_X_PCI_Test`).
2. **Password**: Enter and confirm a strong password for the ZIP encryption.
3. **Shred Confirmation**: After the bundle is created, you will be prompted to shred the original files. **Warning**: This action is irreversible.

### Expected Output
```text
======================================
    Secure Evidence Bundler v1.0
======================================
Enter a name for the final bundle: Client_X_Evidence

[*] Locating evidence files (.csv, .pcap)...
./Septum/PCI_VLAN_200_Report.csv
./Septum/PCI_VLAN_200_Evidence.pcap
./compliance-auditor/tls_remediation.csv

Enter a strong password to encrypt the bundle:
Confirm password:

[*] Creating encrypted bundle: Client_X_Evidence_20260512_143000.zip...
[+] Bundle created successfully.

Do you want to securely SHRED and delete the original unencrypted files? (y/N): y
[*] Shredding original files...
    -> Shredding ./Septum/PCI_VLAN_200_Report.csv
    -> Shredding ./Septum/PCI_VLAN_200_Evidence.pcap
    -> Shredding ./compliance-auditor/tls_remediation.csv
[+] Original files securely deleted.

======================================
Done. Your secure bundle is ready to SCP:
Client_X_Evidence_20260512_143000.zip
======================================
```

## Security Note
This tool uses the Linux `shred` command with the `-u` (remove) flag. On standard filesystems (EXT4), this overwrites the disk blocks where your unencrypted evidence lived multiple times, making data recovery extremely difficult. This is a critical step for maintaining a clean and secure testing environment on remote assets.
