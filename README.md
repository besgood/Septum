# Septum: Large-Scale PCI Segmentation Tester

Septum is a high-fidelity, low-impact network scanning wrapper designed specifically for PCI DSS segmentation testing (Requirement 11.4.1) across massive IP ranges.

## Key Features

- **PCI Compliance Ready**: Captures Open, Closed, and Filtered port states, including the technical reason.
- **Network Safety**: Enforces strict rate limiting.
- **VLAN Aware**: Interactive interface selection.
- **Resilient**: Supports pausing, safe exiting, and resuming.
- **AI-Ready Reporting**: Includes a Python parser for CSV conversion.

## Installation

1. Clone the repository
2. chmod +x septum.sh parse_xml.py

## Usage

Run the scan:
```bash
./septum.sh
```

Parse results:
```bash
python3 parse_xml.py input.xml output.csv
```
