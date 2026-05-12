#!/bin/bash
# Secure Evidence Bundler
# Finds all CSV reports and PCAP evidence, compresses them, encrypts the zip, and securely shreds the originals.

echo "======================================"
echo "    Secure Evidence Bundler v1.0      "
echo "======================================"

# Check for zip
if ! command -v zip &> /dev/null; then
    echo "[-] Error: zip is required. Install with: sudo apt-get install zip"
    exit 1
fi

read -p "Enter a name for the final bundle (e.g., Client_ABC_Evidence): " BUNDLE_NAME
if [ -z "$BUNDLE_NAME" ]; then echo "Name required."; exit 1; fi

BUNDLE_FILE="${BUNDLE_NAME}_$(date +%Y%m%d_%H%M%S).zip"

echo ""
echo "[*] Locating evidence files (.csv, .pcap) in current directory and subdirectories..."
FILES_TO_BUNDLE=$(find . -maxdepth 2 -type f \( -name "*.csv" -o -name "*.pcap" \))

if [ -z "$FILES_TO_BUNDLE" ]; then
    echo "[-] No evidence files found."
    exit 0
fi

echo "$FILES_TO_BUNDLE"
echo ""

read -s -p "Enter a strong password to encrypt the evidence bundle: " ZIP_PASS
echo ""
read -s -p "Confirm password: " ZIP_PASS2
echo ""

if [ "$ZIP_PASS" != "$ZIP_PASS2" ]; then
    echo "[-] Passwords do not match. Exiting."
    exit 1
fi

echo ""
echo "[*] Creating encrypted bundle: $BUNDLE_FILE..."
# use -e for encrypt, -j to strip paths (optional, omitted here to keep structure), -@ to read from stdin
echo "$FILES_TO_BUNDLE" | zip -e -P "$ZIP_PASS" "$BUNDLE_FILE" -@ >/dev/null

if [ $? -eq 0 ] && [ -f "$BUNDLE_FILE" ]; then
    echo "[+] Bundle created successfully."
    echo ""
    read -p "Do you want to securely SHRED and delete the original unencrypted files? (y/N): " DO_SHRED
    if [[ "$DO_SHRED" =~ ^[Yy]$ ]]; then
        echo "[*] Shredding original files..."
        for file in $FILES_TO_BUNDLE; do
            echo "    -> Shredding $file"
            shred -u "$file" 2>/dev/null || rm -f "$file"
        done
        echo "[+] Original files securely deleted."
    else
        echo "[*] Original files kept."
    fi
    echo ""
    echo "======================================"
    echo "Done. Your secure bundle is ready to SCP:"
    echo "$BUNDLE_FILE"
    echo "======================================"
else
    echo "[-] Error creating bundle."
fi
