#!/usr/bin/env python3
"""
BlackCat Exfiltration Data Decryptor
Decrypts files using AES-GCM with provided key
"""

import struct
import os
from datetime import datetime

# Try to import cryptography library, provide instructions if not available
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[-] Cryptography library not installed")
    print("[*] Install it with: pip install cryptography")

def decrypt_blackcat_data(encrypted_data, key_hex):
    """
    Decrypt BlackCat exfiltration data
    Format: 12-byte nonce + AES-GCM ciphertext
    """
    if not CRYPTO_AVAILABLE:
        print("[-] Cannot decrypt: cryptography library not available")
        return None

    try:
        # Convert hex key to bytes
        key = bytes.fromhex(key_hex)
        if len(key) != 32:
            print(f"[-] Key must be 32 bytes (64 hex chars), got {len(key)} bytes")
            return None

        # Extract nonce (first 12 bytes) and ciphertext
        if len(encrypted_data) < 12:
            print(f"[-] Data too short ({len(encrypted_data)} bytes)")
            return None

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        # Decrypt using AES-GCM
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)

        print(f"[+] Successfully decrypted {len(decrypted)} bytes")
        return decrypted

    except Exception as e:
        print(f"[-] Decryption failed: {e}")
        return None

def analyze_decrypted_data(decrypted_data, output_dir):
    """
    Analyze decrypted BlackCat exfiltration data
    Format: BLACKCAT_EXFIL_v1.0 + system info + files
    """
    try:
        # --- MAJOR FIX: Correct the offset calculation for the magic string ---
        if not decrypted_data.startswith(b'BLACKCAT_EXFIL_v1.0'):
            print("[-] Not a valid BlackCat exfiltration file")
            # Try to show what we actually have
            print(f"[*] First 20 bytes (hex): {decrypted_data[:20].hex()}")
            print(f"[*] First 20 bytes (ascii): {decrypted_data[:20]}")
            return False

        print("[*] Analyzing decrypted data...")
        # Magic string is 19 bytes: len("BLACKCAT_EXFIL_v1.0") = 19
        MAGIC_STRING = b'BLACKCAT_EXFIL_v1.0'
        offset = len(MAGIC_STRING)  # Should be 19

        # Read system info length (4-byte big-endian)
        if len(decrypted_data) < offset + 4:
            print("[-] Data too short to read system info length")
            return False

        info_len = struct.unpack('>I', decrypted_data[offset:offset+4])[0]
        offset += 4

        # Read system info
        if len(decrypted_data) < offset + info_len:
            print(f"[-] Data too short to read system info (needed {info_len} bytes)")
            return False

        system_info = decrypted_data[offset:offset+info_len].decode('utf-8', errors='ignore')
        offset += info_len

        print(f"[*] System: {system_info}")

        # Read number of files
        if len(decrypted_data) < offset + 4:
            print("[-] Data too short to read file count")
            return False

        file_count = struct.unpack('>I', decrypted_data[offset:offset+4])[0]
        offset += 4

        print(f"[*] Found {file_count} files")

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Extract each file
        extracted_files = []
        for i in range(file_count):
            print(f"[*] Processing file {i+1}/{file_count}...")

            # Read path length
            if len(decrypted_data) < offset + 4:
                print(f"[-] Data truncated at file {i+1} (path length)")
                break
            path_len = struct.unpack('>I', decrypted_data[offset:offset+4])[0]
            offset += 4

            # Read path
            if len(decrypted_data) < offset + path_len:
                print(f"[-] Data truncated at file {i+1} (path)")
                break
            file_path = decrypted_data[offset:offset+path_len].decode('utf-8', errors='ignore')
            offset += path_len

            # Read file size
            if len(decrypted_data) < offset + 8:
                print(f"[-] Data truncated at file {i+1} (file size)")
                break
            file_size = struct.unpack('>Q', decrypted_data[offset:offset+8])[0]
            offset += 8

            # Read file data
            if len(decrypted_data) < offset + file_size:
                print(f"[-] Data truncated at file {i+1} (file data, needed {file_size} bytes)")
                break
            file_data = decrypted_data[offset:offset+file_size]
            offset += file_size

            # Skip separator "---FILE_END---" (14 bytes)
            SEPARATOR = b'---FILE_END---'
            if len(decrypted_data) < offset + len(SEPARATOR):
                print(f"[-] Data truncated at file {i+1} (separator)")
                break
            # Verify separator
            actual_separator = decrypted_data[offset:offset+len(SEPARATOR)]
            if actual_separator != SEPARATOR:
                print(f"[!] Warning: Expected separator not found at file {i+1}")
                print(f"    Got: {actual_separator}")
                # Try to continue anyway
            offset += len(SEPARATOR)

            # Create safe filename
            safe_name = os.path.basename(file_path)
            safe_name = safe_name.replace('..', '_').replace('/', '_').replace('\\', '_')
            if not safe_name:
                safe_name = f"file_{i+1:03d}"

            output_path = os.path.join(output_dir, safe_name)

            # Save file
            with open(output_path, 'wb') as f:
                f.write(file_data)

            extracted_files.append((safe_name, len(file_data)))

            # Show preview for text files
            if safe_name.endswith(('.txt', '.ini', '.config', '.sql', '.log', '.xml', '.json')):
                try:
                    preview = file_data[:200].decode('utf-8', errors='ignore')
                    if preview.strip():
                        print(f"  [{i+1}] {safe_name} ({len(file_data)} bytes)")
                        print(f"      Preview: {preview[:80]}...")
                except:
                    pass

        # Create extraction report
        report_path = os.path.join(output_dir, "extraction_report.txt")
        with open(report_path, 'w') as f:
            f.write("BLACKCAT EXFILTRATION DATA EXTRACTION REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Extraction time: {datetime.now()}\n")
            f.write(f"System info: {system_info}\n")
            f.write(f"Total files: {file_count}\n")
            f.write(f"Successfully extracted: {len(extracted_files)}\n\n")

            f.write("EXTRACTED FILES:\n")
            f.write("-" * 30 + "\n")
            for filename, size in extracted_files:
                f.write(f"{filename} ({size} bytes)\n")

        print(f"\n[+] {len(extracted_files)} files saved to: {output_dir}")
        print(f"[+] Report saved to: {report_path}")

        # Show summary
        print("\n" + "=" * 50)
        print("EXTRACTION SUMMARY:")
        print(f"Total files in archive: {file_count}")
        print(f"Successfully extracted: {len(extracted_files)}")
        if extracted_files:
            for filename, size in extracted_files:
                print(f"  - {filename}: {size} bytes")

        return True

    except Exception as e:
        print(f"[-] Error analyzing data: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 60)
    print("BLACKCAT EXFILTRATION DATA DECRYPTOR")
    print("=" * 60)

    if not CRYPTO_AVAILABLE:
        print("\n[!] Please install required library:")
        print("    pip install cryptography")
        return

    # Get encrypted file
    encrypted_file = input("\nEnter path to encrypted file: ").strip()
    if not os.path.exists(encrypted_file):
        print(f"[-] File not found: {encrypted_file}")
        return

    # Get decryption key
    key_hex = input("Enter decryption key (64 hex characters): ").strip()
    if len(key_hex) != 64:
        print(f"[-] Key must be 64 hex characters, got {len(key_hex)}")
        return

    # Output directory
    output_dir = input("Enter output directory [default: extracted]: ").strip()
    if not output_dir:
        output_dir = "extracted"

    # Read encrypted data
    print(f"\n[*] Reading {encrypted_file}...")
    try:
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        print(f"[*] Loaded {len(encrypted_data)} bytes")
    except Exception as e:
        print(f"[-] Failed to read file: {e}")
        return

    # Decrypt data
    print("[*] Decrypting...")
    decrypted_data = decrypt_blackcat_data(encrypted_data, key_hex)

    if decrypted_data is None:
        print("[-] Decryption failed")

        # Try alternative approach - maybe it's not in our format
        print("\n[*] Trying alternative analysis...")
        print(f"First 100 bytes (hex): {encrypted_data[:100].hex()}")
        print(f"First 100 bytes (ascii): {encrypted_data[:100]}")

        # Check for common patterns
        if b'BLACKCAT' in encrypted_data[:100]:
            print("[*] Found 'BLACKCAT' in encrypted data")
            print("[*] Maybe the key is wrong or data is corrupted")
        return

    # Analyze and extract
    print("[*] Extracting files...")
    success = analyze_decrypted_data(decrypted_data, output_dir)

    if not success:
        print("\n[*] Could not parse as structured data")
        print("[*] Saving raw decrypted data...")

        raw_output = os.path.join(output_dir, "raw_decrypted.bin")
        with open(raw_output, 'wb') as f:
            f.write(decrypted_data)
        print(f"[+] Raw data saved to: {raw_output}")

        # Try to show as text
        try:
            text_preview = decrypted_data[:1000].decode('utf-8', errors='ignore')
            if text_preview:
                print("\n[*] Text preview (first 1000 chars):")
                print("-" * 40)
                print(text_preview[:500])
        except:
            pass

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Operation cancelled by user")
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")