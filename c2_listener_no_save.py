#!/usr/bin/env python3
"""
Simple connection monitor for BlackCat C2
Shows incoming connections without saving files
"""

import socket
import struct
from datetime import datetime

def connection_monitor():
    HOST = '0.0.0.0'
    PORT = 4444
    
    print("=" * 60)
    print("BLACKCAT CONNECTION MONITOR")
    print(f"Monitoring port {PORT}")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        
        print(f"[*] Monitor started on port {PORT}")
        
        while True:
            conn, addr = s.accept()
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"\n[{timestamp}] Connection from {addr[0]}")
            
            try:
                conn.settimeout(5)
                
                # Try to get some data
                data = conn.recv(1024)
                
                if data:
                    print(f"  Received {len(data)} bytes")
                    
                    # Check for BlackCat signature
                    if len(data) >= 19 and data.startswith(b'BLACKCAT_EXFIL'):
                        print("  [BLACKCAT] Valid signature detected")
                        
                        # Try to get more data
                        try:
                            total_size = 0
                            if len(data) >= 23:
                                size_data = data[19:23]
                                if len(size_data) == 4:
                                    total_size = struct.unpack('>I', size_data)[0]
                                    print(f"  [BLACKCAT] Total size: {total_size} bytes")
                            
                            # Receive more if needed
                            if total_size > len(data):
                                remaining = total_size - len(data)
                                print(f"  [BLACKCAT] Receiving {remaining} more bytes...")
                                conn.settimeout(10)
                                while len(data) < total_size:
                                    chunk = conn.recv(4096)
                                    if not chunk:
                                        break
                                    data += chunk
                            
                            print(f"  [BLACKCAT] Total received: {len(data)} bytes")
                            print(f"  [BLACKCAT] First 32 bytes: {data[:32].hex()}")
                            
                        except:
                            pass
                    
                    # Quick analysis
                    if b'.txt' in data or b'.doc' in data or b'.pdf' in data:
                        print("  [CONTENT] Contains file extensions")
                    
                    # Count printable characters
                    printable = sum(1 for c in data[:100] if 32 <= c <= 126)
                    if printable > 80:
                        print("  [CONTENT] High percentage of printable text")
                        
                else:
                    print("  No data received")
                    
            except socket.timeout:
                print("  Connection timeout")
            except Exception as e:
                print(f"  Error: {e}")
            finally:
                conn.close()

if __name__ == "__main__":
    try:
        connection_monitor()
    except KeyboardInterrupt:
        print("\n\n[*] Monitor stopped")