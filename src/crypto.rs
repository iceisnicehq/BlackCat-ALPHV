use aes_gcm::{Aes256Gcm, Nonce, Key, aead::Aead};
use aes_gcm::KeyInit as AesKeyInit;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::KeyInit as ChaChaKeyInit;
use rand::Rng;
use std::error::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
}

pub struct CryptoEngine {
    master_key: [u8; 32],
}

impl CryptoEngine {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let mut master_key = [0u8; 32];
        rng.fill(&mut master_key);
        Ok(CryptoEngine { master_key })
    }

    pub fn encrypt_aes_256(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut rng = rand::thread_rng();
        let mut nonce_array = [0u8; 12];
        rng.fill(&mut nonce_array);

        let key = Key::<Aes256Gcm>::from(self.master_key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce_array);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut result = Vec::new();
        result.extend_from_slice(&nonce_array);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt_aes_256(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < 12 {
            return Err(CryptoError::DecryptionFailed("Too short".to_string()));
        }

        let (nonce_array, encrypted_data) = ciphertext.split_at(12);
        let key = Key::<Aes256Gcm>::from(self.master_key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(nonce_array);

        cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }

    pub fn encrypt_chacha20(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut rng = rand::thread_rng();
        let mut nonce_array = [0u8; 12];
        rng.fill(&mut nonce_array);

        let key = Key::<ChaCha20Poly1305>::from(self.master_key);
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from_slice(&nonce_array);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut result = Vec::new();
        result.extend_from_slice(&nonce_array);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn encrypt_file(&self, content: &[u8], use_chacha20: bool) -> Result<Vec<u8>, CryptoError> {
        if use_chacha20 {
            self.encrypt_chacha20(content)
        } else {
            self.encrypt_aes_256(content)
        }
    }

    pub fn get_master_key(&self) -> [u8; 32] {
        self.master_key
    }
}
