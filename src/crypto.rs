use aes::Aes256;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::Rng;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use std::str::FromStr;
use sha2::{Sha256, Digest};

pub struct CryptoEngine {
    rsa_key: RsaPublicKey,
    encryption_mode: String,
}

impl CryptoEngine {
    /// Инициализирует крипто engine с публичным RSA ключом
    pub fn new(
        rsa_public_key_pem: &str,
        encryption_mode: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let rsa_key = RsaPublicKey::from_str(rsa_public_key_pem)
            .map_err(|e| format!("Failed to parse RSA key: {}", e))?;
        
        Ok(CryptoEngine {
            rsa_key,
            encryption_mode: encryption_mode.to_string(),
        })
    }
    
    /// Генерирует случайный AES-256 ключ (32 байта = 256 бит)
    pub fn generate_aes_key() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut key = vec![0u8; 32];
        rng.fill(&mut key[..]);
        key
    }
    
    /// Генерирует случайный ChaCha20 nonce (12 байт для ChaCha20Poly1305)
    pub fn generate_nonce() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut nonce = vec![0u8; 12];
        rng.fill(&mut nonce[..]);
        nonce
    }
    
    /// Шифрует AES ключ используя RSA-4096 публичный ключ
    pub fn encrypt_aes_key(&self, aes_key: &[u8]) -> Result<Vec<u8>, String> {
        let mut rng = rand::thread_rng();
        match self.rsa_key.encrypt(&mut rng, Pkcs1v15Encrypt, aes_key) {
            Ok(encrypted) => Ok(encrypted),
            Err(e) => Err(format!("RSA encryption failed: {}", e)),
        }
    }
    
    /// Шифрует содержимое файла используя ChaCha20 stream cipher
    pub fn encrypt_chacha20(
        plaintext: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Vec<u8> {
        let mut cipher = ChaCha20::new(key.into(), nonce.into());
        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);
        ciphertext
    }
    
    /// Шифрует содержимое файла используя AES-256-CTR режим
    pub fn encrypt_aes256(
        plaintext: &[u8],
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Vec<u8>, String> {
        use aes::cipher::{BlockEncrypt, KeyInit};
        use aes::Block;
        
        // AES-256 блоковое шифрование (в production нужно использовать CTR mode)
        // Это упрощенный пример, в реальности нужен CTR mode implementation
        let cipher = Aes256::new(key.into());
        
        // Простое блоковое шифрование (не рекомендуется для real files - используйте CTR)
        let mut result = Vec::new();
        for chunk in plaintext.chunks(16) {
            let mut block = Block::default();
            if chunk.len() == 16 {
                block.copy_from_slice(chunk);
            } else {
                // Padding PKCS7 для последнего блока
                block[..chunk.len()].copy_from_slice(chunk);
                let pad_len = 16 - chunk.len();
                for i in chunk.len()..16 {
                    block[i] = pad_len as u8;
                }
            }
            cipher.encrypt_block(&mut block);
            result.extend_from_slice(&block);
        }
        
        Ok(result)
    }
    
    /// Дешифрует для тестирования (требует приватный ключ)
    pub fn decrypt_chacha20(
        ciphertext: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Vec<u8> {
        let mut cipher = ChaCha20::new(key.into(), nonce.into());
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);
        plaintext
    }
    
    /// Создает структуру зашифрованного файла с заголовком
    /// [BorderMarker: 4 bytes] [EncryptedAESKey: ~512 bytes] [BorderMarker: 4 bytes] [EncryptedContent: variable]
    pub fn create_encrypted_file_structure(
        original_content: &[u8],
        aes_key: &[u8],
        nonce: &[u8; 12],
        use_chacha20: bool,
    ) -> Result<Vec<u8>, String> {
        let border_marker: [u8; 4] = [0x19, 0x47, 0xB2, 0xCE];
        
        // Шифруем AES ключ
        let encrypted_key = self.encrypt_aes_key(aes_key)?;
        
        // Шифруем содержимое файла
        let encrypted_content = if use_chacha20 {
            let aes_key_arr: [u8; 32] = aes_key.try_into()
                .map_err(|_| "Invalid AES key size".to_string())?;
            Self::encrypt_chacha20(original_content, &aes_key_arr, nonce)
        } else {
            // Для AES используем простое блоковое шифрование
            let aes_key_arr: [u8; 32] = aes_key.try_into()
                .map_err(|_| "Invalid AES key size".to_string())?;
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&nonce[..16]);
            Self::encrypt_aes256(original_content, &aes_key_arr, &iv)?
        };
        
        // Конструируем финальный файл
        let mut result = Vec::new();
        result.extend_from_slice(&border_marker);
        result.extend_from_slice(&encrypted_key);
        result.extend_from_slice(&border_marker);
        result.extend_from_slice(&encrypted_content);
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt_chacha20() {
        let key = [42u8; 32];
        let nonce = [13u8; 12];
        let plaintext = b"Hello, World! This is a test.";
        
        let ciphertext = CryptoEngine::encrypt_chacha20(plaintext, &key, &nonce);
        let decrypted = CryptoEngine::decrypt_chacha20(&ciphertext, &key, &nonce);
        
        assert_eq!(plaintext, &decrypted[..]);
    }
}
