use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub name: String,
    pub value: String,
    pub encryption_type: String,
    pub target_extensions: Vec<String>,
}

impl Config {
    pub fn new(name: String, value: String) -> Self {
        Config {
            name,
            value,
            encryption_type: "aes-256-gcm".to_string(),
            target_extensions: vec!["pdf", "docx", "xlsx"].iter().map(|s| s.to_string()).collect(),
        }
    }
}
