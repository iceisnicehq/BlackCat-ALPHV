use walkdir::WalkDir;

pub fn scan_filesystem(path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();

    for entry in WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
    {
        if let Some(path_str) = entry.path().to_str() {
            files.push(path_str.to_string());
        }
    }

    Ok(files)
}
