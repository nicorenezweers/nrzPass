//! Einstellungen aus Umgebungsvariablen.

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub address: String,
    pub port: u16,
    pub data_dir: PathBuf,
    pub web_dir: Option<PathBuf>,
    pub download_dir: PathBuf,
    pub signups_allowed: bool,
    pub signups_domains: Vec<String>,
    pub trust_proxy: bool,
    pub proxy_enabled: bool,
    pub seed: Option<String>,
    pub db_key: Option<String>,
    /// Anfragen je Minute und IP auf `/identity/*` (und andere heikle Endpunkte).
    pub identity_rate_per_min: u32,
}

fn flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on" | "ja"),
        Err(_) => default,
    }
}

fn opt(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

impl Config {
    pub fn from_env() -> Config {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        Config {
            address: opt("NRZPASS_ADDRESS").unwrap_or_else(|| "0.0.0.0".into()),
            port: opt("NRZPASS_PORT").and_then(|p| p.parse().ok()).unwrap_or(8490),
            data_dir: opt("DATA_DIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("./data")),
            web_dir: opt("WEB_DIR").map(PathBuf::from),
            download_dir: opt("DOWNLOAD_DIR").map(PathBuf::from).unwrap_or_else(|| exe_dir.join("downloads")),
            signups_allowed: flag("SIGNUPS_ALLOWED", false),
            signups_domains: opt("SIGNUPS_DOMAINS")
                .map(|d| d.split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_default(),
            trust_proxy: flag("TRUST_PROXY", false),
            proxy_enabled: flag("PROXY_ENABLED", true),
            seed: opt("NRZPASS_SEED"),
            db_key: opt("NRZPASS_DB_KEY"),
            identity_rate_per_min: opt("IDENTITY_RATE_PER_MIN").and_then(|p| p.parse().ok()).unwrap_or(10),
        }
    }

    /// Fuer Tests: alles Standard, Daten in `dir`.
    pub fn for_dir(dir: PathBuf) -> Config {
        Config {
            address: "127.0.0.1".into(),
            port: 0,
            download_dir: dir.join("downloads"),
            data_dir: dir,
            web_dir: None,
            signups_allowed: false,
            signups_domains: vec![],
            trust_proxy: false,
            proxy_enabled: true,
            seed: None,
            db_key: None,
            identity_rate_per_min: 10,
        }
    }
}
