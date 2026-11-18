//! Update-Pruefung gegen nrzGit (macOS-App und Browser-Erweiterung).
//!
//! * macOS-App: Tauri-Updater liest `latest.json` vom Zweig `umbrel` des nrzPass-Repos,
//!   prueft die minisign-Signatur und ersetzt die App (Befehle `update_check`/`update_install`).
//! * Erweiterung: `update.json` vom selben Zweig; entpackte Erweiterungen koennen sich nicht
//!   selbst ersetzen, deshalb Download + "Erweiterung neu laden".
//! * Webseite: aktualisiert sich mit der Umbrel-App, hier gibt es nichts zu tun.

use crate::env::{self, Platform};
use crate::net::{self, Req, Via};
use crate::state::App;
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::Deserialize;
use serde_json::Value;

/// Basis auf nrzGit (Zweig `umbrel` des nrzPass-Repos).
pub const UPDATE_BASE: &str = "http://100.78.107.162:8390/nicorenezweers/nrzPass/raw/branch/umbrel";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
const AUTO_INTERVAL_MS: f64 = 12.0 * 3600.0 * 1000.0;

#[derive(Clone, Debug, PartialEq, Default)]
pub struct UpdateInfo {
    pub available: bool,
    pub version: String,
    pub notes: String,
    pub date: String,
    /// Download fuer diese Erweiterung (Chrome/Firefox).
    pub download: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct UpdateJson {
    version: String,
    notes: String,
    date: String,
    downloads: std::collections::HashMap<String, String>,
}

pub fn supported() -> bool {
    env::platform() != Platform::Web
}

/// `a > b` fuer Versionen wie "1.2.10".
pub fn newer(a: &str, b: &str) -> bool {
    let p = |v: &str| -> Vec<u64> { v.trim_start_matches('v').split(['.', '-']).take(3).map(|x| x.parse().unwrap_or(0)).collect() };
    p(a) > p(b)
}

pub async fn check() -> Result<UpdateInfo, String> {
    match env::platform() {
        Platform::Tauri => {
            let v = env::tauri_invoke("update_check", js_sys::Object::new().into()).await?;
            let v: Value = serde_json::from_str(&js_sys::JSON::stringify(&v).map(String::from).unwrap_or_default()).map_err(|e| e.to_string())?;
            Ok(UpdateInfo {
                available: v["available"].as_bool().unwrap_or(false),
                version: v["version"].as_str().unwrap_or_default().to_string(),
                notes: v["notes"].as_str().unwrap_or_default().to_string(),
                date: v["date"].as_str().unwrap_or_default().to_string(),
                download: None,
            })
        }
        Platform::Extension => {
            let url = format!("{UPDATE_BASE}/update.json?t={}", env::now_ms() as u64);
            let r = net::send(Req { method: "GET", url, headers: vec![("Accept".into(), "application/json".into())], body: None }, &Via::Direct).await?;
            if !r.ok() {
                return Err(format!("nrzGit antwortet nicht ({})", r.status));
            }
            let u: UpdateJson = serde_json::from_str(&r.body).map_err(|_| "update.json auf nrzGit ist ungültig".to_string())?;
            let key = if env::is_firefox() { "firefox" } else { "chrome" };
            Ok(UpdateInfo {
                available: newer(&u.version, CURRENT),
                download: u.downloads.get(key).cloned(),
                version: u.version,
                notes: u.notes,
                date: u.date,
            })
        }
        Platform::Web => Err("Die Webseite aktualisiert sich mit der Umbrel-App.".into()),
    }
}

/// Beim Entsperren hoechstens alle 12 Stunden still pruefen.
pub fn auto_check(app: App) {
    if !supported() || env::now_ms() - app.settings.get_untracked().last_update_check < AUTO_INTERVAL_MS {
        return;
    }
    spawn_local(async move {
        if let Ok(u) = check().await {
            app.settings.update(|s| s.last_update_check = env::now_ms());
            app.save_settings();
            if u.available {
                app.update.set(Some(u));
            }
        }
    });
}

/// macOS: herunterladen, Signatur pruefen, ersetzen, neu starten.
pub async fn install_mac() -> Result<(), String> {
    env::tauri_invoke("update_install", js_sys::Object::new().into()).await.map(|_| ())
}
