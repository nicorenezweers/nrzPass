//! nrzPass fuer macOS: Tauri-Huelle um den Web-Tresor (dist/web, lokal gebuendelt – es wird
//! kein Code aus dem Netz geladen). Der Rust-Teil uebernimmt nur, was der Webview nicht darf:
//! HTTP zu beliebigen nrzPass-/Vaultwarden-Servern (ohne CORS), Zwischenablage, Speichern-Dialog
//! und Links im Standardbrowser. Ver- und Entschluesselung passiert weiterhin im WASM-Client.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tauri::Manager;
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;

const MAX_BODY: usize = 20 * 1024 * 1024;

#[derive(Deserialize)]
struct HttpReq {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

#[derive(Serialize)]
struct HttpResp {
    status: u16,
    body: String,
}

/// Nur Header, die die Bitwarden-API braucht.
const ALLOWED_HEADERS: &[&str] = &[
    "accept", "authorization", "content-type", "device-type", "bitwarden-client-name", "bitwarden-client-version", "auth-email",
];

#[tauri::command]
async fn http_request(state: tauri::State<'_, reqwest::Client>, req: HttpReq) -> Result<HttpResp, String> {
    let url = url::Url::parse(&req.url).map_err(|_| "Ungültige Adresse".to_string())?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err("Nur http:// und https:// sind erlaubt".into());
    }
    let path = url.path();
    if !(path.contains("/api/") || path.contains("/identity/") || path.ends_with("/alive")) {
        return Err("Nur Aufrufe der Bitwarden-API sind erlaubt".into());
    }
    let method = match req.method.as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        _ => return Err("Methode nicht erlaubt".into()),
    };
    let mut rb = state.request(method, url);
    for (k, v) in &req.headers {
        if ALLOWED_HEADERS.contains(&k.to_ascii_lowercase().as_str()) {
            rb = rb.header(k, v);
        }
    }
    if let Some(b) = req.body {
        rb = rb.body(b);
    }
    let resp = rb.send().await.map_err(|e| {
        if e.is_timeout() { "Zeitüberschreitung".to_string() } else { "Server nicht erreichbar (Adresse, Netzwerk oder Zertifikat prüfen)".to_string() }
    })?;
    let status = resp.status().as_u16();
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    if bytes.len() > MAX_BODY {
        return Err("Antwort zu groß".into());
    }
    Ok(HttpResp { status, body: String::from_utf8_lossy(&bytes).into_owned() })
}

#[tauri::command]
fn clipboard_write(app: tauri::AppHandle, text: String) -> Result<(), String> {
    app.clipboard().write_text(text).map_err(|e| e.to_string())
}

#[tauri::command]
async fn save_file(app: tauri::AppHandle, name: String, contents: String) -> Result<(), String> {
    let path = app
        .dialog()
        .file()
        .set_file_name(&name)
        .add_filter("JSON", &["json"])
        .blocking_save_file()
        .ok_or("Abgebrochen")?;
    let path = path.into_path().map_err(|e| e.to_string())?;
    std::fs::write(&path, contents).map_err(|e| e.to_string())?;
    // Exporte nur fuer den eigenen Benutzer lesbar
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[tauri::command]
fn open_url(app: tauri::AppHandle, url: String) -> Result<(), String> {
    let u = url::Url::parse(&url).map_err(|_| "Ungültige Adresse".to_string())?;
    if !matches!(u.scheme(), "https" | "http") {
        return Err("Nur Webadressen".into());
    }
    app.opener().open_url(u.as_str(), None::<&str>).map_err(|e| e.to_string())
}

fn main() {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("nrzPass-macOS/", env!("CARGO_PKG_VERSION")))
        .https_only(false)
        .build()
        .expect("HTTP-Client");

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .manage(client)
        .invoke_handler(tauri::generate_handler![http_request, clipboard_write, save_file, open_url])
        .setup(|app| {
            if let Some(w) = app.get_webview_window("main") {
                // Kein Bildschirmfoto / keine Bildschirmfreigabe des Tresors
                let _ = w.set_content_protected(true);
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("nrzPass konnte nicht starten");
}
