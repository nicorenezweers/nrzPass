//! HTTP zu nrzPass- und Vaultwarden-Servern.
//!
//! * Webseite: eigener Server direkt (gleicher Ursprung); Vaultwarden ueber `/api/nrz/proxy`
//!   des eigenen Servers (Vaultwarden erlaubt keine fremden Webseiten per CORS).
//! * Erweiterung: alles direkt (Host-Berechtigung umgeht CORS).
//! * macOS-App: alles ueber den Rust-Teil der App (Tauri-Befehl `http_request`).

use crate::env::{self, Platform};
use base64_lite::b64url;
use nrzpass_core::api::{self, TokenResponse};
use serde_json::{json, Value};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

mod base64_lite {
    /// Base64url ohne Auffuellung (Header `Auth-Email`).
    pub fn b64url(s: &str) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let b = s.as_bytes();
        let mut out = String::new();
        for c in b.chunks(3) {
            let n = c.iter().enumerate().fold(0u32, |a, (i, x)| a | (*x as u32) << (16 - 8 * i));
            for i in 0..(c.len() + 1) {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        out
    }
}

pub const CLIENT_VERSION: &str = "2025.1.0";

#[derive(Clone, Debug)]
pub struct Resp {
    pub status: u16,
    pub body: String,
}

impl Resp {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
    pub fn error(&self) -> String {
        let v = self.json();
        api::error_message(&v).unwrap_or_else(|| match self.status {
            0 => "Server nicht erreichbar".into(),
            401 => "Sitzung abgelaufen – bitte neu anmelden".into(),
            404 => "Nicht gefunden (ist das ein nrzPass- oder Vaultwarden-Server?)".into(),
            429 => "Zu viele Versuche – bitte kurz warten".into(),
            s => format!("Serverfehler ({s})"),
        })
    }
}

/// Weg zum Server.
#[derive(Clone, Debug, PartialEq)]
pub enum Via {
    Direct,
    Tauri,
    /// Ueber den eigenen nrzPass-Server (Basis-URL, Zugangstoken).
    Proxy(String, String),
}

pub fn default_via() -> Via {
    if env::platform() == Platform::Tauri { Via::Tauri } else { Via::Direct }
}

pub struct Req<'a> {
    pub method: &'a str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

pub async fn send(req: Req<'_>, via: &Via) -> Result<Resp, String> {
    match via {
        Via::Direct => fetch(req).await,
        Via::Tauri => {
            let args = json!({ "req": {
                "method": req.method, "url": req.url,
                "headers": req.headers, "body": req.body,
            }});
            let v = js_sys::JSON::parse(&args.to_string()).map_err(env::js_err)?;
            let r = env::tauri_invoke("http_request", v).await?;
            let r: Value = serde_json::from_str(&js_sys::JSON::stringify(&r).map(String::from).unwrap_or_default())
                .map_err(|e| e.to_string())?;
            Ok(Resp { status: r["status"].as_u64().unwrap_or(0) as u16, body: r["body"].as_str().unwrap_or("").to_string() })
        }
        Via::Proxy(base, token) => {
            let headers: serde_json::Map<String, Value> =
                req.headers.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
            let body = json!({ "url": req.url, "method": req.method, "headers": headers, "body": req.body });
            let r = fetch(Req {
                method: "POST",
                url: format!("{}/api/nrz/proxy", base.trim_end_matches('/')),
                headers: vec![
                    ("Content-Type".into(), "application/json".into()),
                    ("Authorization".into(), format!("Bearer {token}")),
                ],
                body: Some(body.to_string()),
            })
            .await?;
            if !r.ok() {
                return Err(format!("nrzPass-Proxy: {}", r.error()));
            }
            let v = r.json();
            Ok(Resp { status: v["status"].as_u64().unwrap_or(0) as u16, body: v["body"].as_str().unwrap_or("").to_string() })
        }
    }
}

async fn fetch(req: Req<'_>) -> Result<Resp, String> {
    let init = web_sys::RequestInit::new();
    init.set_method(req.method);
    init.set_mode(web_sys::RequestMode::Cors);
    init.set_credentials(web_sys::RequestCredentials::Omit);
    init.set_cache(web_sys::RequestCache::NoStore);
    init.set_redirect(web_sys::RequestRedirect::Error);
    let headers = web_sys::Headers::new().map_err(env::js_err)?;
    for (k, v) in &req.headers {
        headers.set(k, v).map_err(env::js_err)?;
    }
    init.set_headers(&headers);
    if let Some(b) = &req.body {
        init.set_body(&JsValue::from_str(b));
    }
    let request = web_sys::Request::new_with_str_and_init(&req.url, &init).map_err(env::js_err)?;
    let resp = JsFuture::from(env::window().fetch_with_request(&request))
        .await
        .map_err(|_| "Server nicht erreichbar (Adresse, Netzwerk oder Zertifikat prüfen)".to_string())?;
    let resp: web_sys::Response = resp.unchecked_into();
    let text = JsFuture::from(resp.text().map_err(env::js_err)?).await.map_err(env::js_err)?;
    Ok(Resp { status: resp.status(), body: text.as_string().unwrap_or_default() })
}

/// Verbindung zu einem Bitwarden-kompatiblen Server.
#[derive(Clone, Debug)]
pub struct Conn {
    pub base: String,
    pub via: Via,
    pub device_id: String,
}

pub enum LoginError {
    TwoFactor(Vec<String>),
    Msg(String),
}

pub fn normalize_server(s: &str) -> String {
    let s = s.trim().trim_end_matches('/');
    if s.starts_with("http://") || s.starts_with("https://") { s.to_string() } else { format!("https://{s}") }
}

impl Conn {
    fn std_headers(&self) -> Vec<(String, String)> {
        let (dtype, client, _) = env::device();
        vec![
            ("Accept".into(), "application/json".into()),
            ("Device-Type".into(), dtype.to_string()),
            ("Bitwarden-Client-Name".into(), client.into()),
            ("Bitwarden-Client-Version".into(), CLIENT_VERSION.into()),
        ]
    }

    pub async fn raw(&self, method: &str, path: &str, token: Option<&str>, body: Option<&Value>) -> Result<Resp, String> {
        let mut headers = self.std_headers();
        if let Some(t) = token {
            headers.push(("Authorization".into(), format!("Bearer {t}")));
        }
        if body.is_some() {
            headers.push(("Content-Type".into(), "application/json".into()));
        }
        send(
            Req { method, url: format!("{}{}", self.base, path), headers, body: body.map(|b| b.to_string()) },
            &self.via,
        )
        .await
    }

    pub async fn prelogin(&self, email: &str) -> Result<nrzpass_core::Kdf, String> {
        let body = json!({ "email": email });
        let mut r = self.raw("POST", "/identity/accounts/prelogin", None, Some(&body)).await?;
        if r.status == 404 {
            r = self.raw("POST", "/api/accounts/prelogin", None, Some(&body)).await?;
        }
        if !r.ok() {
            return Err(r.error());
        }
        let p: api::PreloginResponse = api::from_value_lenient(r.json()).map_err(|e| e.to_string())?;
        nrzpass_core::Kdf::from_api(p.kdf, Some(p.kdf_iterations), p.kdf_memory, p.kdf_parallelism)
            .map_err(|e| format!("Unsichere Server-Vorgabe abgelehnt: {e}"))
    }

    async fn token(&self, form: Vec<(&str, String)>, email: Option<&str>) -> Result<Resp, String> {
        let body = form
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, js_sys::encode_uri_component(&v)))
            .collect::<Vec<_>>()
            .join("&");
        let mut headers = self.std_headers();
        headers.push(("Content-Type".into(), "application/x-www-form-urlencoded; charset=utf-8".into()));
        if let Some(e) = email {
            headers.push(("Auth-Email".into(), b64url(e)));
        }
        send(Req { method: "POST", url: format!("{}/identity/connect/token", self.base), headers, body: Some(body) }, &self.via).await
    }

    pub async fn login(
        &self,
        email: &str,
        password_hash: &str,
        two_factor: Option<(String, i64, bool)>,
        remember_token: Option<String>,
    ) -> Result<TokenResponse, LoginError> {
        let (dtype, client, dname) = env::device();
        let mut form = vec![
            ("grant_type", "password".to_string()),
            ("username", email.to_string()),
            ("password", password_hash.to_string()),
            ("scope", "api offline_access".to_string()),
            ("client_id", client.to_string()),
            ("deviceType", dtype.to_string()),
            ("deviceIdentifier", self.device_id.clone()),
            ("deviceName", dname.to_string()),
        ];
        if let Some((code, provider, remember)) = two_factor {
            form.push(("twoFactorToken", code));
            form.push(("twoFactorProvider", provider.to_string()));
            form.push(("twoFactorRemember", if remember { "1" } else { "0" }.to_string()));
        } else if let Some(t) = remember_token {
            form.push(("twoFactorToken", t));
            form.push(("twoFactorProvider", "5".to_string()));
            form.push(("twoFactorRemember", "0".to_string()));
        }
        let r = self.token(form, Some(email)).await.map_err(LoginError::Msg)?;
        let v = api::normalize_keys(r.json());
        if r.ok() {
            return serde_json::from_value::<TokenResponse>(v).map_err(|e| LoginError::Msg(e.to_string()));
        }
        if let Some(p) = v.get("twoFactorProviders").and_then(Value::as_array) {
            let list = p.iter().map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())).collect();
            return Err(LoginError::TwoFactor(list));
        }
        Err(LoginError::Msg(r.error()))
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, String> {
        let (_, client, _) = env::device();
        let r = self
            .token(
                vec![
                    ("grant_type", "refresh_token".into()),
                    ("client_id", client.into()),
                    ("refresh_token", refresh_token.into()),
                ],
                None,
            )
            .await?;
        if !r.ok() {
            return Err(if r.status == 400 || r.status == 401 { "Sitzung abgelaufen – bitte neu anmelden".into() } else { r.error() });
        }
        serde_json::from_value(api::normalize_keys(r.json())).map_err(|e| e.to_string())
    }
}
