//! Hintergrund-Dienst (MV3 Service Worker bzw. Firefox-Hintergrundskript).
//!
//! Sicherheitsregeln:
//! * Anfragen von Inhaltsskripten bekommen nur Daten, die zur Adresse des anfragenden
//!   Frames (`sender.url`, vom Browser gesetzt – nicht von der Seite) passen.
//! * Passwoerter gehen erst beim Klick auf einen Vorschlag an die Seite (`get_fill`),
//!   und auch dann wird der Abgleich erneut geprueft.
//! * Eintraege mit "Master-Passwort abfragen" werden nie automatisch ausgefuellt.
//! * Schluessel und Index liegen nur in `storage.session` (Arbeitsspeicher) und werden bei
//!   Inaktivitaet (Auto-Sperre) geloescht.
//! * Passwoerter und TOTP-Schluessel stehen im Index nur verschluesselt (Sitzungsschluessel
//!   `indexKey`) und werden erst beim Ausfuellen bzw. Vergleichen kurz entschluesselt.

use crate::ext::{self, Area, INDEX, KEYS, LAST_USED, NEVER, SESSION};
use crate::logic::{self, Decision, IndexItem};
use nrzpass_core::api::{self, Cipher, CipherLogin, LoginUri, TokenResponse};
use nrzpass_core::vault::{self, KeyRing};
use nrzpass_core::SymmetricKey;
use zeroize::{Zeroize, Zeroizing};
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

const ALARM: &str = "nrzpass-autolock";
const PENDING_TTL_MS: f64 = 10.0 * 60_000.0;

#[wasm_bindgen]
pub fn bg_init() {
    if let Some(alarms) = ext::path(&["alarms"]) {
        let _ = ext::call(&alarms, "create", &[JsValue::from_str(ALARM), ext::obj(&[("periodInMinutes", JsValue::from(1))])]);
    }
    if let Some(action) = action() {
        let _ = ext::call(&action, "setBadgeBackgroundColor", &[ext::obj(&[("color", JsValue::from_str("#3f3f46"))])]);
    }
}

fn action() -> Option<JsValue> {
    ext::path(&["action"]).or_else(|| ext::path(&["browserAction"]))
}

fn is_firefox() -> bool {
    ext::path(&["runtime"])
        .and_then(|rt| ext::call(&rt, "getURL", &[JsValue::from_str("")]).ok())
        .and_then(|u| u.as_string())
        .map(|u| u.starts_with("moz-extension:"))
        .unwrap_or(false)
}

fn own_url_prefix() -> String {
    ext::path(&["runtime"])
        .and_then(|rt| ext::call(&rt, "getURL", &[JsValue::from_str("")]).ok())
        .and_then(|u| u.as_string())
        .unwrap_or_default()
}

async fn index() -> Option<Vec<IndexItem>> {
    let s = ext::store_get(Area::Session, INDEX).await?;
    Some(logic::parse_index(&s))
}

async fn keys() -> Option<Value> {
    let s = ext::store_get(Area::Session, KEYS).await?;
    serde_json::from_str::<Value>(&s).ok().filter(|v| v["userKey"].is_string())
}

/// Sitzungsschluessel, mit dem Passwoerter/TOTP-Schluessel im Index verschluesselt sind.
async fn index_key() -> Option<SymmetricKey> {
    keys().await.and_then(|k| SymmetricKey::from_b64(k["indexKey"].as_str()?).ok())
}

fn open(key: &SymmetricKey, v: Option<&str>) -> Option<Zeroizing<String>> {
    let enc = v.filter(|v| !v.is_empty())?.parse().ok()?;
    key.decrypt_str(&enc).ok().map(Zeroizing::new)
}

fn seal(key: &SymmetricKey, v: Option<&str>) -> Option<String> {
    v.filter(|v| !v.is_empty()).map(|v| key.encrypt_str(v).to_string())
}

async fn touch() {
    ext::store_set(Area::Session, LAST_USED, &ext::now_ms().to_string()).await;
}

async fn never_list() -> Vec<String> {
    ext::store_get(Area::Local, NEVER).await.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn now_secs() -> u64 {
    (ext::now_ms() / 1000.0) as u64
}

fn now_iso() -> String {
    js_sys::Date::new_0().to_iso_string().as_string().unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// Nachrichten
// ---------------------------------------------------------------------------------------------

#[wasm_bindgen]
pub async fn bg_message(msg: JsValue, sender: JsValue) -> Result<JsValue, JsValue> {
    let msg = ext::from_js(&msg);
    let sender = ext::from_js(&sender);
    let frame_url = sender["url"].as_str().unwrap_or("").to_string();
    let tab_id = sender.pointer("/tab/id").and_then(Value::as_i64);
    let from_extension_page = !frame_url.is_empty() && frame_url.starts_with(&own_url_prefix());
    let out = match msg["type"].as_str().unwrap_or("") {
        "status" => json!({ "locked": keys().await.is_none() }),
        "get_logins" => get_logins(&frame_url).await,
        "get_fill" => get_fill(&frame_url, msg["key"].as_str().unwrap_or("")).await,
        "generate" => json!({ "password": nrzpass_core::generator::suggest() }),
        "remember_login" => {
            remember(&frame_url, tab_id, msg["username"].as_str().unwrap_or(""), msg["password"].as_str().unwrap_or("")).await
        }
        "get_pending" => get_pending(&frame_url, tab_id).await,
        "save_pending" => match save_pending(&frame_url, tab_id).await {
            Ok(()) => json!({ "ok": true }),
            Err(e) => json!({ "error": e }),
        },
        "dismiss_pending" => {
            clear_pending(tab_id).await;
            json!({ "ok": true })
        }
        "never_pending" => {
            let host = nrzpass_core::url::site_key(&frame_url);
            let mut list = never_list().await;
            if !host.is_empty() && !list.contains(&host) {
                list.push(host);
                ext::store_set(Area::Local, NEVER, &serde_json::to_string(&list).unwrap_or_default()).await;
            }
            clear_pending(tab_id).await;
            json!({ "ok": true })
        }
        "unlocked" if from_extension_page => {
            touch().await;
            refresh_badges().await;
            json!({ "ok": true })
        }
        "locked" if from_extension_page => {
            lock().await;
            json!({ "ok": true })
        }
        _ => Value::Null,
    };
    Ok(ext::to_js(&out))
}

async fn get_logins(frame_url: &str) -> Value {
    let Some(idx) = index().await else { return json!({ "locked": true, "items": [] }) };
    let items: Vec<Value> = logic::matching(&idx, frame_url)
        .into_iter()
        .map(|i| json!({ "key": i.key, "name": i.name, "username": i.username.clone().unwrap_or_default() }))
        .collect();
    json!({ "locked": false, "items": items })
}

async fn get_fill(frame_url: &str, key: &str) -> Value {
    let Some(idx) = index().await else { return json!({ "error": "nrzPass ist gesperrt" }) };
    let Some(item) = idx.iter().find(|i| i.key == key) else { return json!({ "error": "Eintrag nicht gefunden" }) };
    if !item.matches(frame_url) {
        return json!({ "error": "Dieser Eintrag gehört nicht zu dieser Seite" });
    }
    if item.reprompt == 1 {
        return json!({ "error": "Dieser Eintrag verlangt das Master-Passwort – bitte über das nrzPass-Symbol ausfüllen" });
    }
    let Some(ik) = index_key().await else { return json!({ "error": "nrzPass ist gesperrt" }) };
    touch().await;
    let password = open(&ik, item.password.as_deref());
    let totp = open(&ik, item.totp.as_deref())
        .and_then(|t| nrzpass_core::totp::Totp::parse(&t))
        .map(|t| t.code_at(now_secs()));
    json!({ "username": item.username, "password": password.as_deref().map(|p| p.as_str()), "totp": totp })
}

fn pending_key(tab: i64) -> String {
    format!("nrzpass.pending.{tab}")
}

fn hint_key(tab: i64) -> String {
    format!("nrzpass.hint.{tab}")
}

async fn remember(frame_url: &str, tab: Option<i64>, username: &str, password: &str) -> Value {
    let Some(tab) = tab else { return json!({ "action": "none" }) };
    let base = nrzpass_core::url::site_key(frame_url);
    // Mehrstufige Anmeldung: erst nur der Benutzername
    if password.is_empty() {
        if !username.trim().is_empty() {
            let h = json!({ "username": username.trim(), "base": base, "ts": ext::now_ms() });
            ext::store_set(Area::Session, &hint_key(tab), &h.to_string()).await;
        }
        return json!({ "action": "none" });
    }
    let mut username = username.trim().to_string();
    if username.is_empty() {
        if let Some(h) = ext::store_get(Area::Session, &hint_key(tab)).await.and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
            if h["base"].as_str() == Some(base.as_str()) && ext::now_ms() - h["ts"].as_f64().unwrap_or(0.0) < PENDING_TTL_MS {
                username = h["username"].as_str().unwrap_or("").to_string();
            }
        }
    }
    let (Some(idx), Some(ik)) = (index().await, index_key().await) else { return json!({ "action": "none", "locked": true }) };
    // Nur die passenden Kandidaten kurz entschluesseln, vergleichen und wieder ueberschreiben
    let mut cands: Vec<IndexItem> = logic::matching(&idx, frame_url).into_iter().cloned().collect();
    for c in cands.iter_mut() {
        c.password = open(&ik, c.password.as_deref()).map(|p| p.to_string());
    }
    let decision = logic::decide(&cands, frame_url, &username, password, &never_list().await);
    for c in cands.iter_mut() {
        if let Some(p) = c.password.as_mut() {
            p.zeroize();
        }
    }
    let (action, key) = match &decision {
        Decision::None => return json!({ "action": "none" }),
        Decision::New => ("new", None),
        Decision::Update { key } => ("update", Some(key.clone())),
    };
    let pending = json!({
        "action": action, "key": key, "url": frame_url, "host": logic::entry_name(frame_url),
        "username": username, "password": seal(&ik, Some(password)), "ts": ext::now_ms(),
    });
    ext::store_set(Area::Session, &pending_key(tab), &pending.to_string()).await;
    json!({ "action": action, "host": logic::entry_name(frame_url), "username": username })
}

async fn load_pending(tab: Option<i64>) -> Option<Value> {
    let tab = tab?;
    let p: Value = serde_json::from_str(&ext::store_get(Area::Session, &pending_key(tab)).await?).ok()?;
    if ext::now_ms() - p["ts"].as_f64().unwrap_or(0.0) > PENDING_TTL_MS {
        clear_pending(Some(tab)).await;
        return None;
    }
    Some(p)
}

async fn clear_pending(tab: Option<i64>) {
    if let Some(t) = tab {
        ext::store_remove(Area::Session, &[&pending_key(t), &hint_key(t)]).await;
    }
}

async fn get_pending(frame_url: &str, tab: Option<i64>) -> Value {
    let Some(p) = load_pending(tab).await else { return json!({ "pending": null }) };
    let base = |u: &str| nrzpass_core::url::site_key(u);
    if base(p["url"].as_str().unwrap_or("")) != base(frame_url) {
        return json!({ "pending": null });
    }
    json!({ "pending": { "action": p["action"], "host": p["host"], "username": p["username"] } })
}

// ---------------------------------------------------------------------------------------------
// Speichern auf dem nrzPass-Server
// ---------------------------------------------------------------------------------------------

async fn save_pending(frame_url: &str, tab: Option<i64>) -> Result<(), String> {
    let p = load_pending(tab).await.ok_or("Nichts zu speichern")?;
    let base = |u: &str| nrzpass_core::url::site_key(u);
    if base(p["url"].as_str().unwrap_or("")) != base(frame_url) {
        return Err("Gehört nicht zu dieser Seite".into());
    }
    let k = keys().await.ok_or("nrzPass ist gesperrt – bitte über das Symbol entsperren")?;
    let user_key = SymmetricKey::from_b64(k["userKey"].as_str().unwrap_or("")).map_err(|_| "Schlüssel ungültig")?;
    let ik = index_key().await.ok_or("nrzPass ist gesperrt – bitte über das Symbol entsperren")?;
    let ring = KeyRing::new(user_key);
    let url = p["url"].as_str().unwrap_or("").to_string();
    let username = p["username"].as_str().unwrap_or("").to_string();
    let password = open(&ik, p["password"].as_str()).ok_or("Nichts zu speichern")?;
    let password: &str = password.as_str();
    let saved: Cipher = match p["action"].as_str() {
        Some("update") => {
            let key = p["key"].as_str().unwrap_or("");
            let id = key.strip_prefix("nrz:").ok_or("Nur Einträge im nrzPass-Tresor lassen sich ändern")?;
            let enc: Cipher = api::from_value_lenient(authed("GET", &format!("/api/ciphers/{id}"), None).await?).map_err(|e| e.to_string())?;
            let mut plain = vault::decrypt_cipher(&ring, &enc).map_err(|e| e.to_string())?;
            vault::set_password(&mut plain, password, &now_iso());
            let req = vault::encrypt_cipher(&ring, &plain).map_err(|e| e.to_string());
            vault::wipe_secrets(&mut plain);
            let req = req?;
            let body = serde_json::to_value(&req).map_err(|e| e.to_string())?;
            api::from_value_lenient(authed("PUT", &format!("/api/ciphers/{id}"), Some(body)).await?).map_err(|e| e.to_string())?
        }
        _ => {
            let plain = Cipher {
                cipher_type: api::cipher_type::LOGIN,
                name: Some(logic::entry_name(&url)),
                login: Some(CipherLogin {
                    username: Some(username).filter(|u| !u.is_empty()),
                    password: Some(password.to_string()),
                    uris: Some(vec![LoginUri { uri: Some(logic::origin_of(&url)), ..Default::default() }]),
                    ..Default::default()
                }),
                edit: true,
                ..Default::default()
            };
            let mut plain = plain;
            let req = vault::encrypt_cipher(&ring, &plain).map_err(|e| e.to_string());
            vault::wipe_secrets(&mut plain);
            let req = req?;
            let body = serde_json::to_value(&req).map_err(|e| e.to_string())?;
            api::from_value_lenient(authed("POST", "/api/ciphers", Some(body)).await?).map_err(|e| e.to_string())?
        }
    };
    // Index sofort aktualisieren, damit Ausfuellen ohne neues Synchronisieren klappt
    let dec = vault::reveal(&ring, &vault::decrypt_listing(&ring, &saved).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let login = dec.login.clone().unwrap_or_default();
    let item = IndexItem {
        key: format!("nrz:{}", dec.id),
        name: dec.name.clone().unwrap_or_default(),
        username: login.username.clone(),
        password: seal(&ik, login.password.as_deref()),
        totp: seal(&ik, login.totp.as_deref()),
        uris: login.uris.clone().unwrap_or_default().into_iter().filter_map(|u| Some((u.uri?, u.match_type))).collect(),
        reprompt: dec.reprompt,
    };
    let mut login = login;
    for v in [&mut login.password, &mut login.totp].into_iter().flatten() {
        v.zeroize();
    }
    drop(dec);
    let mut idx = index().await.unwrap_or_default();
    idx.retain(|i| i.key != item.key);
    idx.push(item);
    ext::store_set(Area::Session, INDEX, &serde_json::to_string(&idx).unwrap_or_default()).await;
    clear_pending(tab).await;
    touch().await;
    refresh_badges().await;
    Ok(())
}

async fn http(method: &str, url: &str, headers: &[(&str, String)], body: Option<String>) -> Result<(u16, String), String> {
    let init = web_sys::RequestInit::new();
    init.set_method(method);
    init.set_credentials(web_sys::RequestCredentials::Omit);
    init.set_cache(web_sys::RequestCache::NoStore);
    let h = web_sys::Headers::new().map_err(ext::err_str)?;
    for (k, v) in headers {
        h.set(k, v).map_err(ext::err_str)?;
    }
    init.set_headers(&h);
    if let Some(b) = &body {
        init.set_body(&JsValue::from_str(b));
    }
    let req = web_sys::Request::new_with_str_and_init(url, &init).map_err(ext::err_str)?;
    let resp = ext::promise(ext::call(&ext::global(), "fetch", &[req.into()]).map_err(ext::err_str)?)
        .await
        .map_err(|_| "nrzPass-Server nicht erreichbar".to_string())?;
    let resp: web_sys::Response = resp.dyn_into().map_err(|_| "Antwort ungültig".to_string())?;
    let text = ext::promise(resp.text().map_err(ext::err_str)?.into()).await.map_err(ext::err_str)?;
    Ok((resp.status(), text.as_string().unwrap_or_default()))
}

fn std_headers() -> Vec<(&'static str, String)> {
    vec![
        ("Accept", "application/json".into()),
        ("Device-Type", if is_firefox() { "3" } else { "2" }.into()),
        ("Bitwarden-Client-Name", "browser".into()),
        ("Bitwarden-Client-Version", "2025.1.0".into()),
    ]
}

/// Neues Zugangstoken holen und in Sitzung (nrzpass.keys) und gespeicherter Anmeldung
/// (nrzpass.session, verschluesselt) ablegen – sonst wuerde ein rotiertes Refresh-Token im
/// Popup veralten und der Server das Geraet als gestohlen abmelden.
async fn refresh(k: &mut Value) -> Result<(), String> {
    let server = k["server"].as_str().unwrap_or("").trim_end_matches('/').to_string();
    let refresh = k.pointer("/tokens/refresh").and_then(Value::as_str).unwrap_or("").to_string();
    if refresh.is_empty() {
        return Err("Sitzung abgelaufen – bitte nrzPass öffnen".into());
    }
    let body = format!(
        "grant_type=refresh_token&client_id=browser&refresh_token={}",
        js_sys::encode_uri_component(&refresh)
    );
    let mut h = std_headers();
    h.push(("Content-Type", "application/x-www-form-urlencoded; charset=utf-8".into()));
    let (status, text) = http("POST", &format!("{server}/identity/connect/token"), &h, Some(body)).await?;
    if !(200..300).contains(&status) {
        return Err("Sitzung abgelaufen – bitte nrzPass öffnen und neu anmelden".into());
    }
    let t: TokenResponse = serde_json::from_value(api::normalize_keys(serde_json::from_str(&text).unwrap_or(Value::Null)))
        .map_err(|e| e.to_string())?;
    let tokens = json!({
        "access": t.access_token,
        "refresh": t.refresh_token.clone().filter(|r| !r.is_empty()).unwrap_or(refresh),
        "expiresAt": ext::now_ms() + (t.expires_in.max(60) as f64 - 30.0) * 1000.0,
    });
    k["tokens"] = tokens.clone();
    ext::store_set(Area::Session, KEYS, &k.to_string()).await;
    if let (Some(s), Ok(uk)) = (ext::store_get(Area::Local, SESSION).await, SymmetricKey::from_b64(k["userKey"].as_str().unwrap_or(""))) {
        if let Ok(mut sess) = serde_json::from_str::<Value>(&s) {
            sess["tokens"] = Value::String(uk.encrypt_str(&tokens.to_string()).to_string());
            ext::store_set(Area::Local, SESSION, &sess.to_string()).await;
        }
    }
    Ok(())
}

async fn authed(method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
    let mut k = keys().await.ok_or("nrzPass ist gesperrt")?;
    let server = k["server"].as_str().unwrap_or("").trim_end_matches('/').to_string();
    if server.is_empty() {
        return Err("Kein Server bekannt – bitte nrzPass öffnen".into());
    }
    if k.pointer("/tokens/expiresAt").and_then(Value::as_f64).unwrap_or(0.0) < ext::now_ms() {
        refresh(&mut k).await?;
    }
    for attempt in 0..2 {
        let mut h = std_headers();
        h.push(("Authorization", format!("Bearer {}", k.pointer("/tokens/access").and_then(Value::as_str).unwrap_or(""))));
        if body.is_some() {
            h.push(("Content-Type", "application/json".into()));
        }
        let (status, text) = http(method, &format!("{server}{path}"), &h, body.as_ref().map(|b| b.to_string())).await?;
        if status == 401 && attempt == 0 {
            refresh(&mut k).await?;
            continue;
        }
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if !(200..300).contains(&status) {
            return Err(api::error_message(&v).unwrap_or_else(|| format!("Serverfehler ({status})")));
        }
        return Ok(v);
    }
    Err("Sitzung abgelaufen".into())
}

// ---------------------------------------------------------------------------------------------
// Sperre, Badge, Alarme
// ---------------------------------------------------------------------------------------------

async fn lock() {
    ext::store_remove(Area::Session, &[KEYS, INDEX, LAST_USED]).await;
    clear_badges().await;
}

#[wasm_bindgen]
pub async fn bg_alarm(name: String) {
    if name != ALARM {
        return;
    }
    let Some(k) = keys().await else { return };
    let minutes = k["autoLockMinutes"].as_f64().unwrap_or(15.0);
    if minutes <= 0.0 {
        return;
    }
    let last: f64 = ext::store_get(Area::Session, LAST_USED).await.and_then(|s| s.parse().ok()).unwrap_or_else(ext::now_ms);
    if ext::now_ms() - last > minutes * 60_000.0 {
        lock().await;
    }
}

async fn set_badge(tab_id: i64, text: &str) {
    if let Some(a) = action() {
        if let Ok(p) = ext::call(&a, "setBadgeText", &[ext::obj(&[("tabId", JsValue::from(tab_id as f64)), ("text", JsValue::from_str(text))])]) {
            let _ = ext::promise(p).await;
        }
    }
}

async fn badge_for(tab_id: i64, url: &str, idx: &Option<Vec<IndexItem>>) {
    let text = match idx {
        Some(i) => {
            let n = logic::matching(i, url).len();
            if n == 0 { String::new() } else { n.to_string() }
        }
        None => String::new(),
    };
    set_badge(tab_id, &text).await;
}

#[wasm_bindgen]
pub async fn bg_tab(tab_id: i32) {
    let Some(tabs) = ext::path(&["tabs"]) else { return };
    let Ok(p) = ext::call(&tabs, "get", &[JsValue::from(tab_id)]) else { return };
    let Ok(tab) = ext::promise(p).await else { return };
    let url = ext::get(&tab, "url").and_then(|u| u.as_string()).unwrap_or_default();
    badge_for(tab_id as i64, &url, &index().await).await;
}

async fn all_tabs(active_only: bool) -> Vec<(i64, String)> {
    let Some(tabs) = ext::path(&["tabs"]) else { return vec![] };
    let q = if active_only { ext::obj(&[("active", JsValue::TRUE)]) } else { ext::obj(&[]) };
    let Ok(p) = ext::call(&tabs, "query", &[q]) else { return vec![] };
    let list = ext::from_js(&ext::promise(p).await.unwrap_or(JsValue::NULL));
    list.as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| Some((t["id"].as_i64()?, t["url"].as_str().unwrap_or("").to_string())))
        .collect()
}

async fn refresh_badges() {
    let idx = index().await;
    for (id, url) in all_tabs(true).await {
        badge_for(id, &url, &idx).await;
    }
}

async fn clear_badges() {
    for (id, _) in all_tabs(false).await {
        set_badge(id, "").await;
    }
}
