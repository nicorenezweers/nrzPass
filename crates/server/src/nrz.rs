//! nrzPass-Erweiterungen: Serverinfo, verknuepfte Konten (Vaultwarden), Sicherheitsprotokoll,
//! Geraete, Vaultwarden-Proxy und Downloads (macOS-App, Browser-Erweiterung).

use crate::auth::{log_event, Auth};
use crate::db::{self, int, opt_text, text};
use crate::error::{ApiError, ApiResult};
use crate::identity::{is_enc, revoke_device as revoke};
use crate::util::{iso, new_id, now_ms, valid_id};
use crate::{p, St};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::StreamExt;
use nrzpass_core::api::{self, LinkedAccountRequest, ServerInfo};
use serde_json::{json, Value};

pub async fn info(State(st): State<St>) -> ApiResult<Json<ServerInfo>> {
    let c = st.db.lock().await;
    let users = db::query_one(&c, "SELECT COUNT(*) FROM users", vec![]).await?.map(|r| int(&r[0])).unwrap_or(0);
    Ok(Json(ServerInfo {
        name: "nrzPass".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        signups_allowed: users == 0 || st.cfg.signups_allowed,
        has_users: users > 0,
    }))
}

// ---------------------------------------------------------------------------------------------
// Verknuepfte Konten
// ---------------------------------------------------------------------------------------------

fn linked_json(r: &db::Row) -> Value {
    json!({"id": text(&r[0]), "data": text(&r[1]), "revisionDate": iso(int(&r[2]))})
}

fn linked_data(body: Value) -> ApiResult<String> {
    let req: LinkedAccountRequest = api::from_value_lenient(body).map_err(|_| ApiError::bad("data fehlt."))?;
    if !is_enc(&req.data) || req.data.len() > 64 * 1024 {
        return Err(ApiError::bad("data muss verschluesselt sein."));
    }
    Ok(req.data)
}

pub async fn list_linked(State(st): State<St>, a: Auth) -> ApiResult<Json<Vec<Value>>> {
    let c = st.db.lock().await;
    let rows = db::query(&c, "SELECT id, data, revision_ms FROM linked_accounts WHERE user_id = ?1", p![a.user_id.as_str()]).await?;
    Ok(Json(rows.iter().map(linked_json).collect()))
}

pub async fn create_linked(State(st): State<St>, a: Auth, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let data = linked_data(body)?;
    let c = st.db.lock().await;
    let n = db::query_one(&c, "SELECT COUNT(*) FROM linked_accounts WHERE user_id = ?1", p![a.user_id.as_str()]).await?.map(|r| int(&r[0])).unwrap_or(0);
    if n >= 50 {
        return Err(ApiError::bad("Zu viele verknuepfte Konten."));
    }
    let id = new_id();
    let now = now_ms();
    db::exec(&c, "INSERT INTO linked_accounts (id, user_id, data, revision_ms) VALUES (?1, ?2, ?3, ?4)", p![id.as_str(), a.user_id.as_str(), data.as_str(), now]).await?;
    Ok(Json(json!({"id": id, "data": data, "revisionDate": iso(now)})))
}

pub async fn update_linked(State(st): State<St>, a: Auth, Path(id): Path<String>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let data = linked_data(body)?;
    if !valid_id(&id) {
        return Err(ApiError::not_found());
    }
    let c = st.db.lock().await;
    let now = now_ms();
    let n = db::exec(&c, "UPDATE linked_accounts SET data = ?1, revision_ms = ?2 WHERE id = ?3 AND user_id = ?4", p![data.as_str(), now, id.as_str(), a.user_id.as_str()]).await?;
    if n == 0 {
        return Err(ApiError::not_found());
    }
    Ok(Json(json!({"id": id, "data": data, "revisionDate": iso(now)})))
}

pub async fn delete_linked(State(st): State<St>, a: Auth, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let c = st.db.lock().await;
    let n = db::exec(&c, "DELETE FROM linked_accounts WHERE id = ?1 AND user_id = ?2", p![id.as_str(), a.user_id.as_str()]).await?;
    if n == 0 {
        return Err(ApiError::not_found());
    }
    Ok(Json(json!({})))
}

// ---------------------------------------------------------------------------------------------
// Sicherheitsprotokoll und Geraete
// ---------------------------------------------------------------------------------------------

pub async fn events(State(st): State<St>, a: Auth) -> ApiResult<Json<Vec<Value>>> {
    let c = st.db.lock().await;
    let rows = db::query(
        &c,
        "SELECT kind, ip, device, at_ms FROM events WHERE user_id = ?1 ORDER BY at_ms DESC, id DESC LIMIT 200",
        p![a.user_id.as_str()],
    )
    .await?;
    // Alte Eintraege aufraeumen (nur die letzten 1000 behalten)
    let _ = db::exec(
        &c,
        "DELETE FROM events WHERE user_id = ?1 AND id NOT IN (SELECT id FROM events WHERE user_id = ?1 ORDER BY id DESC LIMIT 1000)",
        p![a.user_id.as_str()],
    )
    .await;
    Ok(Json(
        rows.iter()
            .map(|r| json!({"kind": text(&r[0]), "ip": opt_text(&r[1]), "device": opt_text(&r[2]), "date": iso(int(&r[3]))}))
            .collect(),
    ))
}

pub async fn devices(State(st): State<St>, a: Auth) -> ApiResult<Json<Vec<Value>>> {
    let c = st.db.lock().await;
    let rows = db::query(
        &c,
        "SELECT id, name, dtype, created_ms, last_seen_ms FROM devices WHERE user_id = ?1 ORDER BY last_seen_ms DESC",
        p![a.user_id.as_str()],
    )
    .await?;
    Ok(Json(
        rows.iter()
            .map(|r| {
                json!({
                    "id": text(&r[0]),
                    "name": text(&r[1]),
                    "deviceType": int(&r[2]),
                    "created": iso(int(&r[3])),
                    "lastSeen": iso(int(&r[4])),
                    "current": text(&r[0]) == a.device_id,
                })
            })
            .collect(),
    ))
}

pub async fn revoke_device(State(st): State<St>, a: Auth, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let c = st.db.lock().await;
    let d = db::query_one(&c, "SELECT name FROM devices WHERE id = ?1 AND user_id = ?2", p![id.as_str(), a.user_id.as_str()])
        .await?
        .ok_or_else(ApiError::not_found)?;
    revoke(&c, &id).await?;
    log_event(&c, &a.user_id, "device_revoked", Some(&a.ip), Some(&text(&d[0]))).await;
    Ok(Json(json!({})))
}

// ---------------------------------------------------------------------------------------------
// Proxy zu Vaultwarden/Bitwarden (Vaultwarden erlaubt kein CORS fuer fremde Webseiten)
// ---------------------------------------------------------------------------------------------

const PROXY_HEADERS: &[&str] = &[
    "authorization", "content-type", "accept", "device-type", "bitwarden-client-name", "bitwarden-client-version", "auth-email",
];
const PROXY_MAX: usize = 20 * 1024 * 1024;

/// Erlaubt nur Bitwarden-API-Pfade auf http/https und keine Link-Local-/Metadaten-Adressen.
pub fn proxy_url_allowed(raw: &str) -> Result<url::Url, &'static str> {
    let u = url::Url::parse(raw).map_err(|_| "Ungueltige Adresse.")?;
    if u.scheme() != "https" && u.scheme() != "http" {
        return Err("Nur http und https sind erlaubt.");
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("Zugangsdaten in der Adresse sind nicht erlaubt.");
    }
    let path = u.path();
    if !(path.contains("/identity/") || path.contains("/api/") || path.ends_with("/alive")) {
        return Err("Nur Bitwarden-API-Pfade (/api/, /identity/) sind erlaubt.");
    }
    match u.host() {
        None => return Err("Host fehlt."),
        Some(url::Host::Ipv4(ip)) if ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() => {
            return Err("Diese Adresse ist nicht erlaubt.")
        }
        Some(url::Host::Ipv6(ip)) if ip.is_unspecified() || ip.is_multicast() || (ip.segments()[0] & 0xffc0) == 0xfe80 => {
            return Err("Diese Adresse ist nicht erlaubt.")
        }
        Some(url::Host::Domain(d)) if d.eq_ignore_ascii_case("metadata.google.internal") => return Err("Diese Adresse ist nicht erlaubt."),
        _ => {}
    }
    Ok(u)
}

pub async fn proxy(State(st): State<St>, a: Auth, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    if !st.cfg.proxy_enabled {
        return Err(ApiError::forbidden("Der Proxy ist auf diesem Server ausgeschaltet."));
    }
    if !st.proxy_limit.check(&a.user_id) {
        return Err(ApiError::too_many("Zu viele Proxy-Anfragen."));
    }
    let url = proxy_url_allowed(body.get("url").and_then(Value::as_str).unwrap_or("")).map_err(ApiError::bad)?;
    let method = match body.get("method").and_then(Value::as_str).unwrap_or("GET").to_uppercase().as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        _ => return Err(ApiError::bad("Methode nicht erlaubt.")),
    };
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(Value::Object(h)) = body.get("headers") {
        for (k, v) in h {
            let lk = k.to_lowercase();
            if !PROXY_HEADERS.contains(&lk.as_str()) {
                continue;
            }
            if let (Ok(n), Some(Ok(v))) = (HeaderName::from_bytes(lk.as_bytes()), v.as_str().map(HeaderValue::from_str)) {
                headers.insert(n, v);
            }
        }
    }
    let mut req = st.http.request(method, url).headers(headers);
    if let Some(b) = body.get("body").and_then(Value::as_str) {
        req = req.body(b.to_string());
    }
    let resp = req.send().await.map_err(|e| {
        ApiError::new(StatusCode::BAD_GATEWAY, &format!("Server nicht erreichbar: {}", e.without_url()))
    })?;
    let status = resp.status().as_u16();
    let mut buf = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "Antwort abgebrochen."))?;
        if buf.len() + chunk.len() > PROXY_MAX {
            return Err(ApiError::new(StatusCode::BAD_GATEWAY, "Antwort ist zu gross."));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Json(json!({"status": status, "body": String::from_utf8_lossy(&buf)})))
}

// ---------------------------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------------------------

fn safe_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 120
        && !n.starts_with('.')
        && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

pub async fn list_downloads(State(st): State<St>) -> ApiResult<Json<Vec<Value>>> {
    let mut out = Vec::new();
    if let Ok(mut rd) = tokio::fs::read_dir(&st.cfg.download_dir).await {
        while let Ok(Some(e)) = rd.next_entry().await {
            let name = e.file_name().to_string_lossy().to_string();
            if !safe_name(&name) {
                continue;
            }
            if let Ok(m) = e.metadata().await {
                if m.is_file() {
                    out.push(json!({"name": name, "size": m.len()}));
                }
            }
        }
    }
    out.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(Json(out))
}

pub async fn download(State(st): State<St>, Path(file): Path<String>) -> Response {
    if !safe_name(&file) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = st.cfg.download_dir.join(&file);
    let Ok(f) = tokio::fs::File::open(&path).await else { return StatusCode::NOT_FOUND.into_response() };
    let Ok(meta) = f.metadata().await else { return StatusCode::NOT_FOUND.into_response() };
    if !meta.is_file() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mime = mime_guess::from_path(&path).first_or_octet_stream();
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_str(mime.as_ref()).unwrap_or(HeaderValue::from_static("application/octet-stream")));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(meta.len()));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{file}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    (h, Body::from_stream(tokio_util::io::ReaderStream::new(f))).into_response()
}
