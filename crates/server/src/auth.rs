//! Anmeldung: Passwort-Hashes (Argon2id), Bearer-Tokens, Client-IP.

use crate::db::{self, int, text};
use crate::error::ApiError;
use crate::util::{now_ms, token_hash};
use crate::{p, St};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use std::net::SocketAddr;

fn argon() -> Argon2<'static> {
    // OWASP-Empfehlung: Argon2id, 19 MiB, 2 Durchlaeufe, 1 Thread
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(19456, 2, 1, None).expect("gueltige Parameter"))
}

/// Server-seitiger Hash des Master-Passwort-Hashes, den der Client schickt.
pub fn hash_password(client_hash: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut rand_core::OsRng);
    argon()
        .hash_password(client_hash.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Prueft in einem eigenen Thread (Argon2 blockiert sonst den Server).
pub async fn verify_password(client_hash: String, stored: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&stored).map(|h| argon().verify_password(client_hash.as_bytes(), &h).is_ok()).unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

pub async fn hash_password_async(client_hash: String) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || hash_password(&client_hash))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)
}

/// Prueft den Master-Passwort-Hash eines angemeldeten Benutzers.
pub async fn check_user_password(st: &St, user_id: &str, client_hash: &str) -> Result<(), ApiError> {
    let stored = {
        let c = st.db.lock().await;
        db::query_one(&c, "SELECT pw_hash FROM users WHERE id = ?1", p![user_id]).await?.map(|r| text(&r[0]))
    };
    let Some(stored) = stored else { return Err(ApiError::unauthorized()) };
    if verify_password(client_hash.to_string(), stored).await {
        Ok(())
    } else {
        Err(ApiError::bad("Das Master-Passwort ist falsch."))
    }
}

/// IP des Clients. `X-Forwarded-For` nur mit `TRUST_PROXY=1` (z. B. hinter dem umbrel-App-Proxy).
pub fn client_ip(st: &St, headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if st.cfg.trust_proxy {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            return ip;
        }
        if let Some(ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            return ip.trim().to_string();
        }
    }
    peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "unbekannt".into())
}

/// Angemeldeter Benutzer (aus `Authorization: Bearer …`).
#[derive(Debug, Clone)]
pub struct Auth {
    pub user_id: String,
    pub device_id: String,
    pub ip: String,
}

impl FromRequestParts<St> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &St) -> Result<Auth, ApiError> {
        let token = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
            .map(str::trim)
            .filter(|t| !t.is_empty() && t.len() <= 200)
            .ok_or_else(ApiError::unauthorized)?;
        let c = st.db.lock().await;
        let row = db::query_one(
            &c,
            "SELECT user_id, device_id, expires FROM access_tokens WHERE hash = ?1",
            p![token_hash(token)],
        )
        .await?
        .ok_or_else(ApiError::unauthorized)?;
        if int(&row[2]) < now_ms() {
            return Err(ApiError::unauthorized());
        }
        drop(c);
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
        Ok(Auth { user_id: text(&row[0]), device_id: text(&row[1]), ip: client_ip(st, &parts.headers, peer) })
    }
}

/// IP fuer Endpunkte ohne Anmeldung.
pub struct ClientIp(pub String);

impl FromRequestParts<St> for ClientIp {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, st: &St) -> Result<ClientIp, ApiError> {
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0);
        Ok(ClientIp(client_ip(st, &parts.headers, peer)))
    }
}

/// Bremst Brute-Force je IP (gleicher Topf wie `/identity/*`).
pub fn limit_ip(st: &St, ip: &str) -> Result<(), ApiError> {
    if st.ip_limit.check(ip) {
        Ok(())
    } else {
        Err(ApiError::too_many("Zu viele Anfragen. Bitte eine Minute warten."))
    }
}

/// Sicherheitsprotokoll.
pub async fn log_event(c: &turso::Connection, user_id: &str, kind: &str, ip: Option<&str>, device: Option<&str>) {
    let _ = db::exec(
        c,
        "INSERT INTO events (user_id, kind, ip, device, at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
        p![user_id, kind, ip.map(str::to_string), device.map(str::to_string), now_ms()],
    )
    .await;
}
