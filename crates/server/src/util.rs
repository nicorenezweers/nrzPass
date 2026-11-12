//! Zeit, Zufall, Hilfsantworten.

use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// ISO-8601 mit Millisekunden in UTC, wie Bitwarden.
pub fn iso(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

pub fn parse_iso_ms(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.timestamp_millis())
}

/// Zufaelliges Token (32 Byte, Base64url).
pub fn random_token() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    B64URL.encode(b)
}

/// Tokens werden nur als SHA-256 gespeichert.
pub fn token_hash(t: &str) -> String {
    Sha256::digest(t.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn valid_id(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok()
}

pub async fn alive() -> Json<Value> {
    Json(json!(iso(now_ms())))
}

pub async fn version() -> Json<Value> {
    Json(json!("2025.1.0"))
}

pub async fn bw_config() -> Json<Value> {
    Json(json!({
        "version": "2025.1.0",
        "gitHash": "nrzpass",
        "server": {"name": "nrzPass", "url": "https://nrzgit/nicorenezweers/nrzPass"},
        "environment": {"vault": null, "api": null, "identity": null, "notifications": null, "sso": null},
        "featureStates": {},
        "object": "config"
    }))
}
