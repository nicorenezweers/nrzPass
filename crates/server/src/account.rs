//! Konto: Sync, Profil, Master-Passwort, Konto loeschen, Zwei-Faktor (TOTP).

use crate::auth::{self, log_event, Auth};
use crate::ciphers::{cipher_json, folder_json, CIPHER_COLS};
use crate::db::{self, int, opt_text, text};
use crate::error::{ApiError, ApiResult};
use crate::identity::{is_enc, revoke_device, verify_totp_step};
use crate::util::{iso, new_id, now_ms};
use crate::{p, St};
use axum::extract::State;
use axum::Json;
use nrzpass_core::api::{self, AuthenticatorRequest, ChangePasswordRequest, PasswordVerify};
use nrzpass_core::crypto::Kdf;
use serde_json::{json, Value};

async fn profile_json(c: &turso::Connection, user_id: &str) -> ApiResult<Value> {
    let r = db::query_one(
        c,
        "SELECT id, email, name, hint, akey, private_key, security_stamp, totp_secret, created_ms FROM users WHERE id = ?1",
        p![user_id],
    )
    .await?
    .ok_or_else(ApiError::unauthorized)?;
    Ok(json!({
        "id": text(&r[0]),
        "name": opt_text(&r[2]),
        "email": text(&r[1]),
        "emailVerified": true,
        "premium": true,
        "premiumFromOrganization": false,
        "masterPasswordHint": opt_text(&r[3]),
        "culture": "de-DE",
        "twoFactorEnabled": opt_text(&r[7]).is_some(),
        "key": text(&r[4]),
        "privateKey": opt_text(&r[5]),
        "securityStamp": text(&r[6]),
        "forcePasswordReset": false,
        "usesKeyConnector": false,
        "avatarColor": null,
        "creationDate": iso(int(&r[8])),
        "organizations": [],
        "providers": [],
        "providerOrganizations": [],
        "object": "profile"
    }))
}

pub async fn sync(State(st): State<St>, a: Auth) -> ApiResult<Json<Value>> {
    let c = st.db.lock().await;
    let profile = profile_json(&c, &a.user_id).await?;
    let folders: Vec<Value> = db::query(&c, "SELECT id, name, revision_ms FROM folders WHERE user_id = ?1", p![a.user_id.as_str()])
        .await?
        .iter()
        .map(folder_json)
        .collect();
    let ciphers: Vec<Value> = db::query(&c, &format!("SELECT {CIPHER_COLS} FROM ciphers WHERE user_id = ?1"), p![a.user_id.as_str()])
        .await?
        .iter()
        .map(cipher_json)
        .collect();
    let _ = db::exec(&c, "UPDATE devices SET last_seen_ms = ?1 WHERE id = ?2", p![now_ms(), a.device_id.as_str()]).await;
    Ok(Json(json!({
        "profile": profile,
        "folders": folders,
        "ciphers": ciphers,
        "collections": [],
        "policies": [],
        "sends": [],
        "domains": null,
        "object": "sync"
    })))
}

pub async fn profile(State(st): State<St>, a: Auth) -> ApiResult<Json<Value>> {
    let c = st.db.lock().await;
    Ok(Json(profile_json(&c, &a.user_id).await?))
}

pub async fn update_profile(State(st): State<St>, a: Auth, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let body = api::normalize_keys(body);
    let name: Option<String> = body.get("name").and_then(Value::as_str).map(|n| n.trim().chars().take(100).collect());
    let hint: Option<String> = body.get("masterPasswordHint").and_then(Value::as_str).map(|n| n.trim().chars().take(200).collect());
    let c = st.db.lock().await;
    db::exec(&c, "UPDATE users SET name = ?1, revision_ms = ?2 WHERE id = ?3", p![name, now_ms(), a.user_id.as_str()]).await?;
    if body.get("masterPasswordHint").is_some() {
        db::exec(&c, "UPDATE users SET hint = ?1 WHERE id = ?2", p![hint.filter(|h| !h.is_empty()), a.user_id.as_str()]).await?;
    }
    Ok(Json(profile_json(&c, &a.user_id).await?))
}

pub async fn revision_date(State(st): State<St>, a: Auth) -> ApiResult<Json<Value>> {
    let c = st.db.lock().await;
    let r = db::query_one(&c, "SELECT revision_ms FROM users WHERE id = ?1", p![a.user_id.as_str()]).await?.ok_or_else(ApiError::unauthorized)?;
    Ok(Json(json!(int(&r[0]))))
}

pub async fn bump_revision(c: &turso::Connection, user_id: &str) -> turso::Result<()> {
    db::exec(c, "UPDATE users SET revision_ms = ?1 WHERE id = ?2", p![now_ms(), user_id]).await.map(|_| ())
}

fn lenient<T: serde::de::DeserializeOwned>(v: Value) -> ApiResult<T> {
    api::from_value_lenient(v).map_err(|e| ApiError::bad(&format!("Ungueltige Anfrage: {e}")))
}

pub async fn change_password(State(st): State<St>, a: Auth, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    auth::limit_ip(&st, &a.ip)?;
    let req: ChangePasswordRequest = lenient(body)?;
    auth::check_user_password(&st, &a.user_id, &req.master_password_hash).await?;
    if !is_enc(&req.key) {
        return Err(ApiError::bad("Ungueltiger Kontoschluessel."));
    }
    let kdf = match req.kdf {
        Some(k) => Some(
            Kdf::from_api(k, req.kdf_iterations, req.kdf_memory, req.kdf_parallelism).map_err(|e| ApiError::bad(&e.to_string()))?,
        ),
        None => None,
    };
    let new_hash = auth::hash_password_async(req.new_master_password_hash).await?;
    let c = st.db.lock().await;
    db::exec(
        &c,
        "UPDATE users SET pw_hash = ?1, akey = ?2, security_stamp = ?3, revision_ms = ?4 WHERE id = ?5",
        p![new_hash, req.key, new_id(), now_ms(), a.user_id.as_str()],
    )
    .await?;
    if let Some(hint) = req.master_password_hint {
        let hint: String = hint.trim().chars().take(200).collect();
        db::exec(&c, "UPDATE users SET hint = ?1 WHERE id = ?2", p![(!hint.is_empty()).then_some(hint), a.user_id.as_str()]).await?;
    }
    if let Some(k) = kdf {
        db::exec(
            &c,
            "UPDATE users SET kdf = ?1, kdf_iter = ?2, kdf_mem = ?3, kdf_par = ?4 WHERE id = ?5",
            p![k.kind(), k.iterations(), k.memory(), k.parallelism(), a.user_id.as_str()],
        )
        .await?;
    }
    // Alle Geraete abmelden – auch dieses
    for d in db::query(&c, "SELECT id FROM devices WHERE user_id = ?1", p![a.user_id.as_str()]).await? {
        revoke_device(&c, &text(&d[0])).await?;
    }
    db::exec(&c, "DELETE FROM access_tokens WHERE user_id = ?1", p![a.user_id.as_str()]).await?;
    log_event(&c, &a.user_id, "password_changed", Some(&a.ip), None).await;
    Ok(Json(json!({})))
}

pub async fn verify_password(State(st): State<St>, a: Auth, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    auth::limit_ip(&st, &a.ip)?;
    let req: PasswordVerify = lenient(body)?;
    auth::check_user_password(&st, &a.user_id, &req.master_password_hash).await?;
    Ok(Json(json!({})))
}

pub async fn delete_account(State(st): State<St>, a: Auth, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    auth::limit_ip(&st, &a.ip)?;
    let req: PasswordVerify = lenient(body)?;
    auth::check_user_password(&st, &a.user_id, &req.master_password_hash).await?;
    let c = st.db.lock().await;
    let uid = a.user_id.as_str();
    for d in db::query(&c, "SELECT id FROM devices WHERE user_id = ?1", p![uid]).await? {
        revoke_device(&c, &text(&d[0])).await?;
    }
    for sql in [
        "DELETE FROM access_tokens WHERE user_id = ?1",
        "DELETE FROM ciphers WHERE user_id = ?1",
        "DELETE FROM folders WHERE user_id = ?1",
        "DELETE FROM linked_accounts WHERE user_id = ?1",
        "DELETE FROM events WHERE user_id = ?1",
        "DELETE FROM users WHERE id = ?1",
    ] {
        db::exec(&c, sql, p![uid]).await?;
    }
    Ok(Json(json!({})))
}

// ---------------------------------------------------------------------------------------------
// Zwei-Faktor (Authenticator-App, TOTP)
// ---------------------------------------------------------------------------------------------

async fn totp_enabled(c: &turso::Connection, user_id: &str) -> ApiResult<bool> {
    Ok(db::query_one(c, "SELECT totp_secret FROM users WHERE id = ?1", p![user_id])
        .await?
        .and_then(|r| opt_text(&r[0]))
        .is_some())
}

pub async fn two_factor_list(State(st): State<St>, a: Auth) -> ApiResult<Json<Value>> {
    let c = st.db.lock().await;
    let enabled = totp_enabled(&c, &a.user_id).await?;
    Ok(Json(json!({
        "data": [{"enabled": enabled, "type": 0, "object": "twoFactorProvider"}],
        "continuationToken": null,
        "object": "list"
    })))
}

pub async fn get_authenticator(State(st): State<St>, a: Auth, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    auth::limit_ip(&st, &a.ip)?;
    let req: PasswordVerify = lenient(body)?;
    auth::check_user_password(&st, &a.user_id, &req.master_password_hash).await?;
    let c = st.db.lock().await;
    let sealed = db::query_one(&c, "SELECT totp_secret FROM users WHERE id = ?1", p![a.user_id.as_str()]).await?.and_then(|r| opt_text(&r[0]));
    let (enabled, key) = match sealed.and_then(|s| st.keys.open(&s, &a.user_id)) {
        Some(k) => (true, String::from_utf8_lossy(&k).to_string()),
        None => (false, nrzpass_core::totp::new_secret()),
    };
    Ok(Json(json!({"enabled": enabled, "key": key, "object": "twoFactorAuthenticator"})))
}

pub async fn enable_authenticator(State(st): State<St>, a: Auth, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    auth::limit_ip(&st, &a.ip)?;
    let req: AuthenticatorRequest = lenient(body)?;
    auth::check_user_password(&st, &a.user_id, &req.master_password_hash).await?;
    let key = req.key.trim().replace(' ', "").to_uppercase();
    if nrzpass_core::totp::base32_decode(&key).map(|k| k.len() < 10).unwrap_or(true) {
        return Err(ApiError::bad("Ungueltiger Authenticator-Schluessel."));
    }
    let step = verify_totp_step(&key, &req.token, 0).ok_or_else(|| ApiError::bad("Der Code stimmt nicht. Uhrzeit des Handys pruefen und erneut versuchen."))?;
    let c = st.db.lock().await;
    db::exec(
        &c,
        "UPDATE users SET totp_secret = ?1, totp_last_step = ?2, revision_ms = ?3 WHERE id = ?4",
        p![st.keys.seal(key.as_bytes(), &a.user_id), step, now_ms(), a.user_id.as_str()],
    )
    .await?;
    db::exec(&c, "UPDATE devices SET remember_hash = NULL, remember_expires = 0 WHERE user_id = ?1", p![a.user_id.as_str()]).await?;
    log_event(&c, &a.user_id, "totp_enabled", Some(&a.ip), None).await;
    Ok(Json(json!({"enabled": true, "key": key, "object": "twoFactorAuthenticator"})))
}

pub async fn disable_two_factor(State(st): State<St>, a: Auth, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    auth::limit_ip(&st, &a.ip)?;
    let req: PasswordVerify = lenient(body)?;
    auth::check_user_password(&st, &a.user_id, &req.master_password_hash).await?;
    let c = st.db.lock().await;
    db::exec(&c, "UPDATE users SET totp_secret = NULL, totp_last_step = 0, revision_ms = ?1 WHERE id = ?2", p![now_ms(), a.user_id.as_str()]).await?;
    db::exec(&c, "UPDATE devices SET remember_hash = NULL, remember_expires = 0 WHERE user_id = ?1", p![a.user_id.as_str()]).await?;
    log_event(&c, &a.user_id, "totp_disabled", Some(&a.ip), None).await;
    Ok(Json(json!({"enabled": false, "type": 0, "object": "twoFactorProvider"})))
}
