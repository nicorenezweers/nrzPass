//! `/identity/*`: Prelogin, Registrierung und Token (Passwort, Refresh, Zwei-Faktor).

use crate::auth::{self, log_event, ClientIp};
use crate::db::{self, int, opt_int, opt_text, text};
use crate::error::{ApiError, ApiResult};
use crate::util::{new_id, now_ms, random_token, token_hash};
use crate::{p, St};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use nrzpass_core::api::{self, PreloginRequest, PreloginResponse, RegisterRequest};
use nrzpass_core::crypto::{normalize_email, EncString, Kdf};
use serde_json::{json, Value};
use std::collections::HashMap;

pub const ACCESS_TTL_MS: i64 = 3600 * 1000;
pub const REFRESH_TTL_MS: i64 = 30 * 24 * 3600 * 1000;
pub const REMEMBER_TTL_MS: i64 = 30 * 24 * 3600 * 1000;
const MAX_FAILED: i64 = 5;

pub async fn prelogin(State(st): State<St>, ClientIp(ip): ClientIp, Json(body): Json<Value>) -> ApiResult<Json<PreloginResponse>> {
    auth::limit_ip(&st, &ip)?;
    let req: PreloginRequest = api::from_value_lenient(body).map_err(|_| ApiError::bad("E-Mail fehlt."))?;
    let email = normalize_email(&req.email);
    let c = st.db.lock().await;
    let row = db::query_one(&c, "SELECT kdf, kdf_iter, kdf_mem, kdf_par FROM users WHERE email = ?1", p![email]).await?;
    // Unbekannte E-Mail: Standardwerte, damit niemand herausfindet, welche Konten es gibt
    let kdf = Kdf::DEFAULT;
    Ok(Json(match row {
        Some(r) => PreloginResponse { kdf: int(&r[0]), kdf_iterations: int(&r[1]), kdf_memory: opt_int(&r[2]), kdf_parallelism: opt_int(&r[3]) },
        None => PreloginResponse { kdf: kdf.kind(), kdf_iterations: kdf.iterations(), kdf_memory: kdf.memory(), kdf_parallelism: kdf.parallelism() },
    }))
}

fn valid_email(e: &str) -> bool {
    let Some((local, domain)) = e.rsplit_once('@') else { return false };
    !local.is_empty() && domain.contains('.') && e.len() <= 254 && !e.chars().any(|c| c.is_whitespace() || c.is_control())
}

pub fn is_enc(s: &str) -> bool {
    matches!(s.parse::<EncString>(), Ok(EncString::AesCbc256HmacSha256 { .. }))
}

fn valid_client_hash(h: &str) -> bool {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(h).map(|b| b.len() == 32).unwrap_or(false)
}

pub async fn register(State(st): State<St>, ClientIp(ip): ClientIp, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    auth::limit_ip(&st, &ip)?;
    let req: RegisterRequest = api::from_value_lenient(body).map_err(|e| ApiError::bad(&format!("Ungueltige Anfrage: {e}")))?;
    let email = normalize_email(&req.email);
    if !valid_email(&email) {
        return Err(ApiError::bad("Bitte eine gueltige E-Mail-Adresse angeben."));
    }
    if !valid_client_hash(&req.master_password_hash) {
        return Err(ApiError::bad("Ungueltiger Master-Passwort-Hash."));
    }
    if !is_enc(&req.key) {
        return Err(ApiError::bad("Ungueltiger Kontoschluessel."));
    }
    let kdf = Kdf::from_api(req.kdf, Some(req.kdf_iterations), req.kdf_memory, req.kdf_parallelism)
        .map_err(|e| ApiError::bad(&e.to_string()))?;
    let hint = req.master_password_hint.filter(|h| !h.trim().is_empty());
    if hint.as_deref().map(|h| h.chars().count() > 200).unwrap_or(false) {
        return Err(ApiError::bad("Der Hinweis darf hoechstens 200 Zeichen lang sein."));
    }
    let name = req.name.map(|n| n.chars().take(100).collect::<String>());
    let (public_key, private_key) = match req.keys {
        Some(k) if !k.encrypted_private_key.is_empty() => {
            if !is_enc(&k.encrypted_private_key) {
                return Err(ApiError::bad("Ungueltiger privater Schluessel."));
            }
            (Some(k.public_key), Some(k.encrypted_private_key))
        }
        _ => (None, None),
    };

    let pw_hash = auth::hash_password_async(req.master_password_hash).await?;
    let c = st.db.lock().await;
    let users = db::query_one(&c, "SELECT COUNT(*) FROM users", vec![]).await?.map(|r| int(&r[0])).unwrap_or(0);
    if users > 0 {
        if !st.cfg.signups_allowed {
            return Err(ApiError::forbidden("Registrierung ist auf diesem Server geschlossen."));
        }
        if !st.cfg.signups_domains.is_empty() {
            let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
            if !st.cfg.signups_domains.iter().any(|d| d == domain) {
                return Err(ApiError::forbidden("Diese E-Mail-Domain ist fuer die Registrierung nicht freigegeben."));
            }
        }
    }
    if db::query_one(&c, "SELECT id FROM users WHERE email = ?1", p![email.as_str()]).await?.is_some() {
        return Err(ApiError::bad("Fuer diese E-Mail gibt es schon ein Konto."));
    }
    let id = new_id();
    let now = now_ms();
    db::exec(
        &c,
        "INSERT INTO users (id, email, name, pw_hash, hint, akey, private_key, public_key, kdf, kdf_iter, kdf_mem, kdf_par, \
         security_stamp, created_ms, revision_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        p![
            id.as_str(), email.as_str(), name, pw_hash, hint, req.key, private_key, public_key, kdf.kind(), kdf.iterations(),
            kdf.memory(), kdf.parallelism(), new_id(), now, now
        ],
    )
    .await?;
    log_event(&c, &id, "register", Some(&ip), None).await;
    Ok(Json(json!({"object": "register", "captchaBypassToken": null})))
}

struct UserRow {
    id: String,
    pw_hash: String,
    akey: String,
    private_key: Option<String>,
    kdf: i64,
    kdf_iter: i64,
    kdf_mem: Option<i64>,
    kdf_par: Option<i64>,
    totp_secret: Option<String>,
    totp_last_step: i64,
    failed: i64,
    locked_until: i64,
}

const USER_COLS: &str =
    "id, pw_hash, akey, private_key, kdf, kdf_iter, kdf_mem, kdf_par, totp_secret, totp_last_step, failed_logins, locked_until";

fn user_row(r: &db::Row) -> UserRow {
    UserRow {
        id: text(&r[0]),
        pw_hash: text(&r[1]),
        akey: text(&r[2]),
        private_key: opt_text(&r[3]),
        kdf: int(&r[4]),
        kdf_iter: int(&r[5]),
        kdf_mem: opt_int(&r[6]),
        kdf_par: opt_int(&r[7]),
        totp_secret: opt_text(&r[8]),
        totp_last_step: int(&r[9]),
        failed: int(&r[10]),
        locked_until: int(&r[11]),
    }
}

/// Antwort fuer erfolgreiche Anmeldung.
fn token_response(u: &UserRow, access: &str, refresh: &str, remember: Option<String>) -> Response {
    let mut v = json!({
        "access_token": access,
        "expires_in": ACCESS_TTL_MS / 1000,
        "token_type": "Bearer",
        "refresh_token": refresh,
        "Key": u.akey,
        "PrivateKey": u.private_key,
        "Kdf": u.kdf,
        "KdfIterations": u.kdf_iter,
        "KdfMemory": u.kdf_mem,
        "KdfParallelism": u.kdf_par,
        "ResetMasterPassword": false,
        "ForcePasswordReset": false,
        "scope": "api offline_access",
        "unofficialServer": true,
        "UserDecryptionOptions": {"HasMasterPassword": true, "Object": "userDecryptionOptions"},
    });
    if let Some(r) = remember {
        v["TwoFactorToken"] = json!(r);
    }
    (StatusCode::OK, Json(v)).into_response()
}

fn two_factor_required() -> ApiError {
    ApiError {
        status: StatusCode::BAD_REQUEST,
        body: json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": ["0"],
            "TwoFactorProviders2": {"0": null},
            "MasterPasswordPolicy": {"Object": "masterPasswordPolicy"}
        }),
    }
}

const WRONG: &str = "E-Mail oder Master-Passwort ist falsch.";

/// TOTP pruefen, inkl. Schutz vor Wiederverwendung: liefert den genutzten Zeitschritt.
pub fn verify_totp_step(secret_b32: &str, code: &str, last_step: i64) -> Option<i64> {
    let t = nrzpass_core::totp::Totp::parse(secret_b32)?;
    let code = code.trim().replace(' ', "");
    let now = (now_ms() / 1000) as u64;
    for s in [now.saturating_sub(t.period), now, now + t.period] {
        let step = (s / t.period) as i64;
        if step > last_step && nrzpass_core::crypto::ct_eq(t.code_at(s).as_bytes(), code.as_bytes()) {
            return Some(step);
        }
    }
    None
}

/// Fehlversuch zaehlen; ab 5 Fehlern wachsende Sperre (1 min, 2 min, … max. 1 h).
async fn register_failure(c: &turso::Connection, u: &UserRow, kind: &str, ip: &str, device: &str) -> turso::Result<()> {
    let failed = u.failed + 1;
    let mut locked = 0;
    if failed >= MAX_FAILED {
        let mins = 1i64 << (failed - MAX_FAILED).min(6);
        locked = now_ms() + mins.min(60) * 60 * 1000;
    }
    db::exec(c, "UPDATE users SET failed_logins = ?1, locked_until = ?2 WHERE id = ?3", p![failed, locked, u.id.as_str()]).await?;
    log_event(c, &u.id, kind, Some(ip), Some(device)).await;
    if locked > 0 {
        log_event(c, &u.id, "account_locked", Some(ip), Some(device)).await;
    }
    Ok(())
}

pub async fn token(State(st): State<St>, ClientIp(ip): ClientIp, Form(f): Form<HashMap<String, String>>) -> Result<Response, ApiError> {
    auth::limit_ip(&st, &ip)?;
    match form_get(&f, "grant_type").as_deref() {
        Some("password") => password_grant(&st, &ip, &f).await,
        Some("refresh_token") => refresh_grant(&st, &form_get(&f, "refresh_token").unwrap_or_default()).await,
        _ => Err(ApiError::grant("Nicht unterstuetzter grant_type.")),
    }
}

fn form_get(f: &HashMap<String, String>, k: &str) -> Option<String> {
    f.get(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

async fn password_grant(st: &St, ip: &str, f: &HashMap<String, String>) -> Result<Response, ApiError> {
    let get = |k: &str| form_get(f, k);
    let email = normalize_email(&get("username").unwrap_or_default());
    let client_hash = get("password").unwrap_or_default();
    let identifier = get("deviceIdentifier").filter(|d| d.len() <= 100).unwrap_or_else(new_id);
    let device_name: String = get("deviceName").unwrap_or_else(|| "Unbekanntes Geraet".into()).chars().take(80).collect();
    let device_type = get("deviceType").and_then(|d| d.parse::<i64>().ok()).unwrap_or(14);

    let row = {
        let c = st.db.lock().await;
        db::query_one(&c, &format!("SELECT {USER_COLS} FROM users WHERE email = ?1"), p![email.as_str()]).await?
    };
    let Some(u) = row.as_ref().map(user_row) else {
        // Gleiche Rechenzeit wie bei einem echten Konto
        auth::verify_password(client_hash, st.dummy_hash.clone()).await;
        return Err(ApiError::grant(WRONG));
    };
    if u.locked_until > now_ms() {
        let mins = ((u.locked_until - now_ms()) / 60_000) + 1;
        return Err(ApiError::too_many(&format!(
            "Zu viele Fehlversuche – das Konto ist noch {mins} Minute(n) gesperrt."
        )));
    }
    if client_hash.is_empty() || !auth::verify_password(client_hash, u.pw_hash.clone()).await {
        let c = st.db.lock().await;
        register_failure(&c, &u, "login_failed", ip, &device_name).await?;
        return Err(ApiError::grant(WRONG));
    }

    let c = st.db.lock().await;
    let now = now_ms();
    let existing = db::query_one(
        &c,
        "SELECT id, remember_hash, remember_expires FROM devices WHERE user_id = ?1 AND identifier = ?2",
        p![u.id.as_str(), identifier.as_str()],
    )
    .await?;

    // Zwei-Faktor
    let mut remember_token = None;
    let mut totp_step = None;
    if let Some(sealed) = u.totp_secret.as_deref() {
        let token = get("twoFactorToken");
        let provider = get("twoFactorProvider").unwrap_or_else(|| "0".into());
        let Some(token) = token else { return Err(two_factor_required()) };
        if provider == "5" {
            // "Angemeldet bleiben": gespeichertes Remember-Token dieses Geraets
            let ok = existing.as_ref().is_some_and(|d| {
                opt_text(&d[1]).is_some_and(|h| nrzpass_core::crypto::ct_eq(h.as_bytes(), token_hash(&token).as_bytes()))
                    && int(&d[2]) > now
            });
            if !ok {
                return Err(two_factor_required());
            }
        } else {
            let secret = st.keys.open(sealed, &u.id).ok_or_else(|| ApiError::internal("TOTP-Schluessel nicht lesbar"))?;
            let secret = String::from_utf8_lossy(&secret).to_string();
            match verify_totp_step(&secret, &token, u.totp_last_step) {
                Some(step) => totp_step = Some(step),
                None => {
                    register_failure(&c, &u, "totp_failed", ip, &device_name).await?;
                    return Err(ApiError::grant("Der Zwei-Faktor-Code ist falsch oder abgelaufen."));
                }
            }
            if get("twoFactorRemember").as_deref() == Some("1") {
                remember_token = Some(random_token());
            }
        }
    }

    db::exec(&c, "UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?1", p![u.id.as_str()]).await?;
    if let Some(step) = totp_step {
        db::exec(&c, "UPDATE users SET totp_last_step = ?1 WHERE id = ?2", p![step, u.id.as_str()]).await?;
    }

    let access = random_token();
    let refresh = random_token();
    let device_id = match existing {
        Some(d) => {
            let id = text(&d[0]);
            db::exec(
                &c,
                "UPDATE devices SET name = ?1, dtype = ?2, refresh_hash = ?3, refresh_expires = ?4, last_seen_ms = ?5 WHERE id = ?6",
                p![device_name.as_str(), device_type, token_hash(&refresh), now + REFRESH_TTL_MS, now, id.as_str()],
            )
            .await?;
            id
        }
        None => {
            let id = new_id();
            db::exec(
                &c,
                "INSERT INTO devices (id, user_id, identifier, name, dtype, refresh_hash, refresh_expires, created_ms, last_seen_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                p![id.as_str(), u.id.as_str(), identifier.as_str(), device_name.as_str(), device_type, token_hash(&refresh), now + REFRESH_TTL_MS, now, now],
            )
            .await?;
            id
        }
    };
    if let Some(r) = remember_token.as_deref() {
        db::exec(
            &c,
            "UPDATE devices SET remember_hash = ?1, remember_expires = ?2 WHERE id = ?3",
            p![token_hash(r), now + REMEMBER_TTL_MS, device_id.as_str()],
        )
        .await?;
    }
    db::exec(&c, "DELETE FROM access_tokens WHERE expires < ?1", p![now]).await?;
    db::exec(&c, "DELETE FROM old_refresh WHERE expires < ?1", p![now]).await?;
    db::exec(
        &c,
        "INSERT INTO access_tokens (hash, user_id, device_id, expires) VALUES (?1, ?2, ?3, ?4)",
        p![token_hash(&access), u.id.as_str(), device_id.as_str(), now + ACCESS_TTL_MS],
    )
    .await?;
    log_event(&c, &u.id, "login", Some(ip), Some(&device_name)).await;
    Ok(token_response(&u, &access, &refresh, remember_token))
}

/// Entfernt ein Geraet samt Tokens.
pub async fn revoke_device(c: &turso::Connection, device_id: &str) -> turso::Result<()> {
    db::exec(c, "DELETE FROM access_tokens WHERE device_id = ?1", p![device_id]).await?;
    db::exec(c, "DELETE FROM old_refresh WHERE device_id = ?1", p![device_id]).await?;
    db::exec(c, "DELETE FROM devices WHERE id = ?1", p![device_id]).await?;
    Ok(())
}

async fn refresh_grant(st: &St, refresh: &str) -> Result<Response, ApiError> {
    if refresh.is_empty() || refresh.len() > 200 {
        return Err(ApiError::grant("Ungueltiges Refresh-Token."));
    }
    let h = token_hash(refresh);
    let now = now_ms();
    let c = st.db.lock().await;
    let dev = db::query_one(&c, "SELECT id, user_id, refresh_expires, name FROM devices WHERE refresh_hash = ?1", p![h.as_str()]).await?;
    let Some(dev) = dev else {
        // Wiederverwendetes (bereits ersetztes) Token: Hinweis auf Diebstahl -> Geraet abmelden
        if let Some(old) = db::query_one(&c, "SELECT device_id FROM old_refresh WHERE hash = ?1", p![h.as_str()]).await? {
            let device_id = text(&old[0]);
            if let Some(d) = db::query_one(&c, "SELECT user_id, name FROM devices WHERE id = ?1", p![device_id.as_str()]).await? {
                log_event(&c, &text(&d[0]), "device_revoked", None, Some(&text(&d[1]))).await;
            }
            revoke_device(&c, &device_id).await?;
        }
        return Err(ApiError::grant("Ungueltiges Refresh-Token."));
    };
    let (device_id, user_id) = (text(&dev[0]), text(&dev[1]));
    if int(&dev[2]) < now {
        revoke_device(&c, &device_id).await?;
        return Err(ApiError::grant("Die Sitzung ist abgelaufen – bitte neu anmelden."));
    }
    let u = db::query_one(&c, &format!("SELECT {USER_COLS} FROM users WHERE id = ?1"), p![user_id.as_str()])
        .await?
        .map(|r| user_row(&r))
        .ok_or_else(|| ApiError::grant("Konto nicht gefunden."))?;
    let access = random_token();
    let new_refresh = random_token();
    db::exec(
        &c,
        "INSERT INTO old_refresh (hash, device_id, expires) VALUES (?1, ?2, ?3)",
        p![h.as_str(), device_id.as_str(), now + REFRESH_TTL_MS],
    )
    .await?;
    db::exec(
        &c,
        "UPDATE devices SET refresh_hash = ?1, refresh_expires = ?2, last_seen_ms = ?3 WHERE id = ?4",
        p![token_hash(&new_refresh), now + REFRESH_TTL_MS, now, device_id.as_str()],
    )
    .await?;
    db::exec(
        &c,
        "INSERT INTO access_tokens (hash, user_id, device_id, expires) VALUES (?1, ?2, ?3, ?4)",
        p![token_hash(&access), user_id.as_str(), device_id.as_str(), now + ACCESS_TTL_MS],
    )
    .await?;
    Ok(token_response(&u, &access, &new_refresh, None))
}
