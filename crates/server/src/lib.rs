//! nrzPass-Server: liefert den Web-Tresor aus und spricht eine Teilmenge der Bitwarden-API
//! (wie Vaultwarden). Der Server sieht nie ein Master-Passwort und nie Klartext: alle Eintraege
//! kommen fertig verschluesselt vom Client. Zusaetzlich ist die Turso-Datenbankdatei selbst mit
//! AEGIS-256 verschluesselt, und TOTP-Schluessel sind noch einmal mit XChaCha20-Poly1305 gesichert.

pub mod account;
pub mod auth;
pub mod ciphers;
pub mod config;
pub mod db;
pub mod error;
pub mod identity;
pub mod keys;
pub mod nrz;
pub mod ratelimit;
pub mod util;
pub mod web;

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post, put};
use axum::Router;
use std::sync::Arc;

pub use config::Config;

/// Gemeinsamer Zustand aller Anfragen.
pub struct AppState {
    pub cfg: Config,
    pub db: db::Db,
    pub keys: keys::ServerKeys,
    pub ip_limit: ratelimit::RateLimiter,
    pub proxy_limit: ratelimit::RateLimiter,
    pub web: web::WebAssets,
    pub http: reqwest::Client,
    /// Argon2-Hash eines Zufallswerts: gleicht die Antwortzeit bei unbekannten E-Mails an.
    pub dummy_hash: String,
}

pub type St = Arc<AppState>;

/// Oeffnet die Datenbank und baut den Router.
pub async fn build(cfg: Config) -> anyhow_like::Result<Router> {
    std::fs::create_dir_all(&cfg.data_dir).map_err(|e| format!("DATA_DIR {:?}: {e}", cfg.data_dir))?;
    let keys = keys::ServerKeys::load(&cfg)?;
    let db = db::Db::open(&cfg.data_dir.join("nrzpass.db"), &keys.db_key_hex()).await?;
    db.migrate().await?;
    restrict_permissions(&cfg.data_dir);
    let web = web::WebAssets::load(cfg.web_dir.clone());
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(concat!("nrzPass/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let dummy_hash = auth::hash_password("nrzpass-dummy-value")?;
    let state = Arc::new(AppState {
        ip_limit: ratelimit::RateLimiter::new(cfg.identity_rate_per_min, cfg.identity_rate_per_min as f64 / 60.0),
        proxy_limit: ratelimit::RateLimiter::new(120, 2.0),
        cfg,
        db,
        keys,
        web,
        http,
        dummy_hash,
    });
    Ok(router(state))
}

pub fn router(state: St) -> Router {
    let api = Router::new()
        .route("/alive", get(util::alive))
        .route("/api/alive", get(util::alive))
        .route("/api/version", get(util::version))
        .route("/api/config", get(util::bw_config))
        // Identity
        .route("/identity/accounts/prelogin", post(identity::prelogin))
        .route("/api/accounts/prelogin", post(identity::prelogin))
        .route("/identity/accounts/register", post(identity::register))
        .route("/api/accounts/register", post(identity::register))
        .route("/identity/connect/token", post(identity::token))
        // Konto
        .route("/api/sync", get(account::sync))
        .route("/api/accounts/profile", get(account::profile).put(account::update_profile).post(account::update_profile))
        .route("/api/accounts/revision-date", get(account::revision_date))
        .route("/api/accounts/password", post(account::change_password))
        .route("/api/accounts/verify-password", post(account::verify_password))
        .route("/api/accounts/delete", post(account::delete_account))
        .route("/api/accounts", delete(account::delete_account))
        // Zwei-Faktor
        .route("/api/two-factor", get(account::two_factor_list))
        .route("/api/two-factor/get-authenticator", post(account::get_authenticator))
        .route("/api/two-factor/authenticator", put(account::enable_authenticator).post(account::enable_authenticator))
        .route("/api/two-factor/disable", put(account::disable_two_factor).post(account::disable_two_factor))
        // Eintraege und Ordner
        .route("/api/ciphers", post(ciphers::create))
        .route("/api/ciphers/create", post(ciphers::create_with_collections))
        .route(
            "/api/ciphers/import",
            post(ciphers::import).layer(DefaultBodyLimit::max(20 * 1024 * 1024)),
        )
        .route("/api/ciphers/{id}", get(ciphers::get_one).put(ciphers::update).post(ciphers::update).delete(ciphers::hard_delete))
        .route("/api/ciphers/{id}/delete", put(ciphers::soft_delete).post(ciphers::soft_delete))
        .route("/api/ciphers/{id}/restore", put(ciphers::restore).post(ciphers::restore))
        .route("/api/folders", get(ciphers::list_folders).post(ciphers::create_folder))
        .route("/api/folders/{id}", put(ciphers::update_folder).post(ciphers::update_folder).delete(ciphers::delete_folder))
        // nrzPass-Erweiterungen
        .route("/api/nrz/info", get(nrz::info))
        .route("/api/nrz/linked", get(nrz::list_linked).post(nrz::create_linked))
        .route("/api/nrz/linked/{id}", put(nrz::update_linked).delete(nrz::delete_linked))
        .route("/api/nrz/events", get(nrz::events))
        .route("/api/nrz/devices", get(nrz::devices))
        .route("/api/nrz/devices/{id}", delete(nrz::revoke_device))
        .route("/api/nrz/proxy", post(nrz::proxy))
        .route("/api/nrz/downloads", get(nrz::list_downloads))
        .layer(web::cors_layer());

    Router::new()
        .merge(api)
        .route("/downloads/{file}", get(nrz::download))
        .fallback(web::static_handler)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(state.clone(), web::security_headers))
        .with_state(state)
}

/// Datenbankdateien nur fuer den eigenen Benutzer lesbar machen (zusaetzlich zur Verschluesselung).
fn restrict_permissions(dir: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        for f in ["nrzpass.db", "nrzpass.db-wal", "nrzpass.db-shm", "db.key"] {
            let _ = std::fs::set_permissions(dir.join(f), std::fs::Permissions::from_mode(0o600));
        }
    }
}

/// Kleiner Fehlertyp fuer den Start (Meldung als Text).
pub mod anyhow_like {
    pub type Result<T> = std::result::Result<T, String>;
}
