//! Zustand und Ablaeufe: Anmelden, Entsperren, Sperren, Synchronisieren, Speichern.
//!
//! Sicherheitsmodell im Client:
//! * Gespeichert (localStorage / chrome.storage.local) wird nur, was ohne Master-Passwort
//!   wertlos ist: Server, E-Mail, KDF, der mit dem Master-Schluessel verschluesselte
//!   Benutzerschluessel und die Tokens – letztere zusaetzlich mit dem Benutzerschluessel
//!   verschluesselt.
//! * Entschluesselte Schluessel und Eintraege existieren nur im Arbeitsspeicher und werden
//!   beim Sperren verworfen (Schluessel werden dabei ueberschrieben).
//! * In der Erweiterung liegt der Benutzerschluessel waehrend der Sitzung in
//!   chrome.storage.session (nur Arbeitsspeicher, nur fuer die Erweiterung lesbar).

use crate::env::{self, Area, Platform};
use crate::net::{normalize_server, Conn, LoginError, Via};
use leptos::prelude::*;
use leptos::task::spawn_local;
use nrzpass_core::api::{self, Cipher, Folder, LinkedAccountData, TokenResponse};
use nrzpass_core::crypto::{self, MasterKey};
use nrzpass_core::vault::{self, KeyRing};
use nrzpass_core::{Kdf, SymmetricKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SESSION_KEY: &str = "nrzpass.session";
const SETTINGS_KEY: &str = "nrzpass.settings";
const EXT_KEYS: &str = "nrzpass.keys";
const EXT_INDEX: &str = "nrzpass.index";
pub const PRIMARY: &str = "nrz";

/// Dauerhaft gespeicherte Anmeldung (ohne Geheimnisse im Klartext).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StoredSession {
    pub server: String,
    pub email: String,
    pub name: Option<String>,
    pub kdf: Kdf,
    pub protected_key: String,
    pub device_id: String,
    /// EncString (Benutzerschluessel) mit [`Tokens`] als JSON.
    pub tokens: String,
    /// Merkt sich die Zwei-Faktor-Freigabe dieses Geraets (verschluesselt).
    #[serde(default)]
    pub remember: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Tokens {
    pub access: String,
    pub refresh: String,
    pub expires_at: f64,
}

impl Tokens {
    fn from_response(t: &TokenResponse) -> Tokens {
        Tokens {
            access: t.access_token.clone(),
            refresh: t.refresh_token.clone().unwrap_or_default(),
            expires_at: env::now_ms() + (t.expires_in.max(60) as f64 - 30.0) * 1000.0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// Minuten ohne Aktivitaet bis zur Sperre (0 = nie).
    pub auto_lock_minutes: u32,
    /// Zwischenablage nach so vielen Sekunden leeren (0 = nie).
    pub clipboard_clear_secs: u32,
    /// Sperren, wenn das Fenster/der Tab laenger als 1 Minute verborgen ist.
    pub lock_when_hidden: bool,
    pub generator: nrzpass_core::generator::PasswordOptions,
    pub passphrase: nrzpass_core::generator::PassphraseOptions,
    pub use_passphrase: bool,
    /// Server fuer Tauri/Erweiterung (auf der Webseite der eigene Ursprung).
    pub last_server: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            auto_lock_minutes: 15,
            clipboard_clear_secs: 30,
            lock_when_hidden: false,
            generator: Default::default(),
            passphrase: Default::default(),
            use_passphrase: false,
            last_server: String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Phase {
    Loading,
    Setup,
    Locked,
    Unlocked,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AccountKind {
    Primary,
    Linked { linked_id: String, data: LinkedAccountData },
}

/// Ein entsperrtes Konto (nrzPass selbst oder ein verknuepftes Vaultwarden-Konto).
#[derive(Clone, Debug)]
pub struct Account {
    pub id: String,
    pub label: String,
    pub email: String,
    pub server: String,
    pub kind: AccountKind,
    pub keys: KeyRing,
    pub tokens: Tokens,
    pub conn: Conn,
    pub error: Option<String>,
    pub two_factor: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub account: String,
    pub cipher: Cipher,
    pub broken: bool,
}

impl Entry {
    pub fn key(&self) -> String {
        format!("{}:{}", self.account, self.cipher.id)
    }
    pub fn name(&self) -> String {
        self.cipher.name.clone().unwrap_or_else(|| "(ohne Namen)".into())
    }
    pub fn subtitle(&self) -> String {
        let c = &self.cipher;
        match c.cipher_type {
            api::cipher_type::LOGIN => c.login.as_ref().and_then(|l| l.username.clone()).unwrap_or_default(),
            api::cipher_type::CARD => c
                .card
                .as_ref()
                .map(|k| {
                    let n = k.number.clone().unwrap_or_default();
                    let last: String = n.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
                    format!("{} •••• {}", k.brand.clone().unwrap_or_default(), last).trim().to_string()
                })
                .unwrap_or_default(),
            api::cipher_type::IDENTITY => c
                .identity
                .as_ref()
                .map(|i| format!("{} {}", i.first_name.clone().unwrap_or_default(), i.last_name.clone().unwrap_or_default()).trim().to_string())
                .unwrap_or_default(),
            _ => String::new(),
        }
    }
    pub fn uris(&self) -> Vec<(String, Option<i64>)> {
        self.cipher
            .login
            .as_ref()
            .and_then(|l| l.uris.as_ref())
            .map(|u| u.iter().filter_map(|u| Some((u.uri.clone()?, u.match_type))).collect())
            .unwrap_or_default()
    }
    pub fn deleted(&self) -> bool {
        self.cipher.deleted_date.is_some()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FolderEntry {
    pub account: String,
    pub folder: Folder,
}

#[derive(Clone, Debug, PartialEq)]
pub enum View {
    Vault,
    Generator,
    Accounts,
    Settings,
    Health,
    Downloads,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Filter {
    All,
    Favorites,
    Type(i64),
    Folder(String, Option<String>),
    Account(String),
    Trash,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Toast {
    pub id: u32,
    pub text: String,
    pub error: bool,
}

#[derive(Clone, Copy)]
pub struct App {
    pub phase: RwSignal<Phase>,
    pub session: RwSignal<Option<StoredSession>>,
    pub settings: RwSignal<Settings>,
    pub accounts: RwSignal<Vec<Account>>,
    pub entries: RwSignal<Vec<Entry>>,
    pub folders: RwSignal<Vec<FolderEntry>>,
    pub view: RwSignal<View>,
    pub filter: RwSignal<Filter>,
    pub search: RwSignal<String>,
    pub selected: RwSignal<Option<String>>,
    /// `Some(None)` = neuer Eintrag, `Some(Some(key))` = bearbeiten.
    pub editing: RwSignal<Option<Option<String>>>,
    pub syncing: RwSignal<bool>,
    pub toasts: RwSignal<Vec<Toast>>,
    pub last_activity: StoredValue<f64>,
    pub hidden_since: StoredValue<Option<f64>>,
    /// Aktiver Tab (nur Erweiterung): ID und Adresse.
    pub tab: RwSignal<Option<(i32, String)>>,
    pub nav_open: RwSignal<bool>,
}

pub fn app() -> App {
    expect_context::<App>()
}

impl App {
    pub fn new() -> App {
        App {
            phase: RwSignal::new(Phase::Loading),
            session: RwSignal::new(None),
            settings: RwSignal::new(Settings::default()),
            accounts: RwSignal::new(vec![]),
            entries: RwSignal::new(vec![]),
            folders: RwSignal::new(vec![]),
            view: RwSignal::new(View::Vault),
            filter: RwSignal::new(Filter::All),
            search: RwSignal::new(String::new()),
            selected: RwSignal::new(None),
            editing: RwSignal::new(None),
            syncing: RwSignal::new(false),
            toasts: RwSignal::new(vec![]),
            last_activity: StoredValue::new(env::now_ms()),
            hidden_since: StoredValue::new(None),
            tab: RwSignal::new(None),
            nav_open: RwSignal::new(false),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Meldungen
    // -----------------------------------------------------------------------------------------

    pub fn toast(&self, text: impl Into<String>) {
        self.push_toast(text.into(), false);
    }
    pub fn error(&self, text: impl Into<String>) {
        self.push_toast(text.into(), true);
    }
    fn push_toast(&self, text: String, error: bool) {
        let id = (env::now_ms() as u64 % 1_000_000_000) as u32 ^ (self.toasts.get_untracked().len() as u32);
        self.toasts.update(|t| t.push(Toast { id, text, error }));
        let toasts = self.toasts;
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(if error { 6000 } else { 3000 }).await;
            toasts.update(|t| t.retain(|x| x.id != id));
        });
    }

    pub fn copy(&self, label: &str, text: String) {
        let secs = self.settings.get_untracked().clipboard_clear_secs;
        let app = *self;
        let label = label.to_string();
        spawn_local(async move {
            if env::copy(&text, secs).await {
                if secs > 0 {
                    app.toast(format!("{label} kopiert – wird nach {secs} s geleert"));
                } else {
                    app.toast(format!("{label} kopiert"));
                }
            } else {
                app.error("Kopieren nicht möglich");
            }
        });
    }

    // -----------------------------------------------------------------------------------------
    // Start
    // -----------------------------------------------------------------------------------------

    pub async fn boot(&self) {
        if let Some(s) = env::store_get(Area::Local, SETTINGS_KEY).await {
            if let Ok(s) = serde_json::from_str::<Settings>(&s) {
                self.settings.set(s);
            }
        }
        if env::platform() == Platform::Extension {
            self.tab.set(env::active_tab().await);
        }
        let session = env::store_get(Area::Local, SESSION_KEY).await.and_then(|s| serde_json::from_str::<StoredSession>(&s).ok());
        match session {
            Some(s) => {
                self.session.set(Some(s.clone()));
                // Erweiterung: noch entsperrt aus derselben Browser-Sitzung?
                if let Some(k) = env::store_get(Area::Session, EXT_KEYS).await {
                    if let Ok(v) = serde_json::from_str::<Value>(&k) {
                        if let Some(uk) = v["userKey"].as_str().and_then(|u| SymmetricKey::from_b64(u).ok()) {
                            if self.finish_unlock(&s, uk).await.is_ok() {
                                return;
                            }
                        }
                    }
                }
                self.phase.set(Phase::Locked);
            }
            None => self.phase.set(Phase::Setup),
        }
    }

    pub fn save_settings(&self) {
        let s = serde_json::to_string(&self.settings.get_untracked()).unwrap_or_default();
        spawn_local(async move { env::store_set(Area::Local, SETTINGS_KEY, &s).await });
    }

    pub fn default_server(&self) -> String {
        match env::platform() {
            Platform::Web => env::origin(),
            _ => self.settings.get_untracked().last_server,
        }
    }

    // -----------------------------------------------------------------------------------------
    // Anmelden / Registrieren
    // -----------------------------------------------------------------------------------------

    /// Erste Anmeldung auf diesem Geraet. `Ok(Some(..))` = Zwei-Faktor-Code noetig.
    pub async fn login(&self, server: &str, email: &str, password: &str, totp: Option<(String, bool)>) -> Result<Option<Vec<String>>, String> {
        let base = normalize_server(server);
        let email = crypto::normalize_email(email);
        let device_id = self
            .session
            .get_untracked()
            .filter(|s| s.server == base)
            .map(|s| s.device_id)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let conn = Conn { base: base.clone(), via: crate::net::default_via(), device_id: device_id.clone() };
        let kdf = conn.prelogin(&email).await?;
        let master = MasterKey::derive(password, &email, kdf).map_err(|e| e.to_string())?;
        let hash = master.password_hash(password);
        let tf = totp.map(|(c, r)| (c, 0, r));
        let t = match conn.login(&email, &hash, tf, None).await {
            Ok(t) => t,
            Err(LoginError::TwoFactor(p)) => return Ok(Some(p)),
            Err(LoginError::Msg(m)) => return Err(m),
        };
        let protected = t.key.clone().ok_or("Server hat keinen Schlüssel geliefert")?;
        let user_key = crypto::unlock_user_key(&master, &protected).map_err(|_| "Schlüssel konnte nicht entschlüsselt werden".to_string())?;
        // KDF der Antwort bevorzugen (falls Prelogin veraltet war)
        let kdf = match t.kdf {
            Some(k) => Kdf::from_api(k, t.kdf_iterations, t.kdf_memory, t.kdf_parallelism).unwrap_or(kdf),
            None => kdf,
        };
        let tokens = Tokens::from_response(&t);
        let session = StoredSession {
            server: base.clone(),
            email: email.clone(),
            name: None,
            kdf,
            protected_key: protected,
            device_id,
            tokens: user_key.encrypt_str(&serde_json::to_string(&tokens).unwrap()).to_string(),
            remember: None,
        };
        self.persist_session(&session).await;
        self.settings.update(|s| s.last_server = base);
        self.save_settings();
        self.finish_unlock(&session, user_key).await?;
        Ok(None)
    }

    pub async fn register(&self, server: &str, name: &str, email: &str, password: &str, hint: &str) -> Result<(), String> {
        let base = normalize_server(server);
        let email = crypto::normalize_email(email);
        let conn = Conn { base: base.clone(), via: crate::net::default_via(), device_id: String::new() };
        let kdf = Kdf::DEFAULT;
        let (pw, em) = (password.to_string(), email.clone());
        // RSA-Schluesselpaar fuer Kompatibilitaet mit Bitwarden-Clients
        let acc = crypto::make_account(&pw, &em, kdf, true).map_err(|e| e.to_string())?;
        let body = json!({
            "email": email,
            "name": name,
            "masterPasswordHash": acc.master_password_hash,
            "masterPasswordHint": if hint.is_empty() { Value::Null } else { Value::String(hint.into()) },
            "key": acc.protected_user_key,
            "kdf": kdf.kind(),
            "kdfIterations": kdf.iterations(),
            "kdfMemory": kdf.memory(),
            "kdfParallelism": kdf.parallelism(),
            "keys": { "publicKey": acc.public_key_b64, "encryptedPrivateKey": acc.encrypted_private_key },
        });
        let mut r = conn.raw("POST", "/identity/accounts/register", None, Some(&body)).await?;
        if r.status == 404 {
            r = conn.raw("POST", "/api/accounts/register", None, Some(&body)).await?;
        }
        if !r.ok() {
            return Err(r.error());
        }
        drop(acc);
        match self.login(&base, &email, password, None).await? {
            None => Ok(()),
            Some(_) => Err("Zwei-Faktor nötig".into()),
        }
    }

    async fn persist_session(&self, s: &StoredSession) {
        env::store_set(Area::Local, SESSION_KEY, &serde_json::to_string(s).unwrap_or_default()).await;
        self.session.set(Some(s.clone()));
    }

    // -----------------------------------------------------------------------------------------
    // Entsperren / Sperren
    // -----------------------------------------------------------------------------------------

    pub async fn unlock(&self, password: &str) -> Result<(), String> {
        let s = self.session.get_untracked().ok_or("Nicht angemeldet")?;
        let master = MasterKey::derive(password, &s.email, s.kdf).map_err(|e| e.to_string())?;
        let uk = crypto::unlock_user_key(&master, &s.protected_key).map_err(|_| "Falsches Master-Passwort".to_string())?;
        self.finish_unlock(&s, uk).await
    }

    async fn finish_unlock(&self, s: &StoredSession, user_key: SymmetricKey) -> Result<(), String> {
        let tokens: Tokens = user_key
            .decrypt_str(&s.tokens.parse().map_err(|_| "Sitzung beschädigt".to_string())?)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .ok_or("Sitzung beschädigt – bitte neu anmelden")?;
        let primary = Account {
            id: PRIMARY.into(),
            label: "nrzPass".into(),
            email: s.email.clone(),
            server: s.server.clone(),
            kind: AccountKind::Primary,
            keys: KeyRing::new(user_key.clone()),
            tokens,
            conn: Conn { base: s.server.clone(), via: crate::net::default_via(), device_id: s.device_id.clone() },
            error: None,
            two_factor: false,
        };
        self.accounts.set(vec![primary]);
        self.last_activity.set_value(env::now_ms());
        self.phase.set(Phase::Unlocked);
        if env::platform() == Platform::Extension {
            env::store_set(Area::Session, EXT_KEYS, &json!({ "userKey": user_key.to_b64().as_str() }).to_string()).await;
        }
        self.sync_all().await;
        Ok(())
    }

    pub fn lock(&self) {
        if self.phase.get_untracked() != Phase::Unlocked {
            return;
        }
        // Schluessel verwerfen (SymmetricKey ueberschreibt sich beim Drop)
        self.accounts.set(vec![]);
        self.entries.set(vec![]);
        self.folders.set(vec![]);
        self.selected.set(None);
        self.editing.set(None);
        self.search.set(String::new());
        self.phase.set(Phase::Locked);
        spawn_local(async {
            env::store_remove(Area::Session, EXT_KEYS).await;
            env::store_remove(Area::Session, EXT_INDEX).await;
            let _ = env::send_to_background(&json!({"type": "locked"})).await;
        });
    }

    pub async fn logout(&self) {
        // Sitzung dieses Geraets auch auf dem Server beenden (nur nrzPass-Server, best effort)
        if self.phase.get_untracked() == Phase::Unlocked {
            if let Ok(v) = self.call(PRIMARY, "GET", "/api/nrz/devices", None).await {
                if let Some(id) = v.as_array().and_then(|a| a.iter().find(|d| d["current"].as_bool() == Some(true))).and_then(|d| d["id"].as_str()) {
                    let _ = self.call(PRIMARY, "DELETE", &format!("/api/nrz/devices/{id}"), None).await;
                }
            }
        }
        self.lock();
        self.view.set(View::Vault);
        self.filter.set(Filter::All);
        env::store_remove(Area::Local, SESSION_KEY).await;
        self.session.set(None);
        self.accounts.set(vec![]);
        self.phase.set(Phase::Setup);
    }

    /// Wird regelmaessig aufgerufen: automatische Sperre.
    pub fn tick(&self) {
        if self.phase.get_untracked() != Phase::Unlocked {
            return;
        }
        let s = self.settings.get_untracked();
        let now = env::now_ms();
        if s.auto_lock_minutes > 0 && now - self.last_activity.get_value() > s.auto_lock_minutes as f64 * 60_000.0 {
            self.lock();
            return;
        }
        if s.lock_when_hidden {
            if let Some(h) = self.hidden_since.get_value() {
                if now - h > 60_000.0 {
                    self.lock();
                }
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Server-Aufrufe mit automatischer Token-Erneuerung
    // -----------------------------------------------------------------------------------------

    fn account(&self, id: &str) -> Option<Account> {
        self.accounts.with_untracked(|a| a.iter().find(|x| x.id == id).cloned())
    }

    fn primary_via_proxy(&self) -> Option<Via> {
        let p = self.account(PRIMARY)?;
        Some(Via::Proxy(p.server.clone(), p.tokens.access.clone()))
    }

    async fn fresh_tokens(&self, id: &str, force: bool) -> Result<Account, String> {
        let mut acc = self.account(id).ok_or("Konto nicht gefunden")?;
        if id != PRIMARY && env::platform() == Platform::Web {
            if let Some(p) = self.account(PRIMARY) {
                if p.tokens.expires_at < env::now_ms() {
                    Box::pin(self.fresh_tokens(PRIMARY, false)).await?;
                }
            }
            acc.conn.via = self.primary_via_proxy().ok_or("nrzPass-Konto fehlt")?;
        }
        if !force && acc.tokens.expires_at > env::now_ms() {
            return Ok(acc);
        }
        let t = acc.conn.refresh(&acc.tokens.refresh).await?;
        let mut tokens = Tokens::from_response(&t);
        if tokens.refresh.is_empty() {
            tokens.refresh = acc.tokens.refresh.clone();
        }
        let rotated = tokens.refresh != acc.tokens.refresh;
        acc.tokens = tokens.clone();
        self.accounts.update(|a| {
            if let Some(x) = a.iter_mut().find(|x| x.id == id) {
                x.tokens = tokens.clone();
            }
        });
        match &acc.kind {
            AccountKind::Primary => {
                if let Some(mut s) = self.session.get_untracked() {
                    s.tokens = acc.keys.user.encrypt_str(&serde_json::to_string(&tokens).unwrap()).to_string();
                    self.persist_session(&s).await;
                }
            }
            AccountKind::Linked { linked_id, data } if rotated => {
                let mut d = data.clone();
                d.refresh_token = tokens.refresh.clone();
                let _ = Box::pin(self.save_linked(Some(linked_id.clone()), &d)).await;
            }
            _ => {}
        }
        Ok(acc)
    }

    /// JSON-Aufruf an ein Konto; bei 401 einmal Token erneuern und wiederholen.
    pub async fn call(&self, id: &str, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        let acc = self.fresh_tokens(id, false).await?;
        let mut r = acc.conn.raw(method, path, Some(&acc.tokens.access), body.as_ref()).await?;
        if r.status == 401 {
            let acc = self.fresh_tokens(id, true).await?;
            r = acc.conn.raw(method, path, Some(&acc.tokens.access), body.as_ref()).await?;
        }
        if !r.ok() {
            return Err(r.error());
        }
        Ok(r.json())
    }

    // -----------------------------------------------------------------------------------------
    // Synchronisieren
    // -----------------------------------------------------------------------------------------

    pub async fn sync_all(&self) {
        if self.syncing.get_untracked() {
            return;
        }
        self.syncing.set(true);
        if let Err(e) = self.sync_account(PRIMARY).await {
            if e.contains("Sitzung abgelaufen") {
                self.syncing.set(false);
                self.error("Sitzung abgelaufen – bitte neu anmelden");
                self.logout().await;
                return;
            }
            self.error(format!("Synchronisieren fehlgeschlagen: {e}"));
        }
        self.load_linked().await;
        let ids: Vec<String> = self.accounts.with_untracked(|a| a.iter().filter(|x| x.id != PRIMARY).map(|x| x.id.clone()).collect());
        for id in ids {
            if let Err(e) = self.sync_account(&id).await {
                self.accounts.update(|a| {
                    if let Some(x) = a.iter_mut().find(|x| x.id == id) {
                        x.error = Some(e.clone());
                    }
                });
            }
        }
        self.syncing.set(false);
        self.publish_extension_index().await;
    }

    pub async fn sync_account(&self, id: &str) -> Result<(), String> {
        let v = self.call(id, "GET", "/api/sync?excludeDomains=true", None).await?;
        let sync: api::SyncResponse = api::from_value_lenient(v).map_err(|e| format!("Antwort unlesbar: {e}"))?;
        let Some(mut acc) = self.account(id) else { return Ok(()) };
        acc.keys.load_orgs(&sync.profile);
        acc.two_factor = sync.profile.two_factor_enabled;
        acc.error = None;
        if id == PRIMARY {
            if let Some(mut s) = self.session.get_untracked() {
                let mut changed = false;
                if s.name != sync.profile.name {
                    s.name = sync.profile.name.clone();
                    changed = true;
                }
                if let Some(k) = sync.profile.key.clone().filter(|k| *k != s.protected_key) {
                    // Master-Passwort wurde auf einem anderen Geraet geaendert
                    s.protected_key = k;
                    changed = true;
                }
                if changed {
                    self.persist_session(&s).await;
                }
            }
        }
        let entries: Vec<Entry> = sync
            .ciphers
            .iter()
            .map(|c| match vault::decrypt_cipher(&acc.keys, c) {
                Ok(p) => Entry { account: id.to_string(), cipher: p, broken: false },
                Err(_) => Entry {
                    account: id.to_string(),
                    cipher: Cipher { name: Some("(nicht entschlüsselbar)".into()), ..c.clone() },
                    broken: true,
                },
            })
            .collect();
        let folders: Vec<FolderEntry> = sync
            .folders
            .iter()
            .filter_map(|f| vault::decrypt_folder(&acc.keys, f).ok())
            .map(|f| FolderEntry { account: id.to_string(), folder: f })
            .collect();
        self.accounts.update(|a| {
            if let Some(x) = a.iter_mut().find(|x| x.id == id) {
                x.keys = acc.keys.clone();
                x.two_factor = acc.two_factor;
                x.error = None;
            }
        });
        self.entries.update(|e| {
            e.retain(|x| x.account != id);
            e.extend(entries);
            e.sort_by_key(|a| a.name().to_lowercase());
        });
        self.folders.update(|f| {
            f.retain(|x| x.account != id);
            f.extend(folders);
            f.sort_by_key(|a| a.folder.name.to_lowercase());
        });
        Ok(())
    }

    /// Erweiterung: Anmeldedaten fuer das automatische Ausfuellen im Sitzungsspeicher ablegen.
    async fn publish_extension_index(&self) {
        if env::platform() != Platform::Extension {
            return;
        }
        let index: Vec<Value> = self.entries.with_untracked(|e| {
            e.iter()
                .filter(|x| !x.deleted() && !x.broken && x.cipher.cipher_type == api::cipher_type::LOGIN)
                .map(|x| {
                    let l = x.cipher.login.clone().unwrap_or_default();
                    json!({
                        "key": x.key(),
                        "name": x.name(),
                        "username": l.username,
                        "password": l.password,
                        "totp": l.totp,
                        "uris": x.uris().into_iter().map(|(u, m)| json!([u, m])).collect::<Vec<_>>(),
                        "reprompt": x.cipher.reprompt,
                    })
                })
                .collect()
        });
        env::store_set(Area::Session, EXT_INDEX, &Value::Array(index).to_string()).await;
        if let (Some(s), Some(p)) = (self.session.get_untracked(), self.account(PRIMARY)) {
            let keys = json!({
                "userKey": p.keys.user.to_b64().as_str(),
                "server": s.server,
                "deviceId": s.device_id,
                "tokens": p.tokens,
                "autoLockMinutes": self.settings.get_untracked().auto_lock_minutes,
            });
            env::store_set(Area::Session, EXT_KEYS, &keys.to_string()).await;
        }
        let _ = env::send_to_background(&json!({"type": "unlocked"})).await;
    }

    // -----------------------------------------------------------------------------------------
    // Eintraege
    // -----------------------------------------------------------------------------------------

    pub fn entry(&self, key: &str) -> Option<Entry> {
        self.entries.with_untracked(|e| e.iter().find(|x| x.key() == key).cloned())
    }

    /// Speichert einen Klartext-Eintrag (neu, wenn `cipher.id` leer ist).
    pub async fn save_entry(&self, account: &str, plain: Cipher) -> Result<String, String> {
        let acc = self.account(account).ok_or("Konto nicht gefunden")?;
        let req = vault::encrypt_cipher(&acc.keys, &plain).map_err(|e| e.to_string())?;
        let body = serde_json::to_value(&req).map_err(|e| e.to_string())?;
        let v = if plain.id.is_empty() {
            if plain.organization_id.is_some() {
                let ids = plain.collection_ids.clone().unwrap_or_default();
                self.call(account, "POST", "/api/ciphers/create", Some(json!({"cipher": body, "collectionIds": ids}))).await?
            } else {
                self.call(account, "POST", "/api/ciphers", Some(body)).await?
            }
        } else {
            self.call(account, "PUT", &format!("/api/ciphers/{}", plain.id), Some(body)).await?
        };
        let saved: Cipher = api::from_value_lenient(v).map_err(|e| e.to_string())?;
        let dec = vault::decrypt_cipher(&acc.keys, &saved).map_err(|e| e.to_string())?;
        let entry = Entry { account: account.to_string(), cipher: dec, broken: false };
        let key = entry.key();
        self.entries.update(|e| {
            e.retain(|x| x.key() != key);
            e.push(entry);
            e.sort_by_key(|a| a.name().to_lowercase());
        });
        self.publish_extension_index().await;
        Ok(key)
    }

    pub async fn delete_entry(&self, key: &str, permanent: bool) -> Result<(), String> {
        let e = self.entry(key).ok_or("Eintrag nicht gefunden")?;
        if permanent {
            self.call(&e.account, "DELETE", &format!("/api/ciphers/{}", e.cipher.id), None).await?;
            self.entries.update(|v| v.retain(|x| x.key() != key));
        } else {
            self.call(&e.account, "PUT", &format!("/api/ciphers/{}/delete", e.cipher.id), None).await?;
            let now = env::now_iso();
            self.entries.update(|v| {
                if let Some(x) = v.iter_mut().find(|x| x.key() == key) {
                    x.cipher.deleted_date = Some(now.clone());
                }
            });
        }
        if self.selected.get_untracked().as_deref() == Some(key) {
            self.selected.set(None);
        }
        self.publish_extension_index().await;
        Ok(())
    }

    pub async fn restore_entry(&self, key: &str) -> Result<(), String> {
        let e = self.entry(key).ok_or("Eintrag nicht gefunden")?;
        self.call(&e.account, "PUT", &format!("/api/ciphers/{}/restore", e.cipher.id), None).await?;
        self.entries.update(|v| {
            if let Some(x) = v.iter_mut().find(|x| x.key() == key) {
                x.cipher.deleted_date = None;
            }
        });
        self.publish_extension_index().await;
        Ok(())
    }

    /// Kopiert einen Eintrag (z. B. aus Vaultwarden) in den nrzPass-Tresor.
    pub async fn copy_to(&self, key: &str, target: &str) -> Result<String, String> {
        let e = self.entry(key).ok_or("Eintrag nicht gefunden")?;
        let mut c = e.cipher.clone();
        c.id = String::new();
        c.organization_id = None;
        c.collection_ids = None;
        c.key = None;
        c.folder_id = None;
        c.deleted_date = None;
        c.extra.remove("attachments");
        self.save_entry(target, c).await
    }

    pub async fn save_folder(&self, account: &str, id: Option<String>, name: &str) -> Result<(), String> {
        let acc = self.account(account).ok_or("Konto nicht gefunden")?;
        let body = json!({ "name": acc.keys.user.encrypt_str(name).to_string() });
        match id {
            Some(id) => self.call(account, "PUT", &format!("/api/folders/{id}"), Some(body)).await?,
            None => self.call(account, "POST", "/api/folders", Some(body)).await?,
        };
        self.sync_account(account).await
    }

    pub async fn delete_folder(&self, account: &str, id: &str) -> Result<(), String> {
        self.call(account, "DELETE", &format!("/api/folders/{id}"), None).await?;
        self.sync_account(account).await
    }

    /// Import: Ordner anlegen und Eintraege in einem Rutsch hochladen.
    pub async fn import(&self, account: &str, imp: vault::Imported) -> Result<usize, String> {
        let acc = self.account(account).ok_or("Konto nicht gefunden")?;
        let mut folder_names: Vec<String> = imp.folder_of.iter().flatten().cloned().collect();
        folder_names.sort();
        folder_names.dedup();
        let mut ciphers = Vec::new();
        let mut rel = Vec::new();
        for (i, c) in imp.items.iter().enumerate() {
            ciphers.push(vault::encrypt_cipher(&acc.keys, c).map_err(|e| e.to_string())?);
            if let Some(f) = &imp.folder_of[i] {
                if let Some(fi) = folder_names.iter().position(|x| x == f) {
                    rel.push(json!({"key": i, "value": fi}));
                }
            }
        }
        let folders: Vec<Value> = folder_names.iter().map(|n| json!({"name": acc.keys.user.encrypt_str(n).to_string()})).collect();
        let n = ciphers.len();
        self.call(account, "POST", "/api/ciphers/import", Some(json!({"ciphers": ciphers, "folders": folders, "folderRelationships": rel}))).await?;
        self.sync_account(account).await?;
        self.publish_extension_index().await;
        Ok(n)
    }

    // -----------------------------------------------------------------------------------------
    // Verknuepfte Konten (Vaultwarden / Bitwarden-kompatible Server)
    // -----------------------------------------------------------------------------------------

    async fn load_linked(&self) {
        let Ok(v) = self.call(PRIMARY, "GET", "/api/nrz/linked", None).await else { return };
        let list: Vec<api::LinkedAccount> = api::from_value_lenient(v).unwrap_or_default();
        let Some(primary) = self.account(PRIMARY) else { return };
        let mut accounts = vec![primary.clone()];
        for la in list {
            let Ok(text) = la.data.parse().and_then(|e| primary.keys.user.decrypt_str(&e)) else { continue };
            let Ok(data) = serde_json::from_str::<LinkedAccountData>(&text) else { continue };
            let Ok(uk) = SymmetricKey::from_b64(&data.user_key) else { continue };
            let existing = self.account(&la.id);
            let via = if env::platform() == Platform::Web {
                Via::Proxy(primary.server.clone(), primary.tokens.access.clone())
            } else {
                crate::net::default_via()
            };
            accounts.push(Account {
                id: la.id.clone(),
                label: data.label.clone(),
                email: data.email.clone(),
                server: data.server.clone(),
                keys: existing.as_ref().map(|e| e.keys.clone()).unwrap_or_else(|| KeyRing::new(uk)),
                tokens: existing.as_ref().map(|e| e.tokens.clone()).unwrap_or(Tokens { refresh: data.refresh_token.clone(), ..Default::default() }),
                conn: Conn { base: data.server.clone(), via, device_id: data.device_id.clone() },
                error: None,
                two_factor: false,
                kind: AccountKind::Linked { linked_id: la.id.clone(), data },
            });
        }
        // Eintraege entfernter Konten verwerfen
        let ids: Vec<String> = accounts.iter().map(|a| a.id.clone()).collect();
        self.entries.update(|e| e.retain(|x| ids.contains(&x.account)));
        self.folders.update(|f| f.retain(|x| ids.contains(&x.account)));
        self.accounts.set(accounts);
    }

    async fn save_linked(&self, id: Option<String>, data: &LinkedAccountData) -> Result<String, String> {
        let p = self.account(PRIMARY).ok_or("nrzPass-Konto fehlt")?;
        let enc = p.keys.user.encrypt_str(&serde_json::to_string(data).unwrap()).to_string();
        let body = json!({ "data": enc });
        let v = match id {
            Some(id) => self.call(PRIMARY, "PUT", &format!("/api/nrz/linked/{id}"), Some(body)).await?,
            None => self.call(PRIMARY, "POST", "/api/nrz/linked", Some(body)).await?,
        };
        Ok(v["id"].as_str().unwrap_or_default().to_string())
    }

    /// Vaultwarden-Konto hinzufuegen. `Ok(Some(..))` = Zwei-Faktor-Code noetig.
    pub async fn add_linked(&self, label: &str, server: &str, email: &str, password: &str, totp: Option<String>) -> Result<Option<Vec<String>>, String> {
        let base = normalize_server(server);
        let email = crypto::normalize_email(email);
        let device_id = uuid::Uuid::new_v4().to_string();
        let via = if env::platform() == Platform::Web {
            self.fresh_tokens(PRIMARY, false).await?;
            self.primary_via_proxy().ok_or("nrzPass-Konto fehlt")?
        } else {
            crate::net::default_via()
        };
        let conn = Conn { base: base.clone(), via, device_id: device_id.clone() };
        let kdf = conn.prelogin(&email).await?;
        let master = MasterKey::derive(password, &email, kdf).map_err(|e| e.to_string())?;
        let hash = master.password_hash(password);
        let t = match conn.login(&email, &hash, totp.map(|c| (c, 0, false)), None).await {
            Ok(t) => t,
            Err(LoginError::TwoFactor(p)) => return Ok(Some(p)),
            Err(LoginError::Msg(m)) => return Err(m),
        };
        let uk = crypto::unlock_user_key(&master, t.key.as_deref().ok_or("Kein Schlüssel vom Server")?)
            .map_err(|_| "Schlüssel des Vaultwarden-Kontos nicht entschlüsselbar".to_string())?;
        let data = LinkedAccountData {
            label: if label.trim().is_empty() { "Vaultwarden".into() } else { label.trim().into() },
            server: base,
            email,
            device_id,
            refresh_token: t.refresh_token.clone().ok_or("Server lieferte kein Refresh-Token")?,
            user_key: uk.to_b64().to_string(),
            private_key: t.private_key.clone(),
        };
        let id = self.save_linked(None, &data).await?;
        self.load_linked().await;
        self.accounts.update(|a| {
            if let Some(x) = a.iter_mut().find(|x| x.id == id) {
                x.tokens = Tokens::from_response(&t);
            }
        });
        self.sync_account(&id).await?;
        self.publish_extension_index().await;
        Ok(None)
    }

    pub async fn remove_linked(&self, id: &str) -> Result<(), String> {
        self.call(PRIMARY, "DELETE", &format!("/api/nrz/linked/{id}"), None).await?;
        self.load_linked().await;
        self.publish_extension_index().await;
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // Konto-Sicherheit
    // -----------------------------------------------------------------------------------------

    /// Master-Passwort pruefen und den Server-Hash liefern.
    pub fn verify_master(&self, password: &str) -> Result<String, String> {
        let s = self.session.get_untracked().ok_or("Nicht angemeldet")?;
        let master = MasterKey::derive(password, &s.email, s.kdf).map_err(|e| e.to_string())?;
        crypto::unlock_user_key(&master, &s.protected_key).map_err(|_| "Falsches Master-Passwort".to_string())?;
        Ok(master.password_hash(password))
    }

    pub async fn change_password(&self, current: &str, new: &str, hint: &str, kdf: Kdf) -> Result<(), String> {
        let s = self.session.get_untracked().ok_or("Nicht angemeldet")?;
        let current_hash = self.verify_master(current)?;
        let p = self.account(PRIMARY).ok_or("Gesperrt")?;
        let (new_hash, new_key) = crypto::rewrap_user_key(&p.keys.user, new, &s.email, kdf).map_err(|e| e.to_string())?;
        self.call(
            PRIMARY,
            "POST",
            "/api/accounts/password",
            Some(json!({
                "masterPasswordHash": current_hash,
                "newMasterPasswordHash": new_hash,
                "masterPasswordHint": if hint.is_empty() { Value::Null } else { Value::String(hint.into()) },
                "key": new_key,
                "kdf": kdf.kind(),
                "kdfIterations": kdf.iterations(),
                "kdfMemory": kdf.memory(),
                "kdfParallelism": kdf.parallelism(),
            })),
        )
        .await?;
        // Alle Sitzungen wurden beendet: mit dem neuen Passwort neu anmelden.
        let server = s.server.clone();
        let email = s.email.clone();
        match self.login(&server, &email, new, None).await {
            Ok(None) => Ok(()),
            _ => {
                self.logout().await;
                Err("Passwort geändert – bitte neu anmelden".into())
            }
        }
    }

    pub fn primary(&self) -> Option<Account> {
        self.account(PRIMARY)
    }
}
