//! Gesamter Ablauf gegen einen echten Server auf einem freien Port.

use nrzpass_core::api::{self, Cipher, CipherLogin, LoginUri};
use nrzpass_core::crypto::{self, Kdf, MasterKey, SymmetricKey};
use nrzpass_core::vault::{self, KeyRing};
use serde_json::{json, Value};
use std::net::SocketAddr;

const KDF: Kdf = Kdf::Argon2id { iterations: 2, memory: 16, parallelism: 1 };
const EMAIL: &str = "Nico@Example.ch";

struct T {
    base: String,
    http: reqwest::Client,
}

impl T {
    async fn post(&self, path: &str, token: Option<&str>, body: Value) -> (u16, Value) {
        let mut r = self.http.post(format!("{}{path}", self.base)).json(&body);
        if let Some(t) = token {
            r = r.bearer_auth(t);
        }
        let resp = r.send().await.unwrap();
        (resp.status().as_u16(), resp.json().await.unwrap_or(Value::Null))
    }
    async fn put(&self, path: &str, token: &str, body: Value) -> (u16, Value) {
        let resp = self.http.put(format!("{}{path}", self.base)).bearer_auth(token).json(&body).send().await.unwrap();
        (resp.status().as_u16(), resp.json().await.unwrap_or(Value::Null))
    }
    async fn get(&self, path: &str, token: Option<&str>) -> (u16, Value) {
        let mut r = self.http.get(format!("{}{path}", self.base));
        if let Some(t) = token {
            r = r.bearer_auth(t);
        }
        let resp = r.send().await.unwrap();
        (resp.status().as_u16(), resp.json().await.unwrap_or(Value::Null))
    }
    async fn delete(&self, path: &str, token: &str) -> u16 {
        self.http.delete(format!("{}{path}", self.base)).bearer_auth(token).send().await.unwrap().status().as_u16()
    }
    async fn token(&self, form: &[(&str, &str)]) -> (u16, Value) {
        let resp = self.http.post(format!("{}/identity/connect/token", self.base)).form(form).send().await.unwrap();
        (resp.status().as_u16(), resp.json().await.unwrap_or(Value::Null))
    }
    async fn login(&self, hash: &str, extra: &[(&str, &str)]) -> (u16, Value) {
        let mut f = vec![
            ("grant_type", "password"),
            ("username", EMAIL),
            ("password", hash),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("deviceType", "10"),
            ("deviceIdentifier", "6b1c9a1e-2f8b-4c55-9d43-1a3c1f6a0001"),
            ("deviceName", "Testgeraet"),
        ];
        f.extend_from_slice(extra);
        self.token(&f).await
    }
}

async fn start() -> (T, tempdir::TempDir) {
    let dir = tempdir::TempDir::new();
    let mut cfg = nrzpass_server::Config::for_dir(dir.0.clone());
    cfg.identity_rate_per_min = 10_000;
    std::fs::create_dir_all(&cfg.download_dir).unwrap();
    std::fs::write(cfg.download_dir.join("nrzPass-test.zip"), b"zip").unwrap();
    let app = nrzpass_server::build(cfg).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    (T { base: format!("http://{addr}"), http: reqwest::Client::new() }, dir)
}

mod tempdir {
    pub struct TempDir(pub std::path::PathBuf);
    impl TempDir {
        pub fn new() -> TempDir {
            let p = std::env::temp_dir().join(format!("nrzpass-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

#[tokio::test]
async fn full_flow() {
    let (t, dir) = start().await;

    // Serverinfo, Sicherheits-Header, Web-Oberflaeche
    let (s, info) = t.get("/api/nrz/info", None).await;
    assert_eq!(s, 200);
    assert_eq!(info["hasUsers"], false);
    assert_eq!(info["signupsAllowed"], true);
    let r = t.http.get(format!("{}/irgendwas", t.base)).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.headers()["content-security-policy"].to_str().unwrap().contains("frame-ancestors 'none'"));
    assert_eq!(r.headers()["x-frame-options"], "DENY");
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert_eq!(t.get("/api/gibtsnicht", None).await.0, 404);
    // CORS fuer die Erweiterung, nicht fuer fremde Seiten
    let pre = |origin: &'static str| {
        t.http
            .request(reqwest::Method::OPTIONS, format!("{}/api/sync", t.base))
            .header("Origin", origin)
            .header("Access-Control-Request-Method", "GET")
            .header("Access-Control-Request-Headers", "authorization")
            .send()
    };
    let ok = pre("chrome-extension://abcdef").await.unwrap();
    assert_eq!(ok.headers().get("access-control-allow-origin").unwrap(), "chrome-extension://abcdef");
    let bad = pre("https://evil.example").await.unwrap();
    assert!(bad.headers().get("access-control-allow-origin").is_none());

    // Registrierung
    let pw = "Sehr-Geheimes-Master-Passwort-1";
    let acc = crypto::make_account(pw, EMAIL, KDF, true).unwrap();
    let reg = json!({
        "email": EMAIL, "name": "Nico", "masterPasswordHash": acc.master_password_hash, "masterPasswordHint": "Hinweis",
        "key": acc.protected_user_key, "kdf": KDF.kind(), "kdfIterations": KDF.iterations(), "kdfMemory": KDF.memory(),
        "kdfParallelism": KDF.parallelism(),
        "keys": {"publicKey": acc.public_key_b64, "encryptedPrivateKey": acc.encrypted_private_key}
    });
    let (s, b) = t.post("/identity/accounts/register", None, reg.clone()).await;
    assert_eq!(s, 200, "{b}");
    let mut second = reg.clone();
    second["email"] = json!("zweite@example.ch");
    let (s, _) = t.post("/api/accounts/register", None, second).await;
    assert_eq!(s, 403, "zweite Registrierung muss geschlossen sein");
    // Schwache KDF wird abgelehnt
    let mut weak = reg.clone();
    weak["email"] = json!("weak@y.ch");
    weak["kdf"] = json!(0);
    weak["kdfIterations"] = json!(1000);
    assert_eq!(t.post("/api/accounts/register", None, weak).await.0, 400);

    // Prelogin
    let (_, pre) = t.post("/identity/accounts/prelogin", None, json!({"email": "nico@example.ch"})).await;
    assert_eq!(pre["kdf"], 1);
    assert_eq!(pre["kdfIterations"], 2);
    assert_eq!(pre["kdfMemory"], 16);
    let (_, unknown) = t.post("/identity/accounts/prelogin", None, json!({"Email": "niemand@example.ch"})).await;
    assert_eq!(unknown["kdfMemory"], 64);

    // Anmeldung
    let mk = MasterKey::derive(pw, EMAIL, KDF).unwrap();
    let hash = mk.password_hash(pw);
    let (s, b) = t.login("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", &[]).await;
    assert_eq!(s, 400);
    assert_eq!(b["error"], "invalid_grant");
    let (s, tok) = t.login(&hash, &[]).await;
    assert_eq!(s, 200, "{tok}");
    let parsed: api::TokenResponse = api::from_value_lenient(tok.clone()).unwrap();
    let access = parsed.access_token.clone();
    let user_key = crypto::unlock_user_key(&mk, parsed.key.as_deref().unwrap()).unwrap();
    assert_eq!(user_key, acc.user_key);
    let keys = KeyRing::new(user_key.clone());

    // Ohne Token: 401
    assert_eq!(t.get("/api/sync", None).await.0, 401);
    assert_eq!(t.get("/api/sync", Some("falsch")).await.0, 401);

    // Ordner + Eintrag
    let (s, folder) = t.post("/api/folders", Some(&access), json!({"name": user_key.encrypt_str("Arbeit").to_string()})).await;
    assert_eq!(s, 200, "{folder}");
    let folder_id = folder["id"].as_str().unwrap().to_string();
    assert_eq!(t.post("/api/folders", Some(&access), json!({"name": "Klartext"})).await.0, 400);

    let plain = Cipher {
        cipher_type: 1,
        folder_id: Some(folder_id.clone()),
        name: Some("GitHub".into()),
        notes: Some("Notiz".into()),
        login: Some(CipherLogin {
            username: Some("nico".into()),
            password: Some("geheim-1".into()),
            uris: Some(vec![LoginUri { uri: Some("https://github.com".into()), match_type: None, ..Default::default() }]),
            ..Default::default()
        }),
        edit: true,
        ..Default::default()
    };
    let req = vault::encrypt_cipher(&keys, &plain).unwrap();
    let (s, created) = t.post("/api/ciphers", Some(&access), serde_json::to_value(&req).unwrap()).await;
    assert_eq!(s, 200, "{created}");
    let cid = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["object"], "cipherDetails");
    // Klartext wird abgelehnt
    let mut bad = serde_json::to_value(&req).unwrap();
    bad["name"] = json!("Klartext");
    assert_eq!(t.post("/api/ciphers", Some(&access), bad).await.0, 400);
    let mut org = serde_json::to_value(&req).unwrap();
    org["organizationId"] = json!(uuid::Uuid::new_v4().to_string());
    assert_eq!(t.post("/api/ciphers", Some(&access), org).await.0, 400);

    // Sync + Entschluesseln
    let (s, sync) = t.get("/api/sync", Some(&access)).await;
    assert_eq!(s, 200);
    let sync: api::SyncResponse = api::from_value_lenient(sync).unwrap();
    assert_eq!(sync.profile.email, "nico@example.ch");
    assert_eq!(sync.ciphers.len(), 1);
    let dec = vault::decrypt_cipher(&keys, &sync.ciphers[0]).unwrap();
    assert_eq!(dec.name.as_deref(), Some("GitHub"));
    assert_eq!(dec.login.as_ref().unwrap().password.as_deref(), Some("geheim-1"));
    assert_eq!(dec.folder_id.as_deref(), Some(folder_id.as_str()));
    assert_eq!(vault::decrypt_folder(&keys, &sync.folders[0]).unwrap().name, "Arbeit");

    // Aendern, Konflikt, Papierkorb
    let mut edited = dec.clone();
    vault::set_password(&mut edited, "geheim-2", "2026-01-01T00:00:00.000Z");
    let (s, upd) = t.put(&format!("/api/ciphers/{cid}"), &access, serde_json::to_value(vault::encrypt_cipher(&keys, &edited).unwrap()).unwrap()).await;
    assert_eq!(s, 200, "{upd}");
    let mut stale = vault::encrypt_cipher(&keys, &edited).unwrap();
    stale.last_known_revision_date = Some("2020-01-01T00:00:00.000Z".into());
    assert_eq!(t.put(&format!("/api/ciphers/{cid}"), &access, serde_json::to_value(stale).unwrap()).await.0, 400);
    assert_eq!(t.put(&format!("/api/ciphers/{cid}/delete"), &access, json!({})).await.0, 200);
    let (_, one) = t.get(&format!("/api/ciphers/{cid}"), Some(&access)).await;
    assert!(one["deletedDate"].is_string());
    assert_eq!(t.put(&format!("/api/ciphers/{cid}/restore"), &access, json!({})).await.0, 200);

    // Import
    let imp = json!({
        "ciphers": [serde_json::to_value(vault::encrypt_cipher(&keys, &Cipher { id: String::new(), folder_id: None, ..plain.clone() }).unwrap()).unwrap(),
                    serde_json::to_value(vault::encrypt_cipher(&keys, &Cipher { id: String::new(), folder_id: None, ..plain.clone() }).unwrap()).unwrap()],
        "folders": [{"name": user_key.encrypt_str("Import").to_string()}],
        "folderRelationships": [{"key": 1, "value": 0}]
    });
    let (s, b) = t.post("/api/ciphers/import", Some(&access), imp).await;
    assert_eq!(s, 200, "{b}");
    let (_, sync) = t.get("/api/sync", Some(&access)).await;
    assert_eq!(sync["ciphers"].as_array().unwrap().len(), 3);
    assert_eq!(sync["folders"].as_array().unwrap().len(), 2);

    // Ordner loeschen -> Eintraege ohne Ordner
    assert_eq!(t.delete(&format!("/api/folders/{folder_id}"), &access).await, 200);
    let (_, one) = t.get(&format!("/api/ciphers/{cid}"), Some(&access)).await;
    assert!(one["folderId"].is_null());

    // Verknuepfte Konten
    assert_eq!(t.post("/api/nrz/linked", Some(&access), json!({"data": "klartext"})).await.0, 400);
    let (s, linked) = t.post("/api/nrz/linked", Some(&access), json!({"data": user_key.encrypt_str("{}").to_string()})).await;
    assert_eq!(s, 200);
    let lid = linked["id"].as_str().unwrap().to_string();
    assert_eq!(t.put(&format!("/api/nrz/linked/{lid}"), &access, json!({"data": user_key.encrypt_str("{1}").to_string()})).await.0, 200);
    let (_, list) = t.get("/api/nrz/linked", Some(&access)).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(t.delete(&format!("/api/nrz/linked/{lid}"), &access).await, 200);

    // Proxy lehnt gefaehrliche Adressen ab
    for url in ["ftp://example.com/api/x", "http://example.com/admin", "http://169.254.169.254/api/x", "http://user:pw@example.com/api/sync"] {
        let (s, _) = t.post("/api/nrz/proxy", Some(&access), json!({"url": url, "method": "GET"})).await;
        assert_eq!(s, 400, "{url}");
    }
    assert_eq!(t.post("/api/nrz/proxy", None, json!({"url": "http://example.com/api/x"})).await.0, 401);
    // ... und funktioniert gegen einen Bitwarden-kompatiblen Server (hier: sich selbst)
    let (s, b) = t.post("/api/nrz/proxy", Some(&access), json!({"url": format!("{}/api/alive", t.base), "method": "GET"})).await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(b["status"], 200);

    // Downloads
    let (_, dl) = t.get("/api/nrz/downloads", None).await;
    assert_eq!(dl[0]["name"], "nrzPass-test.zip");
    let r = t.http.get(format!("{}/downloads/nrzPass-test.zip", t.base)).send().await.unwrap();
    assert!(r.headers()["content-disposition"].to_str().unwrap().contains("attachment"));
    assert_eq!(t.http.get(format!("{}/downloads/..%2Fnrzpass.db", t.base)).send().await.unwrap().status(), 404);

    // Geraete und Protokoll
    let (_, devs) = t.get("/api/nrz/devices", Some(&access)).await;
    assert_eq!(devs.as_array().unwrap().len(), 1);
    assert_eq!(devs[0]["current"], true);
    let (_, ev) = t.get("/api/nrz/events", Some(&access)).await;
    let kinds: Vec<&str> = ev.as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap()).collect();
    assert!(kinds.contains(&"register") && kinds.contains(&"login") && kinds.contains(&"login_failed"));

    // Refresh-Token: Rotation und Diebstahlerkennung
    let refresh1 = parsed.refresh_token.clone().unwrap();
    let (s, r2) = t.token(&[("grant_type", "refresh_token"), ("client_id", "web"), ("refresh_token", &refresh1)]).await;
    assert_eq!(s, 200, "{r2}");
    let refresh2 = r2["refresh_token"].as_str().unwrap().to_string();
    let access2 = r2["access_token"].as_str().unwrap().to_string();
    assert_eq!(t.get("/api/sync", Some(&access2)).await.0, 200);
    let (s, _) = t.token(&[("grant_type", "refresh_token"), ("refresh_token", &refresh1)]).await;
    assert_eq!(s, 400, "altes Refresh-Token darf nicht mehr gehen");
    let (s, _) = t.token(&[("grant_type", "refresh_token"), ("refresh_token", &refresh2)]).await;
    assert_eq!(s, 400, "nach Wiederverwendung ist das Geraet abgemeldet");
    assert_eq!(t.get("/api/sync", Some(&access2)).await.0, 401);

    // Neu anmelden, Master-Passwort aendern
    let (_, tok) = t.login(&hash, &[]).await;
    let access = tok["access_token"].as_str().unwrap().to_string();
    let new_pw = "Neues-Master-Passwort-2";
    let (new_hash, new_key) = crypto::rewrap_user_key(&user_key, new_pw, EMAIL, KDF).unwrap();
    let (s, _) = t.post("/api/accounts/password", Some(&access), json!({
        "masterPasswordHash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "newMasterPasswordHash": new_hash, "key": new_key
    })).await;
    assert_eq!(s, 400, "falsches aktuelles Passwort");
    let (s, b) = t.post("/api/accounts/password", Some(&access), json!({
        "masterPasswordHash": hash, "newMasterPasswordHash": new_hash, "key": new_key
    })).await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(t.get("/api/sync", Some(&access)).await.0, 401, "alte Sitzung ist nach Passwortwechsel ungueltig");
    assert_eq!(t.login(&hash, &[]).await.0, 400);
    let (s, tok) = t.login(&new_hash, &[]).await;
    assert_eq!(s, 200);
    let access = tok["access_token"].as_str().unwrap().to_string();
    let mk2 = MasterKey::derive(new_pw, EMAIL, KDF).unwrap();
    assert_eq!(crypto::unlock_user_key(&mk2, tok["Key"].as_str().unwrap()).unwrap(), user_key);
    let hash = new_hash;

    // Zwei-Faktor
    let (s, ga) = t.post("/api/two-factor/get-authenticator", Some(&access), json!({"masterPasswordHash": hash})).await;
    assert_eq!(s, 200);
    assert_eq!(ga["enabled"], false);
    let secret = ga["key"].as_str().unwrap().to_string();
    let totp = nrzpass_core::totp::Totp::parse(&secret).unwrap();
    let (s, _) = t.put("/api/two-factor/authenticator", &access, json!({"key": secret, "token": "000000x", "masterPasswordHash": hash})).await;
    assert_eq!(s, 400);
    let enabled_at = now();
    let (s, en) = t.put("/api/two-factor/authenticator", &access, json!({"key": secret, "token": totp.code_at(enabled_at), "masterPasswordHash": hash})).await;
    assert_eq!(s, 200, "{en}");
    assert_eq!(en["enabled"], true);
    let (_, list) = t.get("/api/two-factor", Some(&access)).await;
    assert_eq!(list["data"][0]["enabled"], true);

    let (s, b) = t.login(&hash, &[]).await;
    assert_eq!(s, 400);
    assert_eq!(b["TwoFactorProviders"][0], "0");
    // Wiederverwendung des eben benutzten Codes wird abgelehnt
    let used = totp.code_at(enabled_at);
    let (s, _) = t.login(&hash, &[("twoFactorToken", &used), ("twoFactorProvider", "0")]).await;
    assert_eq!(s, 400);
    let next = totp.code_at(enabled_at + 30);
    let (s, b) = t.login(&hash, &[("twoFactorToken", &next), ("twoFactorProvider", "0"), ("twoFactorRemember", "1")]).await;
    assert_eq!(s, 200, "{b}");
    let remember = b["TwoFactorToken"].as_str().unwrap().to_string();
    let (s, b) = t.login(&hash, &[("twoFactorToken", &remember), ("twoFactorProvider", "5")]).await;
    assert_eq!(s, 200, "{b}");
    let access = b["access_token"].as_str().unwrap().to_string();
    let (s, _) = t.login(&hash, &[("twoFactorToken", "falsch"), ("twoFactorProvider", "5")]).await;
    assert_eq!(s, 400);
    let (s, b) = t.put("/api/two-factor/disable", &access, json!({"masterPasswordHash": hash, "type": 0})).await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(t.login(&hash, &[]).await.0, 200);

    // Sperre nach 5 Fehlversuchen (auch mit richtigem Passwort danach)
    for _ in 0..5 {
        assert_eq!(t.login("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", &[]).await.0, 400);
    }
    assert_eq!(t.login(&hash, &[]).await.0, 429);

    // Konto loeschen
    assert_eq!(t.post("/api/accounts/delete", Some(&access), json!({"masterPasswordHash": hash})).await.0, 200);
    let (_, info) = t.get("/api/nrz/info", None).await;
    assert_eq!(info["hasUsers"], false);

    // Datenbankdatei enthaelt keinen Klartext (Turso-Verschluesselung)
    let raw = std::fs::read(dir.0.join("nrzpass.db")).unwrap();
    assert!(!raw.windows(5).any(|w| w == b"users"), "Schema darf nicht lesbar sein");
    let _ = SymmetricKey::generate();
}

