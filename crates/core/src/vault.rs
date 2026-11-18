//! Ver- und Entschluesselung ganzer Eintraege, Export/Import.
//!
//! Ein entschluesselter Eintrag ist ein [`Cipher`] mit Klartext in den Textfeldern. So bleiben
//! alle Strukturen (und unbekannte Felder wie Passkeys) erhalten, und ein in nrzPass bearbeiteter
//! Vaultwarden-Eintrag sieht fuer die offiziellen Bitwarden-Clients unveraendert aus.

use crate::api::{self, Cipher, CipherRequest, Folder};
use crate::crypto::{self, CryptoError, Kdf, MasterKey, PrivateKey, Result, SymmetricKey};
use serde_json::{json, Value};
use std::collections::HashMap;

/// Alle Schluessel eines entsperrten Kontos.
#[derive(Clone, Debug)]
pub struct KeyRing {
    pub user: SymmetricKey,
    pub orgs: HashMap<String, SymmetricKey>,
}

impl KeyRing {
    pub fn new(user: SymmetricKey) -> KeyRing {
        KeyRing { user, orgs: HashMap::new() }
    }

    /// Organisationsschluessel aus dem Profil laden (Vaultwarden-Organisationen).
    pub fn load_orgs(&mut self, profile: &api::Profile) {
        let Some(pk) = profile.private_key.as_deref().filter(|s| !s.is_empty()) else { return };
        let Ok(pk) = PrivateKey::from_encrypted(&self.user, pk) else { return };
        for org in &profile.organizations {
            if let Some(k) = org.key.as_deref() {
                if let Ok(key) = pk.decrypt_org_key(k) {
                    self.orgs.insert(org.id.clone(), key);
                }
            }
        }
    }

    pub fn key_for(&self, org: Option<&str>) -> Result<&SymmetricKey> {
        match org {
            None => Ok(&self.user),
            Some(id) => self.orgs.get(id).ok_or(CryptoError::KeyLength),
        }
    }

    /// Schluessel fuer die Felder eines Eintrags (eigener Eintragsschluessel, falls vorhanden).
    pub fn item_key(&self, c: &Cipher) -> Result<SymmetricKey> {
        let base = self.key_for(c.organization_id.as_deref())?;
        match c.key.as_deref().filter(|k| !k.is_empty()) {
            Some(k) => SymmetricKey::from_bytes(&base.decrypt(&k.parse()?)?),
            None => Ok(base.clone()),
        }
    }
}

fn map_opt(v: &mut Option<String>, f: &mut impl FnMut(&mut String) -> Result<()>) -> Result<()> {
    if v.as_deref() == Some("") {
        *v = None;
    } else if let Some(s) = v.as_mut() {
        f(s)?;
    }
    Ok(())
}

/// Sichtbare Felder (Name, Benutzername, Adressen, ...): werden fuer Liste und Suche entschluesselt.
fn walk_public(c: &mut Cipher, f: &mut impl FnMut(&mut String) -> Result<()>) -> Result<()> {
    map_opt(&mut c.name, f)?;
    if let Some(l) = c.login.as_mut() {
        map_opt(&mut l.username, f)?;
        for u in l.uris.iter_mut().flatten() {
            map_opt(&mut u.uri, f)?;
        }
    }
    if let Some(k) = c.card.as_mut() {
        for v in [&mut k.cardholder_name, &mut k.brand, &mut k.exp_month, &mut k.exp_year] {
            map_opt(v, f)?;
        }
    }
    if let Some(i) = c.identity.as_mut() {
        for v in [
            &mut i.title, &mut i.first_name, &mut i.middle_name, &mut i.last_name, &mut i.address1, &mut i.address2,
            &mut i.address3, &mut i.city, &mut i.state, &mut i.postal_code, &mut i.country, &mut i.company,
            &mut i.email, &mut i.phone, &mut i.username,
        ] {
            map_opt(v, f)?;
        }
    }
    for fl in c.fields.iter_mut().flatten() {
        map_opt(&mut fl.name, f)?;
        if fl.field_type != FIELD_HIDDEN {
            map_opt(&mut fl.value, f)?;
        }
    }
    Ok(())
}

/// Geheime Felder (Passwort, TOTP-Schluessel, Notizen, Kartennummer, CVC, Ausweisnummern, versteckte
/// Felder, Passwortverlauf): bleiben im Speicher verschluesselt, bis sie gebraucht werden.
fn walk_secret(c: &mut Cipher, f: &mut impl FnMut(&mut String) -> Result<()>) -> Result<()> {
    map_opt(&mut c.notes, f)?;
    if let Some(l) = c.login.as_mut() {
        map_opt(&mut l.password, f)?;
        map_opt(&mut l.totp, f)?;
    }
    if let Some(k) = c.card.as_mut() {
        map_opt(&mut k.number, f)?;
        map_opt(&mut k.code, f)?;
    }
    if let Some(i) = c.identity.as_mut() {
        for v in [&mut i.ssn, &mut i.passport_number, &mut i.license_number] {
            map_opt(v, f)?;
        }
    }
    for fl in c.fields.iter_mut().flatten() {
        if fl.field_type == FIELD_HIDDEN {
            map_opt(&mut fl.value, f)?;
        }
    }
    for h in c.password_history.iter_mut().flatten() {
        if !h.password.is_empty() {
            f(&mut h.password)?;
        }
    }
    Ok(())
}

/// Wendet `f` auf jedes verschluesselte Textfeld eines Eintrags an.
fn walk(c: &mut Cipher, f: &mut impl FnMut(&mut String) -> Result<()>) -> Result<()> {
    walk_public(c, f)?;
    walk_secret(c, f)
}

/// Typ "versteckt" bei eigenen Feldern.
pub const FIELD_HIDDEN: i64 = 1;

fn decrypt_in_place(key: &SymmetricKey) -> impl FnMut(&mut String) -> Result<()> + '_ {
    move |s: &mut String| {
        let plain = key.decrypt_str(&s.parse()?)?;
        *s = plain;
        Ok(())
    }
}

/// Entschluesselt einen Eintrag vollstaendig. Schlaegt nur dieser Eintrag fehl, bleibt der Rest des
/// Tresors nutzbar.
pub fn decrypt_cipher(keys: &KeyRing, c: &Cipher) -> Result<Cipher> {
    let key = keys.item_key(c)?;
    let mut out = c.clone();
    walk(&mut out, &mut decrypt_in_place(&key))?;
    // Pruefsummen der URIs sind nur fuer den Server/Client-Abgleich und bleiben verschluesselt.
    Ok(out)
}

/// Entschluesselt nur die sichtbaren Felder; Passwoerter, TOTP-Schluessel usw. bleiben als
/// EncString-Text im Eintrag stehen (siehe [`reveal`] und [`open_secret`]).
pub fn decrypt_listing(keys: &KeyRing, c: &Cipher) -> Result<Cipher> {
    let key = keys.item_key(c)?;
    let mut out = c.clone();
    walk_public(&mut out, &mut decrypt_in_place(&key))?;
    // Geheime Felder nur auf Lesbarkeit pruefen, nicht entschluesselt aufbewahren
    let mut probe = c.clone();
    walk_secret(&mut probe, &mut |s: &mut String| {
        let _ = s.parse::<crypto::EncString>()?;
        Ok(())
    })?;
    Ok(out)
}

/// Klartext-Eintrag, dessen geheime Felder beim Verwerfen ueberschrieben werden.
pub struct Revealed(Cipher);

impl Revealed {
    /// Gibt den Klartext heraus (z. B. fuer den Editor); ab dann ohne automatisches Ueberschreiben.
    pub fn into_inner(mut self) -> Cipher {
        std::mem::take(&mut self.0)
    }
}

impl std::ops::Deref for Revealed {
    type Target = Cipher;
    fn deref(&self) -> &Cipher {
        &self.0
    }
}

impl std::ops::DerefMut for Revealed {
    fn deref_mut(&mut self) -> &mut Cipher {
        &mut self.0
    }
}

impl Drop for Revealed {
    fn drop(&mut self) {
        wipe_secrets(&mut self.0);
    }
}

/// Ueberschreibt alle geheimen Felder eines Klartext-Eintrags mit Nullen.
pub fn wipe_secrets(c: &mut Cipher) {
    use zeroize::Zeroize;
    let _ = walk_secret(c, &mut |s: &mut String| {
        s.zeroize();
        Ok(())
    });
}

/// Entschluesselt die geheimen Felder eines mit [`decrypt_listing`] geladenen Eintrags – nur fuer
/// den Moment, in dem sie gebraucht werden.
pub fn reveal(keys: &KeyRing, listing: &Cipher) -> Result<Revealed> {
    let key = keys.item_key(listing)?;
    let mut out = Revealed(listing.clone());
    walk_secret(&mut out.0, &mut decrypt_in_place(&key))?;
    Ok(out)
}

/// Entschluesselt ein einzelnes geheimes Feld eines Eintrags.
pub fn open_secret(keys: &KeyRing, listing: &Cipher, enc: &str) -> Result<zeroize::Zeroizing<String>> {
    let key = keys.item_key(listing)?;
    Ok(zeroize::Zeroizing::new(key.decrypt_str(&enc.parse()?)?))
}

/// Verschluesselt einen (Klartext-)Eintrag fuer `POST/PUT /api/ciphers`.
pub fn encrypt_cipher(keys: &KeyRing, plain: &Cipher) -> Result<CipherRequest> {
    let key = keys.item_key(plain)?;
    let mut c = plain.clone();
    // Neue URI-Pruefsummen (Bitwarden >= 2023.x prueft sie beim Autofill)
    if let Some(l) = c.login.as_mut() {
        for u in l.uris.iter_mut().flatten() {
            if u.extra.contains_key("uriChecksum") {
                let sum = u.uri.as_deref().map(|uri| {
                    use sha2::Digest;
                    key.encrypt_str(&crypto::b64(&sha2::Sha256::digest(uri.as_bytes()))).to_string()
                });
                u.extra.insert("uriChecksum".into(), sum.map(Value::String).unwrap_or(Value::Null));
            }
        }
    }
    walk(&mut c, &mut |s: &mut String| {
        let enc = key.encrypt_str(s).to_string();
        zeroize::Zeroize::zeroize(s);
        *s = enc;
        Ok(())
    })?;
    let mut extra = c.extra.clone();
    for k in ["object", "edit", "viewPassword", "organizationUseTotp", "attachments", "permissions"] {
        extra.remove(k);
    }
    Ok(CipherRequest {
        cipher_type: c.cipher_type,
        organization_id: c.organization_id,
        folder_id: c.folder_id.filter(|s| !s.is_empty()),
        name: c.name,
        notes: c.notes,
        favorite: c.favorite,
        reprompt: c.reprompt,
        key: c.key,
        login: c.login,
        card: c.card,
        identity: c.identity,
        secure_note: c.secure_note,
        fields: c.fields,
        password_history: c.password_history,
        last_known_revision_date: c.revision_date,
        extra,
    })
}

pub fn decrypt_folder(keys: &KeyRing, f: &Folder) -> Result<Folder> {
    Ok(Folder { name: keys.user.decrypt_str(&f.name.parse()?)?, ..f.clone() })
}

/// Neues Passwort setzen und das alte in den Verlauf schreiben (max. 5 wie Bitwarden).
pub fn set_password(c: &mut Cipher, new_pw: &str, now_iso: &str) {
    let login = c.login.get_or_insert_with(Default::default);
    if let Some(old) = login.password.as_deref().filter(|p| !p.is_empty() && *p != new_pw) {
        let hist = c.password_history.get_or_insert_with(Vec::new);
        hist.insert(0, api::PasswordHistory { password: old.to_string(), last_used_date: now_iso.to_string() });
        hist.truncate(5);
        login.password_revision_date = Some(now_iso.to_string());
    }
    login.password = Some(new_pw.to_string());
}

// ---------------------------------------------------------------------------------------------
// Export / Import (Bitwarden-JSON, kompatibel mit Bitwarden und Vaultwarden)
// ---------------------------------------------------------------------------------------------

/// Unverschluesselter Export im Bitwarden-JSON-Format.
pub fn export_json(items: &[Cipher], folders: &[Folder]) -> String {
    let items: Vec<Value> = items
        .iter()
        .filter(|c| c.deleted_date.is_none())
        .map(|c| {
            let mut v = serde_json::to_value(c).unwrap_or(Value::Null);
            if let Value::Object(m) = &mut v {
                for k in ["object", "edit", "viewPassword", "organizationUseTotp", "attachments", "key", "deletedDate", "permissions"] {
                    m.remove(k);
                }
            }
            v
        })
        .collect();
    let folders: Vec<Value> = folders.iter().map(|f| json!({"id": f.id, "name": f.name})).collect();
    serde_json::to_string_pretty(&json!({"encrypted": false, "folders": folders, "items": items})).unwrap_or_default()
}

/// Passwortgeschuetzter Export (Bitwarden-Format "passwordProtected"), wiederherstellbar in
/// nrzPass, Bitwarden und Vaultwarden.
pub fn export_protected(plain_json: &str, password: &str, kdf: Kdf) -> Result<String> {
    let salt = crypto::b64(&crypto::random_bytes(16));
    let key = MasterKey::derive_raw(password, &salt, kdf)?.stretch();
    let validation = key.encrypt_str(&uuid::Uuid::new_v4().to_string()).to_string();
    let data = key.encrypt_str(plain_json).to_string();
    Ok(serde_json::to_string_pretty(&json!({
        "encrypted": true,
        "passwordProtected": true,
        "salt": salt,
        "kdfType": kdf.kind(),
        "kdfIterations": kdf.iterations(),
        "kdfMemory": kdf.memory(),
        "kdfParallelism": kdf.parallelism(),
        "encKeyValidation_DO_NOT_EDIT": validation,
        "data": data,
    }))
    .unwrap_or_default())
}

/// Ergebnis eines Imports: Klartext-Eintraege (ohne IDs) und Ordnernamen.
#[derive(Debug, Default)]
pub struct Imported {
    pub items: Vec<Cipher>,
    /// Ordnername je Eintrag (gleicher Index wie `items`).
    pub folder_of: Vec<Option<String>>,
}

/// Liest Bitwarden-JSON (auch passwortgeschuetzt), Bitwarden-CSV oder Chrome/Firefox/Safari-CSV.
pub fn import(text: &str, password: Option<&str>) -> std::result::Result<Imported, String> {
    let t = text.trim_start_matches('\u{feff}').trim();
    if t.starts_with('{') {
        let v: Value = serde_json::from_str(t).map_err(|e| format!("JSON ungültig: {e}"))?;
        if v.get("passwordProtected").and_then(Value::as_bool) == Some(true) {
            let pw = password.ok_or("Diese Datei ist passwortgeschützt – Passwort eingeben.")?;
            let kdf = Kdf::from_api(
                v["kdfType"].as_i64().unwrap_or(0),
                v["kdfIterations"].as_i64(),
                v["kdfMemory"].as_i64(),
                v["kdfParallelism"].as_i64(),
            )
            .map_err(|e| e.to_string())?;
            let key = MasterKey::derive_raw(pw, v["salt"].as_str().unwrap_or(""), kdf).map_err(|e| e.to_string())?.stretch();
            let check = v["encKeyValidation_DO_NOT_EDIT"].as_str().unwrap_or("").parse().map_err(|_| "Datei beschädigt")?;
            key.decrypt(&check).map_err(|_| "Falsches Passwort.")?;
            let data = key
                .decrypt_str(&v["data"].as_str().unwrap_or("").parse().map_err(|_| "Datei beschädigt")?)
                .map_err(|_| "Falsches Passwort.")?;
            return import(&data, None);
        }
        if v.get("encrypted").and_then(Value::as_bool) == Some(true) {
            return Err("Konto-verschlüsselte Exporte lassen sich nur im selben Konto öffnen. Bitte als \"passwortgeschützt\" oder unverschlüsselt exportieren.".into());
        }
        let folders: HashMap<String, String> = v["folders"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|f| Some((f["id"].as_str()?.to_string(), f["name"].as_str()?.to_string())))
            .collect();
        let mut out = Imported::default();
        for it in v["items"].as_array().into_iter().flatten() {
            let mut c: Cipher = api::from_value_lenient(it.clone()).map_err(|e| format!("Eintrag ungültig: {e}"))?;
            let folder = c.folder_id.as_ref().and_then(|id| folders.get(id).cloned());
            c.id = String::new();
            c.folder_id = None;
            c.organization_id = None;
            c.key = None;
            c.collection_ids = None;
            out.items.push(c);
            out.folder_of.push(folder);
        }
        return Ok(out);
    }
    import_csv(t)
}

fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match (ch, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            ('"', true) => quoted = false,
            ('"', false) if field.is_empty() => quoted = true,
            (',', false) => row.push(std::mem::take(&mut field)),
            ('\r', false) => {}
            ('\n', false) => {
                row.push(std::mem::take(&mut field));
                if row.iter().any(|f| !f.is_empty()) {
                    rows.push(std::mem::take(&mut row));
                } else {
                    row.clear();
                }
            }
            (c, _) => field.push(c),
        }
    }
    row.push(field);
    if row.iter().any(|f| !f.is_empty()) {
        rows.push(row);
    }
    rows
}

fn import_csv(text: &str) -> std::result::Result<Imported, String> {
    let rows = parse_csv(text);
    let header: Vec<String> = rows.first().ok_or("Datei ist leer")?.iter().map(|h| h.trim().to_lowercase()).collect();
    let col = |names: &[&str]| names.iter().find_map(|n| header.iter().position(|h| h == n));
    let name = col(&["name", "title"]);
    let url = col(&["login_uri", "url", "website"]);
    let user = col(&["login_username", "username", "user", "email"]);
    let pass = col(&["login_password", "password"]);
    let totp = col(&["login_totp", "otpauth", "totp"]);
    let notes = col(&["notes", "note", "extra", "comments"]);
    let folder = col(&["folder", "grouping", "group"]);
    let fav = col(&["favorite"]);
    let kind = col(&["type"]);
    if pass.is_none() && notes.is_none() {
        return Err("Unbekanntes CSV-Format – erwartet werden Spalten wie name, url, username, password.".into());
    }
    let mut out = Imported::default();
    for r in rows.iter().skip(1) {
        let get = |i: Option<usize>| i.and_then(|i| r.get(i)).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let is_note = get(kind).map(|k| k == "note").unwrap_or(false);
        let uri = get(url);
        let title = get(name).or_else(|| uri.as_deref().map(crate::url::host_of)).unwrap_or_else(|| "Ohne Namen".into());
        let mut c = Cipher {
            cipher_type: if is_note { api::cipher_type::SECURE_NOTE } else { api::cipher_type::LOGIN },
            name: Some(title),
            notes: get(notes),
            favorite: get(fav).map(|f| f == "1" || f.eq_ignore_ascii_case("true")).unwrap_or(false),
            edit: true,
            ..Default::default()
        };
        if is_note {
            c.secure_note = Some(api::SecureNote { note_type: 0 });
        } else {
            c.login = Some(api::CipherLogin {
                username: get(user),
                password: get(pass),
                totp: get(totp),
                uris: uri.map(|u| vec![api::LoginUri { uri: Some(u), ..Default::default() }]),
                ..Default::default()
            });
        }
        out.items.push(c);
        out.folder_of.push(get(folder));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Cipher {
        Cipher {
            id: "1".into(),
            cipher_type: 1,
            name: Some("Beispiel".into()),
            login: Some(api::CipherLogin {
                username: Some("nico".into()),
                password: Some("pw1".into()),
                uris: Some(vec![api::LoginUri { uri: Some("https://example.com".into()), ..Default::default() }]),
                ..Default::default()
            }),
            edit: true,
            ..Default::default()
        }
    }

    #[test]
    fn roundtrip_cipher() {
        let keys = KeyRing::new(SymmetricKey::generate());
        let req = encrypt_cipher(&keys, &sample()).unwrap();
        assert!(req.name.as_deref().unwrap().starts_with("2."));
        let enc = Cipher {
            id: "1".into(),
            cipher_type: req.cipher_type,
            name: req.name,
            login: req.login,
            edit: true,
            ..Default::default()
        };
        let dec = decrypt_cipher(&keys, &enc).unwrap();
        assert_eq!(dec.name.as_deref(), Some("Beispiel"));
        assert_eq!(dec.login.unwrap().password.as_deref(), Some("pw1"));
    }

    #[test]
    fn listing_keeps_secrets_encrypted() {
        let keys = KeyRing::new(SymmetricKey::generate());
        let mut plain = sample();
        plain.login.as_mut().unwrap().totp = Some("JBSWY3DPEHPK3PXP".into());
        plain.notes = Some("geheim".into());
        let req = encrypt_cipher(&keys, &plain).unwrap();
        let enc = Cipher { id: "1".into(), cipher_type: 1, name: req.name, notes: req.notes, login: req.login, edit: true, ..Default::default() };
        let list = decrypt_listing(&keys, &enc).unwrap();
        let l = list.login.as_ref().unwrap();
        assert_eq!(list.name.as_deref(), Some("Beispiel"));
        assert_eq!(l.username.as_deref(), Some("nico"));
        assert!(l.password.as_deref().unwrap().starts_with("2."));
        assert!(l.totp.as_deref().unwrap().starts_with("2."));
        assert!(list.notes.as_deref().unwrap().starts_with("2."));
        assert_eq!(open_secret(&keys, &list, l.password.as_deref().unwrap()).unwrap().as_str(), "pw1");
        let full = reveal(&keys, &list).unwrap();
        assert_eq!(full.login.as_ref().unwrap().password.as_deref(), Some("pw1"));
        assert_eq!(full.login.as_ref().unwrap().totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(full.notes.as_deref(), Some("geheim"));
        let mut c = full.into_inner();
        wipe_secrets(&mut c);
        assert!(c.login.unwrap().password.unwrap().bytes().all(|b| b == 0));
    }

    #[test]
    fn password_history() {
        let mut c = sample();
        set_password(&mut c, "pw2", "2026-01-01T00:00:00Z");
        assert_eq!(c.password_history.as_ref().unwrap()[0].password, "pw1");
        assert_eq!(c.login.as_ref().unwrap().password.as_deref(), Some("pw2"));
    }

    #[test]
    fn export_import_protected() {
        let json = export_json(&[sample()], &[]);
        let kdf = Kdf::Pbkdf2 { iterations: 100_000 };
        let prot = export_protected(&json, "export-pw", kdf).unwrap();
        assert!(import(&prot, Some("falsch")).is_err());
        let imp = import(&prot, Some("export-pw")).unwrap();
        assert_eq!(imp.items.len(), 1);
        assert_eq!(imp.items[0].login.as_ref().unwrap().username.as_deref(), Some("nico"));
    }

    #[test]
    fn import_chrome_csv() {
        let csv = "name,url,username,password,note\nGitHub,https://github.com/login,nico,\"pa,ss\"\"x\",\n";
        let imp = import(csv, None).unwrap();
        assert_eq!(imp.items.len(), 1);
        assert_eq!(imp.items[0].login.as_ref().unwrap().password.as_deref(), Some("pa,ss\"x"));
    }
}
