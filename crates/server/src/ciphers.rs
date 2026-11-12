//! Eintraege (Ciphers) und Ordner. Der Server speichert nur, was der Client verschluesselt schickt.

use crate::account::bump_revision;
use crate::auth::Auth;
use crate::db::{self, int, opt_int, opt_text, text};
use crate::error::{ApiError, ApiResult};
use crate::identity::is_enc;
use crate::util::{iso, new_id, now_ms, parse_iso_ms, valid_id};
use crate::{p, St};
use axum::extract::{Path, State};
use axum::Json;
use nrzpass_core::api::{self, ImportRequest};
use serde_json::{json, Map, Value};

pub const CIPHER_COLS: &str = "id, folder_id, ctype, favorite, data, created_ms, revision_ms, deleted_ms";

/// Gespeicherten Eintrag in das Bitwarden-Format `cipherDetails` umwandeln.
pub fn cipher_json(r: &db::Row) -> Value {
    let mut m: Map<String, Value> = serde_json::from_str(&text(&r[4])).unwrap_or_default();
    m.insert("id".into(), json!(text(&r[0])));
    m.insert("folderId".into(), json!(opt_text(&r[1])));
    m.insert("type".into(), json!(int(&r[2])));
    m.insert("favorite".into(), json!(int(&r[3]) != 0));
    m.insert("creationDate".into(), json!(iso(int(&r[5]))));
    m.insert("revisionDate".into(), json!(iso(int(&r[6]))));
    m.insert("deletedDate".into(), json!(opt_int(&r[7]).map(iso)));
    m.insert("organizationId".into(), Value::Null);
    m.insert("organizationUseTotp".into(), json!(false));
    m.insert("edit".into(), json!(true));
    m.insert("viewPassword".into(), json!(true));
    m.insert("collectionIds".into(), json!([]));
    m.insert("attachments".into(), Value::Null);
    m.insert("object".into(), json!("cipherDetails"));
    for k in ["card", "identity", "login", "secureNote", "sshKey", "fields", "passwordHistory", "notes", "key"] {
        m.entry(k).or_insert(Value::Null);
    }
    m.entry("reprompt").or_insert(json!(0));
    Value::Object(m)
}

pub fn folder_json(r: &db::Row) -> Value {
    json!({"id": text(&r[0]), "name": text(&r[1]), "revisionDate": iso(int(&r[2])), "object": "folder"})
}

/// Prueft, ob ein Feld (falls gesetzt) ein gueltiger EncString ist.
fn check_enc(v: Option<&Value>, what: &str) -> ApiResult<()> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if s.is_empty() || is_enc(s) => Ok(()),
        _ => Err(ApiError::bad(&format!("Feld \"{what}\" ist nicht verschluesselt."))),
    }
}

fn check_obj_fields(o: Option<&Value>, prefix: &str) -> ApiResult<()> {
    if let Some(Value::Object(m)) = o {
        for (k, v) in m {
            if v.is_string() {
                check_enc(Some(v), &format!("{prefix}.{k}"))?;
            }
        }
    }
    Ok(())
}

/// Validierter Eintrag: Typ, Ordner, Favorit und die verschluesselten Daten als JSON.
struct CipherIn {
    ctype: i64,
    folder_id: Option<String>,
    favorite: bool,
    data: String,
    last_known: Option<i64>,
}

fn parse_cipher(body: Value) -> ApiResult<CipherIn> {
    let v = api::normalize_keys(body);
    let Value::Object(mut m) = v else { return Err(ApiError::bad("Eintrag muss ein Objekt sein.")) };
    if m.get("organizationId").is_some_and(|o| !o.is_null()) {
        return Err(ApiError::bad("Organisationen werden von nrzPass nicht unterstuetzt."));
    }
    let ctype = m.get("type").and_then(Value::as_i64).ok_or_else(|| ApiError::bad("Typ fehlt."))?;
    if !(1..=5).contains(&ctype) {
        return Err(ApiError::bad("Unbekannter Eintragstyp."));
    }
    match m.get("name") {
        Some(Value::String(s)) if is_enc(s) => {}
        _ => return Err(ApiError::bad("Name fehlt oder ist nicht verschluesselt.")),
    }
    check_enc(m.get("notes"), "notes")?;
    check_enc(m.get("key"), "key")?;
    if let Some(Value::Object(l)) = m.get("login") {
        for k in ["username", "password", "totp"] {
            check_enc(l.get(k), &format!("login.{k}"))?;
        }
        if let Some(Value::Array(uris)) = l.get("uris") {
            for u in uris {
                check_enc(u.get("uri"), "login.uris.uri")?;
            }
        }
    }
    check_obj_fields(m.get("card"), "card")?;
    check_obj_fields(m.get("identity"), "identity")?;
    if let Some(Value::Array(fields)) = m.get("fields") {
        for f in fields {
            check_enc(f.get("name"), "fields.name")?;
            check_enc(f.get("value"), "fields.value")?;
        }
    }
    if let Some(Value::Array(hist)) = m.get("passwordHistory") {
        for h in hist {
            check_enc(h.get("password"), "passwordHistory.password")?;
        }
    }
    let folder_id = m.get("folderId").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
    let favorite = m.get("favorite").and_then(Value::as_bool).unwrap_or(false);
    let last_known = m.get("lastKnownRevisionDate").and_then(Value::as_str).and_then(parse_iso_ms);
    // Server-Felder nicht mitspeichern
    for k in [
        "id", "type", "folderId", "favorite", "organizationId", "lastKnownRevisionDate", "revisionDate", "creationDate",
        "deletedDate", "edit", "viewPassword", "object", "collectionIds", "attachments", "organizationUseTotp", "permissions",
        "attachments2",
    ] {
        m.remove(k);
    }
    let data = serde_json::to_string(&Value::Object(m)).map_err(ApiError::internal)?;
    Ok(CipherIn { ctype, folder_id, favorite, data, last_known })
}

async fn check_folder(c: &turso::Connection, user_id: &str, folder: &Option<String>) -> ApiResult<()> {
    if let Some(f) = folder {
        if !valid_id(f)
            || db::query_one(c, "SELECT id FROM folders WHERE id = ?1 AND user_id = ?2", p![f.as_str(), user_id]).await?.is_none()
        {
            return Err(ApiError::bad("Ordner nicht gefunden."));
        }
    }
    Ok(())
}

async fn load_cipher(c: &turso::Connection, user_id: &str, id: &str) -> ApiResult<db::Row> {
    if !valid_id(id) {
        return Err(ApiError::not_found());
    }
    db::query_one(c, &format!("SELECT {CIPHER_COLS} FROM ciphers WHERE id = ?1 AND user_id = ?2"), p![id, user_id])
        .await?
        .ok_or_else(ApiError::not_found)
}

async fn insert_cipher(c: &turso::Connection, user_id: &str, ci: &CipherIn) -> ApiResult<String> {
    let id = new_id();
    let now = now_ms();
    db::exec(
        c,
        "INSERT INTO ciphers (id, user_id, folder_id, ctype, favorite, data, created_ms, revision_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        p![id.as_str(), user_id, ci.folder_id.clone(), ci.ctype, ci.favorite as i64, ci.data.as_str(), now, now],
    )
    .await?;
    Ok(id)
}

pub async fn create(State(st): State<St>, a: Auth, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let ci = parse_cipher(body)?;
    let c = st.db.lock().await;
    check_folder(&c, &a.user_id, &ci.folder_id).await?;
    let id = insert_cipher(&c, &a.user_id, &ci).await?;
    bump_revision(&c, &a.user_id).await?;
    Ok(Json(cipher_json(&load_cipher(&c, &a.user_id, &id).await?)))
}

pub async fn create_with_collections(st: State<St>, a: Auth, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let body = api::normalize_keys(body);
    let cipher = body.get("cipher").cloned().ok_or_else(|| ApiError::bad("cipher fehlt."))?;
    create(st, a, Json(cipher)).await
}

pub async fn get_one(State(st): State<St>, a: Auth, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let c = st.db.lock().await;
    Ok(Json(cipher_json(&load_cipher(&c, &a.user_id, &id).await?)))
}

pub async fn update(State(st): State<St>, a: Auth, Path(id): Path<String>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let ci = parse_cipher(body)?;
    let c = st.db.lock().await;
    let old = load_cipher(&c, &a.user_id, &id).await?;
    // Konflikt: Eintrag wurde inzwischen auf einem anderen Geraet geaendert (1 s Toleranz)
    if let Some(known) = ci.last_known {
        if int(&old[6]) - known > 1000 {
            return Err(ApiError::bad(
                "Der Eintrag wurde inzwischen auf einem anderen Geraet geaendert. Bitte synchronisieren und erneut bearbeiten.",
            ));
        }
    }
    check_folder(&c, &a.user_id, &ci.folder_id).await?;
    db::exec(
        &c,
        "UPDATE ciphers SET folder_id = ?1, ctype = ?2, favorite = ?3, data = ?4, revision_ms = ?5 WHERE id = ?6 AND user_id = ?7",
        p![ci.folder_id.clone(), ci.ctype, ci.favorite as i64, ci.data.as_str(), now_ms(), id.as_str(), a.user_id.as_str()],
    )
    .await?;
    bump_revision(&c, &a.user_id).await?;
    Ok(Json(cipher_json(&load_cipher(&c, &a.user_id, &id).await?)))
}

pub async fn soft_delete(State(st): State<St>, a: Auth, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let c = st.db.lock().await;
    load_cipher(&c, &a.user_id, &id).await?;
    let now = now_ms();
    db::exec(&c, "UPDATE ciphers SET deleted_ms = ?1, revision_ms = ?1 WHERE id = ?2 AND user_id = ?3", p![now, id.as_str(), a.user_id.as_str()]).await?;
    bump_revision(&c, &a.user_id).await?;
    Ok(Json(json!({})))
}

pub async fn restore(State(st): State<St>, a: Auth, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let c = st.db.lock().await;
    load_cipher(&c, &a.user_id, &id).await?;
    db::exec(
        &c,
        "UPDATE ciphers SET deleted_ms = NULL, revision_ms = ?1 WHERE id = ?2 AND user_id = ?3",
        p![now_ms(), id.as_str(), a.user_id.as_str()],
    )
    .await?;
    bump_revision(&c, &a.user_id).await?;
    Ok(Json(cipher_json(&load_cipher(&c, &a.user_id, &id).await?)))
}

pub async fn hard_delete(State(st): State<St>, a: Auth, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let c = st.db.lock().await;
    load_cipher(&c, &a.user_id, &id).await?;
    db::exec(&c, "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2", p![id.as_str(), a.user_id.as_str()]).await?;
    bump_revision(&c, &a.user_id).await?;
    Ok(Json(json!({})))
}

pub async fn import(State(st): State<St>, a: Auth, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let body = api::normalize_keys(body);
    let ciphers: Vec<Value> = body.get("ciphers").and_then(Value::as_array).cloned().unwrap_or_default();
    let folders: Vec<Value> = body.get("folders").and_then(Value::as_array).cloned().unwrap_or_default();
    let rel: ImportRequest = api::from_value_lenient(json!({
        "ciphers": [],
        "folders": [],
        "folderRelationships": body.get("folderRelationships").cloned().unwrap_or(json!([]))
    }))
    .map_err(|e| ApiError::bad(&format!("Ungueltige Ordnerzuordnung: {e}")))?;
    if ciphers.len() > 20_000 || folders.len() > 2_000 {
        return Err(ApiError::bad("Zu viele Eintraege fuer einen Import."));
    }
    let mut folder_names = Vec::with_capacity(folders.len());
    for f in &folders {
        match f.get("name").and_then(Value::as_str) {
            Some(n) if is_enc(n) => folder_names.push(n.to_string()),
            _ => return Err(ApiError::bad("Ordnername ist nicht verschluesselt.")),
        }
    }
    let mut parsed = Vec::with_capacity(ciphers.len());
    for c in ciphers {
        let mut ci = parse_cipher(c)?;
        ci.folder_id = None;
        parsed.push(ci);
    }
    let c = st.db.lock().await;
    let now = now_ms();
    c.execute("BEGIN", ()).await?;
    let result: ApiResult<()> = async {
        let mut folder_ids = Vec::with_capacity(folder_names.len());
        for n in &folder_names {
            let id = new_id();
            db::exec(&c, "INSERT INTO folders (id, user_id, name, revision_ms) VALUES (?1, ?2, ?3, ?4)", p![id.as_str(), a.user_id.as_str(), n.as_str(), now]).await?;
            folder_ids.push(id);
        }
        for kv in &rel.folder_relationships {
            if let (Some(ci), Some(fid)) = (parsed.get_mut(kv.key), folder_ids.get(kv.value)) {
                ci.folder_id = Some(fid.clone());
            }
        }
        for ci in &parsed {
            insert_cipher(&c, &a.user_id, ci).await?;
        }
        bump_revision(&c, &a.user_id).await?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => {
            c.execute("COMMIT", ()).await?;
            Ok(Json(json!({})))
        }
        Err(e) => {
            let _ = c.execute("ROLLBACK", ()).await;
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Ordner
// ---------------------------------------------------------------------------------------------

fn folder_name(body: Value) -> ApiResult<String> {
    let v = api::normalize_keys(body);
    match v.get("name").and_then(Value::as_str) {
        Some(n) if is_enc(n) => Ok(n.to_string()),
        _ => Err(ApiError::bad("Ordnername fehlt oder ist nicht verschluesselt.")),
    }
}

pub async fn list_folders(State(st): State<St>, a: Auth) -> ApiResult<Json<Value>> {
    let c = st.db.lock().await;
    let data: Vec<Value> =
        db::query(&c, "SELECT id, name, revision_ms FROM folders WHERE user_id = ?1", p![a.user_id.as_str()]).await?.iter().map(folder_json).collect();
    Ok(Json(json!({"data": data, "continuationToken": null, "object": "list"})))
}

pub async fn create_folder(State(st): State<St>, a: Auth, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let name = folder_name(body)?;
    let c = st.db.lock().await;
    let id = new_id();
    let now = now_ms();
    db::exec(&c, "INSERT INTO folders (id, user_id, name, revision_ms) VALUES (?1, ?2, ?3, ?4)", p![id.as_str(), a.user_id.as_str(), name.as_str(), now]).await?;
    bump_revision(&c, &a.user_id).await?;
    Ok(Json(json!({"id": id, "name": name, "revisionDate": iso(now), "object": "folder"})))
}

pub async fn update_folder(State(st): State<St>, a: Auth, Path(id): Path<String>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let name = folder_name(body)?;
    let c = st.db.lock().await;
    check_folder(&c, &a.user_id, &Some(id.clone())).await.map_err(|_| ApiError::not_found())?;
    let now = now_ms();
    db::exec(&c, "UPDATE folders SET name = ?1, revision_ms = ?2 WHERE id = ?3 AND user_id = ?4", p![name.as_str(), now, id.as_str(), a.user_id.as_str()]).await?;
    bump_revision(&c, &a.user_id).await?;
    Ok(Json(json!({"id": id, "name": name, "revisionDate": iso(now), "object": "folder"})))
}

pub async fn delete_folder(State(st): State<St>, a: Auth, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let c = st.db.lock().await;
    check_folder(&c, &a.user_id, &Some(id.clone())).await.map_err(|_| ApiError::not_found())?;
    db::exec(&c, "UPDATE ciphers SET folder_id = NULL, revision_ms = ?1 WHERE folder_id = ?2 AND user_id = ?3", p![now_ms(), id.as_str(), a.user_id.as_str()]).await?;
    db::exec(&c, "DELETE FROM folders WHERE id = ?1 AND user_id = ?2", p![id.as_str(), a.user_id.as_str()]).await?;
    bump_revision(&c, &a.user_id).await?;
    Ok(Json(json!({})))
}
