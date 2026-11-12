//! Datenmodelle der Bitwarden-API (wie Vaultwarden sie spricht).
//!
//! Alle Felder sind camelCase. Aeltere Server antworten in PascalCase – [`normalize_keys`] macht
//! daraus camelCase, bevor deserialisiert wird. Unbekannte Felder (z. B. Passkeys, Anhaenge)
//! landen in `extra` und werden beim Speichern unveraendert zurueckgeschickt.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Wandelt alle Objekt-Schluessel rekursiv in camelCase (erster Buchstabe klein).
pub fn normalize_keys(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, v)| {
                    let mut c = k.chars();
                    let k = match c.next() {
                        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
                        None => k,
                    };
                    (k, normalize_keys(v))
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(normalize_keys).collect()),
        v => v,
    }
}

/// Deserialisiert tolerant (PascalCase oder camelCase).
pub fn from_value_lenient<T: serde::de::DeserializeOwned>(v: Value) -> Result<T, serde_json::Error> {
    serde_json::from_value(normalize_keys(v))
}

pub mod cipher_type {
    pub const LOGIN: i64 = 1;
    pub const SECURE_NOTE: i64 = 2;
    pub const CARD: i64 = 3;
    pub const IDENTITY: i64 = 4;
    pub const SSH_KEY: i64 = 5;
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PreloginRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: i64,
    pub kdf_iterations: i64,
    #[serde(default)]
    pub kdf_memory: Option<i64>,
    #[serde(default)]
    pub kdf_parallelism: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KeysData {
    pub public_key: String,
    pub encrypted_private_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    pub master_password_hash: String,
    #[serde(default)]
    pub master_password_hint: Option<String>,
    pub key: String,
    pub kdf: i64,
    pub kdf_iterations: i64,
    #[serde(default)]
    pub kdf_memory: Option<i64>,
    #[serde(default)]
    pub kdf_parallelism: Option<i64>,
    #[serde(default)]
    pub keys: Option<KeysData>,
}

/// Antwort von `/identity/connect/token` (nach [`normalize_keys`]).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    #[serde(rename = "access_token", alias = "accessToken")]
    pub access_token: String,
    #[serde(rename = "expires_in", alias = "expiresIn", default)]
    pub expires_in: i64,
    #[serde(rename = "token_type", alias = "tokenType", default)]
    pub token_type: String,
    #[serde(rename = "refresh_token", alias = "refreshToken", default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub kdf: Option<i64>,
    #[serde(default)]
    pub kdf_iterations: Option<i64>,
    #[serde(default)]
    pub kdf_memory: Option<i64>,
    #[serde(default)]
    pub kdf_parallelism: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProfileOrganization {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub premium: bool,
    #[serde(default)]
    pub master_password_hint: Option<String>,
    #[serde(default)]
    pub culture: Option<String>,
    #[serde(default)]
    pub two_factor_enabled: bool,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub security_stamp: Option<String>,
    #[serde(default)]
    pub organizations: Vec<ProfileOrganization>,
    #[serde(default)]
    pub object: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub revision_date: Option<String>,
    #[serde(default)]
    pub object: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FolderRequest {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LoginUri {
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default, rename = "match")]
    pub match_type: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CipherLogin {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub uris: Option<Vec<LoginUri>>,
    #[serde(default)]
    pub password_revision_date: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CipherCard {
    #[serde(default)]
    pub cardholder_name: Option<String>,
    #[serde(default)]
    pub brand: Option<String>,
    #[serde(default)]
    pub number: Option<String>,
    #[serde(default)]
    pub exp_month: Option<String>,
    #[serde(default)]
    pub exp_year: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CipherIdentity {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub middle_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub address1: Option<String>,
    #[serde(default)]
    pub address2: Option<String>,
    #[serde(default)]
    pub address3: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub postal_code: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub ssn: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub passport_number: Option<String>,
    #[serde(default)]
    pub license_number: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecureNote {
    #[serde(default, rename = "type")]
    pub note_type: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CipherField {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    /// 0 = Text, 1 = versteckt, 2 = Ja/Nein, 3 = verknuepft
    #[serde(default, rename = "type")]
    pub field_type: i64,
    #[serde(default)]
    pub linked_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistory {
    pub password: String,
    pub last_used_date: String,
}

/// Verschluesselter Eintrag, wie ihn `/api/sync` liefert.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(rename = "type")]
    pub cipher_type: i64,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub reprompt: i64,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub login: Option<CipherLogin>,
    #[serde(default)]
    pub card: Option<CipherCard>,
    #[serde(default)]
    pub identity: Option<CipherIdentity>,
    #[serde(default)]
    pub secure_note: Option<SecureNote>,
    #[serde(default)]
    pub fields: Option<Vec<CipherField>>,
    #[serde(default)]
    pub password_history: Option<Vec<PasswordHistory>>,
    #[serde(default)]
    pub revision_date: Option<String>,
    #[serde(default)]
    pub creation_date: Option<String>,
    #[serde(default)]
    pub deleted_date: Option<String>,
    #[serde(default = "yes")]
    pub edit: bool,
    #[serde(default)]
    pub collection_ids: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn yes() -> bool {
    true
}

/// Anfrage zum Anlegen/Aendern eines Eintrags (`POST /api/ciphers`, `PUT /api/ciphers/{id}`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CipherRequest {
    #[serde(rename = "type")]
    pub cipher_type: i64,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub reprompt: i64,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub login: Option<CipherLogin>,
    #[serde(default)]
    pub card: Option<CipherCard>,
    #[serde(default)]
    pub identity: Option<CipherIdentity>,
    #[serde(default)]
    pub secure_note: Option<SecureNote>,
    #[serde(default)]
    pub fields: Option<Vec<CipherField>>,
    #[serde(default)]
    pub password_history: Option<Vec<PasswordHistory>>,
    #[serde(default)]
    pub last_known_revision_date: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile: Profile,
    #[serde(default)]
    pub folders: Vec<Folder>,
    #[serde(default)]
    pub ciphers: Vec<Cipher>,
    #[serde(default)]
    pub collections: Vec<Value>,
    #[serde(default)]
    pub policies: Vec<Value>,
    #[serde(default)]
    pub sends: Vec<Value>,
    #[serde(default)]
    pub object: Option<String>,
}

/// Massen-Import (`POST /api/ciphers/import`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest {
    pub ciphers: Vec<CipherRequest>,
    #[serde(default)]
    pub folders: Vec<FolderRequest>,
    /// `key` = Index in `ciphers`, `value` = Index in `folders`.
    #[serde(default)]
    pub folder_relationships: Vec<KeyValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KeyValue {
    pub key: usize,
    pub value: usize,
}

/// Fehlermeldung im Bitwarden-Format (Vaultwarden: `message` bzw. `errorModel.message`).
pub fn error_message(v: &Value) -> Option<String> {
    let v = normalize_keys(v.clone());
    v.get("message")
        .and_then(Value::as_str)
        .or_else(|| v.pointer("/errorModel/message").and_then(Value::as_str))
        .or_else(|| v.get("error_description").and_then(Value::as_str))
        .or_else(|| v.get("errorDescription").and_then(Value::as_str))
        .map(str::to_string)
}

// ---------------------------------------------------------------------------------------------
// nrzPass-Erweiterungen (nicht Teil der Bitwarden-API)
// ---------------------------------------------------------------------------------------------

/// Verknuepftes Fremdkonto (z. B. Vaultwarden), komplett clientseitig verschluesselt.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LinkedAccount {
    pub id: String,
    /// EncString mit [`LinkedAccountData`] als JSON, verschluesselt mit dem nrzPass-Benutzerschluessel.
    pub data: String,
    #[serde(default)]
    pub revision_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LinkedAccountRequest {
    pub data: String,
}

/// Klartext eines verknuepften Kontos (nur im Client).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LinkedAccountData {
    pub label: String,
    pub server: String,
    pub email: String,
    pub device_id: String,
    pub refresh_token: String,
    /// Benutzerschluessel des Fremdkontos (Base64, 64 Byte).
    pub user_key: String,
    #[serde(default)]
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEvent {
    pub kind: String,
    pub ip: Option<String>,
    pub device: Option<String>,
    pub date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub device_type: i64,
    pub created: String,
    pub last_seen: String,
    pub current: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    pub master_password_hash: String,
    pub new_master_password_hash: String,
    #[serde(default)]
    pub master_password_hint: Option<String>,
    pub key: String,
    #[serde(default)]
    pub kdf: Option<i64>,
    #[serde(default)]
    pub kdf_iterations: Option<i64>,
    #[serde(default)]
    pub kdf_memory: Option<i64>,
    #[serde(default)]
    pub kdf_parallelism: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PasswordVerify {
    pub master_password_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorRequest {
    pub key: String,
    pub token: String,
    pub master_password_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorResponse {
    pub enabled: bool,
    pub key: String,
    #[serde(default)]
    pub object: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub signups_allowed: bool,
    pub has_users: bool,
}
