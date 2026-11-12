//! nrzPass-Kern: alles, was Server, Web-Tresor, Browser-Erweiterung und macOS-App gemeinsam nutzen.
//!
//! * [`crypto`] – Bitwarden/Vaultwarden-kompatible Verschluesselung (PBKDF2/Argon2id, HKDF,
//!   AES-256-CBC + HMAC-SHA256 "EncString", RSA-OAEP fuer Organisationsschluessel).
//! * [`api`] – Datenmodelle der Bitwarden-API (Sync, Ciphers, Ordner, Token).
//! * [`vault`] – entschluesselte Eintraege und ihre Ver-/Entschluesselung.
//! * [`generator`], [`totp`], [`strength`], [`url`], [`detect`] – Werkzeuge fuer die Oberflaechen.

pub mod api;
pub mod crypto;
pub mod detect;
pub mod generator;
pub mod strength;
pub mod totp;
pub mod url;
pub mod vault;

pub use crypto::{CryptoError, EncString, Kdf, SymmetricKey};
