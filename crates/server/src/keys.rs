//! Server-Schluessel: Datenbank-Schluessel (Turso AEGIS-256) und Schluessel fuer Geheimnisse
//! (TOTP), abgeleitet per HKDF-SHA256 aus `NRZPASS_DB_KEY`, `NRZPASS_SEED` (umbrel: APP_SEED)
//! oder einer zufaelligen Schluesseldatei `DATA_DIR/db.key`.

use crate::config::Config;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

pub struct ServerKeys {
    db: Zeroizing<[u8; 32]>,
    secrets: Zeroizing<[u8; 32]>,
}

fn hkdf32(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(b"nrzpass"), ikm).expand(info, out.as_mut()).expect("32 Byte");
    out
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

impl ServerKeys {
    pub fn load(cfg: &Config) -> Result<ServerKeys, String> {
        if let Some(k) = cfg.db_key.as_deref() {
            let db = Zeroizing::new(parse_hex32(k).ok_or("NRZPASS_DB_KEY muss 64 Hex-Zeichen haben")?);
            let secrets = hkdf32(db.as_ref(), b"nrzpass-secrets-v1");
            return Ok(ServerKeys { db, secrets });
        }
        let master: Zeroizing<Vec<u8>> = if let Some(seed) = cfg.seed.as_deref() {
            Zeroizing::new(seed.as_bytes().to_vec())
        } else {
            let path = cfg.data_dir.join("db.key");
            match std::fs::read_to_string(&path) {
                Ok(s) => Zeroizing::new(parse_hex32(&s).ok_or("db.key ist beschaedigt")?.to_vec()),
                Err(_) => {
                    let mut k = [0u8; 32];
                    OsRng.fill_bytes(&mut k);
                    let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
                    write_private(&path, &hex)?;
                    eprintln!(
                        "WARNUNG: Weder NRZPASS_DB_KEY noch NRZPASS_SEED gesetzt – zufaelliger Schluessel in {:?} erzeugt. \
                         Diese Datei sicher aufbewahren: ohne sie ist die Datenbank nicht lesbar.",
                        path
                    );
                    Zeroizing::new(k.to_vec())
                }
            }
        };
        Ok(ServerKeys { db: hkdf32(&master, b"nrzpass-db-v1"), secrets: hkdf32(&master, b"nrzpass-secrets-v1") })
    }

    pub fn db_key_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(self.db.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// Verschluesselt ein Geheimnis (XChaCha20-Poly1305, `aad` bindet es z. B. an die Benutzer-ID).
    pub fn seal(&self, plain: &[u8], aad: &str) -> String {
        let c = XChaCha20Poly1305::new(self.secrets.as_ref().into());
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let ct = c.encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad: aad.as_bytes() }).expect("Verschluesselung");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        B64.encode(out)
    }

    pub fn open(&self, sealed: &str, aad: &str) -> Option<Zeroizing<Vec<u8>>> {
        let raw = B64.decode(sealed).ok()?;
        if raw.len() < 24 + 16 {
            return None;
        }
        let c = XChaCha20Poly1305::new(self.secrets.as_ref().into());
        c.decrypt(XNonce::from_slice(&raw[..24]), Payload { msg: &raw[24..], aad: aad.as_bytes() }).ok().map(Zeroizing::new)
    }
}

fn write_private(path: &std::path::Path, content: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("{path:?}: {e}"))?;
        f.write_all(content.as_bytes()).map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content).map_err(|e| e.to_string())
    }
}
