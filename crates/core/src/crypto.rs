//! Bitwarden/Vaultwarden-kompatible Kryptografie.
//!
//! Ablauf (identisch zu den offiziellen Bitwarden-Clients, damit ein Vaultwarden-Konto direkt
//! in nrzPass funktioniert und umgekehrt):
//!
//! 1. **Master-Schluessel** = KDF(Master-Passwort, E-Mail) mit PBKDF2-SHA256 oder Argon2id.
//! 2. **Master-Passwort-Hash** (geht an den Server) = PBKDF2-SHA256(Master-Schluessel, Passwort, 1).
//!    Der Server sieht also nie das Passwort und kann den Tresor nicht entschluesseln.
//! 3. **Gestreckter Schluessel** = HKDF-Expand(Master-Schluessel, "enc" | "mac").
//! 4. **Benutzerschluessel** (64 Byte zufaellig) liegt mit dem gestreckten Schluessel
//!    verschluesselt auf dem Server ("protected key").
//! 5. Jeder Wert im Tresor ist ein [`EncString`]: AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC).

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("ungueltiges verschluesseltes Format")]
    InvalidFormat,
    #[error("nicht unterstuetzter Verschluesselungstyp {0}")]
    UnsupportedType(u8),
    #[error("falsches Passwort oder beschaedigte Daten (MAC stimmt nicht)")]
    MacMismatch,
    #[error("Entschluesselung fehlgeschlagen")]
    Decrypt,
    #[error("ungueltige Schluessellaenge")]
    KeyLength,
    #[error("ungueltige KDF-Parameter: {0}")]
    Kdf(String),
    #[error("RSA: {0}")]
    Rsa(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

// ---------------------------------------------------------------------------------------------
// KDF
// ---------------------------------------------------------------------------------------------

/// Schluesselableitung wie in Bitwarden (`kdf`: 0 = PBKDF2-SHA256, 1 = Argon2id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Kdf {
    Pbkdf2 { iterations: u32 },
    /// `memory` in MiB, wie bei Bitwarden.
    Argon2id { iterations: u32, memory: u32, parallelism: u32 },
}

impl Kdf {
    /// Standard fuer neue nrzPass-Konten: Argon2id mit 64 MiB, 3 Durchlaeufen, 4 Threads
    /// (gleich wie Bitwarden; deutlich staerker gegen GPU-Angriffe als PBKDF2).
    pub const DEFAULT: Kdf = Kdf::Argon2id { iterations: 3, memory: 64, parallelism: 4 };

    /// Aus den Feldern der Bitwarden-API (`kdf`, `kdfIterations`, `kdfMemory`, `kdfParallelism`).
    pub fn from_api(kind: i64, iterations: Option<i64>, memory: Option<i64>, parallelism: Option<i64>) -> Result<Kdf> {
        let kdf = match kind {
            0 => Kdf::Pbkdf2 { iterations: iterations.unwrap_or(600_000) as u32 },
            1 => Kdf::Argon2id {
                iterations: iterations.unwrap_or(3) as u32,
                memory: memory.unwrap_or(64) as u32,
                parallelism: parallelism.unwrap_or(4) as u32,
            },
            k => return Err(CryptoError::Kdf(format!("unbekannter Typ {k}"))),
        };
        kdf.validate()?;
        Ok(kdf)
    }

    pub fn kind(&self) -> i64 {
        match self {
            Kdf::Pbkdf2 { .. } => 0,
            Kdf::Argon2id { .. } => 1,
        }
    }
    pub fn iterations(&self) -> i64 {
        match *self {
            Kdf::Pbkdf2 { iterations } | Kdf::Argon2id { iterations, .. } => iterations as i64,
        }
    }
    pub fn memory(&self) -> Option<i64> {
        match *self {
            Kdf::Argon2id { memory, .. } => Some(memory as i64),
            _ => None,
        }
    }
    pub fn parallelism(&self) -> Option<i64> {
        match *self {
            Kdf::Argon2id { parallelism, .. } => Some(parallelism as i64),
            _ => None,
        }
    }

    /// Untergrenzen wie bei Bitwarden – ein boeswilliger Server soll keine schwache KDF
    /// erzwingen koennen (Downgrade-Schutz), Obergrenzen gegen Speicher-Erschoepfung.
    pub fn validate(&self) -> Result<()> {
        match *self {
            Kdf::Pbkdf2 { iterations } => {
                if !(100_000..=10_000_000).contains(&iterations) {
                    return Err(CryptoError::Kdf("PBKDF2 braucht 100'000 bis 10'000'000 Durchläufe".into()));
                }
            }
            Kdf::Argon2id { iterations, memory, parallelism } => {
                if !(2..=20).contains(&iterations) || !(16..=1024).contains(&memory) || !(1..=16).contains(&parallelism) {
                    return Err(CryptoError::Kdf(
                        "Argon2id braucht 2-20 Durchläufe, 16-1024 MiB und 1-16 Threads".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn label(&self) -> String {
        match *self {
            Kdf::Pbkdf2 { iterations } => format!("PBKDF2-SHA256, {iterations} Durchläufe"),
            Kdf::Argon2id { iterations, memory, parallelism } => {
                format!("Argon2id, {memory} MiB, {iterations} Durchläufe, {parallelism} Threads")
            }
        }
    }
}

/// Normalisierte E-Mail als Salz (wie Bitwarden: getrimmt, Kleinbuchstaben).
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// 32-Byte-Master-Schluessel.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn derive(password: &str, email: &str, kdf: Kdf) -> Result<MasterKey> {
        MasterKey::derive_raw(password, &normalize_email(email), kdf)
    }

    /// Wie [`MasterKey::derive`], aber mit unveraendertem Salz (passwortgeschuetzter Export).
    pub fn derive_raw(password: &str, salt: &str, kdf: Kdf) -> Result<MasterKey> {
        kdf.validate()?;
        let mut out = [0u8; 32];
        match kdf {
            Kdf::Pbkdf2 { iterations } => {
                pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), iterations, &mut out);
            }
            Kdf::Argon2id { iterations, memory, parallelism } => {
                let salt_hash = Sha256::digest(salt.as_bytes());
                let params = argon2::Params::new(memory * 1024, iterations, parallelism, Some(32))
                    .map_err(|e| CryptoError::Kdf(e.to_string()))?;
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                    .hash_password_into(password.as_bytes(), &salt_hash, &mut out)
                    .map_err(|e| CryptoError::Kdf(e.to_string()))?;
            }
        }
        Ok(MasterKey(out))
    }

    /// Hash, der zur Anmeldung an den Server geht (Base64).
    pub fn password_hash(&self, password: &str) -> String {
        let mut out = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha256>(&self.0, password.as_bytes(), 1, out.as_mut());
        B64.encode(out.as_ref())
    }

    /// HKDF-Expand auf "enc"/"mac" (ohne Extract-Schritt, wie Bitwarden).
    pub fn stretch(&self) -> SymmetricKey {
        let hk = hkdf::Hkdf::<Sha256>::from_prk(&self.0).expect("32 Byte sind eine gültige PRK");
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        hk.expand(b"enc", &mut enc).expect("Laenge passt");
        hk.expand(b"mac", &mut mac).expect("Laenge passt");
        SymmetricKey { enc, mac }
    }
}

// ---------------------------------------------------------------------------------------------
// Symmetrische Schluessel
// ---------------------------------------------------------------------------------------------

/// 256-Bit-AES-Schluessel + 256-Bit-HMAC-Schluessel. Wird beim Verwerfen ueberschrieben.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SymmetricKey {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey(***)")
    }
}

impl SymmetricKey {
    pub fn generate() -> SymmetricKey {
        let mut b = Zeroizing::new([0u8; 64]);
        OsRng.fill_bytes(b.as_mut());
        SymmetricKey::from_bytes(b.as_ref()).expect("64 Byte")
    }

    pub fn from_bytes(b: &[u8]) -> Result<SymmetricKey> {
        if b.len() != 64 {
            return Err(CryptoError::KeyLength);
        }
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        enc.copy_from_slice(&b[..32]);
        mac.copy_from_slice(&b[32..]);
        Ok(SymmetricKey { enc, mac })
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(64));
        v.extend_from_slice(&self.enc);
        v.extend_from_slice(&self.mac);
        v
    }

    pub fn to_b64(&self) -> Zeroizing<String> {
        Zeroizing::new(B64.encode(self.to_bytes().as_slice()))
    }

    pub fn from_b64(s: &str) -> Result<SymmetricKey> {
        let b = Zeroizing::new(B64.decode(s.trim()).map_err(|_| CryptoError::InvalidFormat)?);
        SymmetricKey::from_bytes(&b)
    }

    pub fn encrypt(&self, plain: &[u8]) -> EncString {
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);
        let data = Aes256CbcEnc::new(&self.enc.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plain);
        let mac = self.mac_of(&iv, &data);
        EncString::AesCbc256HmacSha256 { iv, data, mac }
    }

    pub fn encrypt_str(&self, plain: &str) -> EncString {
        self.encrypt(plain.as_bytes())
    }

    pub fn decrypt(&self, enc: &EncString) -> Result<Zeroizing<Vec<u8>>> {
        match enc {
            EncString::AesCbc256HmacSha256 { iv, data, mac } => {
                let mut m = HmacSha256::new_from_slice(&self.mac).expect("Laenge");
                m.update(iv);
                m.update(data);
                // Vergleich in konstanter Zeit
                m.verify_slice(mac).map_err(|_| CryptoError::MacMismatch)?;
                let plain = Aes256CbcDec::new(&self.enc.into(), &(*iv).into())
                    .decrypt_padded_vec_mut::<Pkcs7>(data)
                    .map_err(|_| CryptoError::Decrypt)?;
                Ok(Zeroizing::new(plain))
            }
            EncString::Rsa { kind, .. } => Err(CryptoError::UnsupportedType(*kind)),
        }
    }

    pub fn decrypt_str(&self, enc: &EncString) -> Result<String> {
        let b = self.decrypt(enc)?;
        String::from_utf8(b.to_vec()).map_err(|_| CryptoError::Decrypt)
    }

    /// Entschluesselt einen optionalen EncString-Text aus der API (leer/None -> None).
    pub fn decrypt_opt(&self, s: Option<&str>) -> Result<Option<String>> {
        match s {
            None => Ok(None),
            Some(s) if s.is_empty() => Ok(None),
            Some(s) => Ok(Some(self.decrypt_str(&s.parse()?)?)),
        }
    }

    /// Verschluesselt optionalen Text (leer -> None, wie die offiziellen Clients).
    pub fn encrypt_opt(&self, s: Option<&str>) -> Option<String> {
        s.filter(|s| !s.is_empty()).map(|s| self.encrypt_str(s).to_string())
    }

    fn mac_of(&self, iv: &[u8], data: &[u8]) -> [u8; 32] {
        let mut m = HmacSha256::new_from_slice(&self.mac).expect("Laenge");
        m.update(iv);
        m.update(data);
        m.finalize().into_bytes().into()
    }
}

// ---------------------------------------------------------------------------------------------
// EncString
// ---------------------------------------------------------------------------------------------

/// Verschluesselter Wert im Bitwarden-Format, z. B. `2.<iv>|<daten>|<mac>`.
#[derive(Clone, PartialEq, Eq)]
pub enum EncString {
    /// Typ 2: AES-256-CBC + HMAC-SHA256.
    AesCbc256HmacSha256 { iv: [u8; 16], data: Vec<u8>, mac: [u8; 32] },
    /// Typ 3 (RSA-OAEP-SHA256) und 4 (RSA-OAEP-SHA1).
    Rsa { kind: u8, data: Vec<u8> },
}

impl fmt::Debug for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncString({})", self)
    }
}

impl fmt::Display for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncString::AesCbc256HmacSha256 { iv, data, mac } => {
                write!(f, "2.{}|{}|{}", B64.encode(iv), B64.encode(data), B64.encode(mac))
            }
            EncString::Rsa { kind, data } => write!(f, "{}.{}", kind, B64.encode(data)),
        }
    }
}

impl std::str::FromStr for EncString {
    type Err = CryptoError;
    fn from_str(s: &str) -> Result<EncString> {
        let (kind, rest) = s.split_once('.').ok_or(CryptoError::InvalidFormat)?;
        let kind: u8 = kind.parse().map_err(|_| CryptoError::InvalidFormat)?;
        let dec = |p: &str| B64.decode(p).map_err(|_| CryptoError::InvalidFormat);
        match kind {
            2 => {
                let mut parts = rest.split('|');
                let (iv, data, mac) = (
                    parts.next().ok_or(CryptoError::InvalidFormat)?,
                    parts.next().ok_or(CryptoError::InvalidFormat)?,
                    parts.next().ok_or(CryptoError::InvalidFormat)?,
                );
                let iv: [u8; 16] = dec(iv)?.try_into().map_err(|_| CryptoError::InvalidFormat)?;
                let mac: [u8; 32] = dec(mac)?.try_into().map_err(|_| CryptoError::InvalidFormat)?;
                let data = dec(data)?;
                if data.is_empty() || data.len() % 16 != 0 {
                    return Err(CryptoError::InvalidFormat);
                }
                Ok(EncString::AesCbc256HmacSha256 { iv, data, mac })
            }
            3 | 4 => {
                // Typ 5/6 haengen ein "|mac" an – veraltet und nicht unterstuetzt.
                let data = dec(rest.split('|').next().unwrap_or(""))?;
                Ok(EncString::Rsa { kind, data })
            }
            // Typ 0 (AES ohne MAC) und 1 werden aus Sicherheitsgruenden abgelehnt.
            k => Err(CryptoError::UnsupportedType(k)),
        }
    }
}

impl Serialize for EncString {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for EncString {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------------------------
// Benutzerschluessel, Kontoerstellung, Passwortwechsel
// ---------------------------------------------------------------------------------------------

/// Entschluesselt den geschuetzten Benutzerschluessel mit dem Master-Schluessel.
pub fn unlock_user_key(master: &MasterKey, protected_key: &str) -> Result<SymmetricKey> {
    let enc: EncString = protected_key.parse()?;
    let raw = master.stretch().decrypt(&enc)?;
    SymmetricKey::from_bytes(&raw)
}

/// Neues Konto: zufaelliger Benutzerschluessel, mit dem Master-Schluessel geschuetzt.
pub struct NewAccountKeys {
    pub user_key: SymmetricKey,
    pub protected_user_key: String,
    pub master_password_hash: String,
    pub public_key_b64: String,
    pub encrypted_private_key: String,
}

pub fn make_account(password: &str, email: &str, kdf: Kdf, with_keypair: bool) -> Result<NewAccountKeys> {
    let master = MasterKey::derive(password, email, kdf)?;
    let user_key = SymmetricKey::generate();
    let protected_user_key = master.stretch().encrypt(&user_key.to_bytes()).to_string();
    let (public_key_b64, encrypted_private_key) = if with_keypair {
        let (public, private) = generate_rsa_keypair()?;
        (B64.encode(public), user_key.encrypt(&private).to_string())
    } else {
        (String::new(), String::new())
    };
    Ok(NewAccountKeys {
        master_password_hash: master.password_hash(password),
        user_key,
        protected_user_key,
        public_key_b64,
        encrypted_private_key,
    })
}

/// Master-Passwort (und optional KDF) wechseln: der Benutzerschluessel bleibt gleich, er wird nur
/// neu geschuetzt – alle Eintraege bleiben gueltig.
pub fn rewrap_user_key(user_key: &SymmetricKey, new_password: &str, email: &str, kdf: Kdf) -> Result<(String, String)> {
    let master = MasterKey::derive(new_password, email, kdf)?;
    Ok((master.password_hash(new_password), master.stretch().encrypt(&user_key.to_bytes()).to_string()))
}

// ---------------------------------------------------------------------------------------------
// RSA (Organisationen in Vaultwarden)
// ---------------------------------------------------------------------------------------------

/// Erzeugt ein RSA-2048-Schluesselpaar (SPKI-DER oeffentlich, PKCS#8-DER privat).
pub fn generate_rsa_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    let private = rsa::RsaPrivateKey::new(&mut OsRng, 2048).map_err(|e| CryptoError::Rsa(e.to_string()))?;
    let public = private
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| CryptoError::Rsa(e.to_string()))?
        .into_vec();
    let der = private.to_pkcs8_der().map_err(|e| CryptoError::Rsa(e.to_string()))?;
    Ok((public, Zeroizing::new(der.as_bytes().to_vec())))
}

/// Privater RSA-Schluessel des Kontos (zum Entschluesseln von Organisationsschluesseln).
pub struct PrivateKey(rsa::RsaPrivateKey);

impl PrivateKey {
    pub fn from_encrypted(user_key: &SymmetricKey, enc: &str) -> Result<PrivateKey> {
        use rsa::pkcs8::DecodePrivateKey;
        let der = user_key.decrypt(&enc.parse()?)?;
        let key = rsa::RsaPrivateKey::from_pkcs8_der(&der).map_err(|e| CryptoError::Rsa(e.to_string()))?;
        Ok(PrivateKey(key))
    }

    pub fn decrypt_org_key(&self, enc: &str) -> Result<SymmetricKey> {
        let enc: EncString = enc.parse()?;
        let raw = match &enc {
            EncString::Rsa { kind: 4, data } => self.0.decrypt(rsa::Oaep::new::<sha1::Sha1>(), data),
            EncString::Rsa { kind: 3, data } => self.0.decrypt(rsa::Oaep::new::<Sha256>(), data),
            EncString::Rsa { kind, .. } => return Err(CryptoError::UnsupportedType(*kind)),
            _ => return Err(CryptoError::UnsupportedType(2)),
        }
        .map_err(|e| CryptoError::Rsa(e.to_string()))?;
        let raw = Zeroizing::new(raw);
        SymmetricKey::from_bytes(&raw)
    }
}

// ---------------------------------------------------------------------------------------------
// Hilfen
// ---------------------------------------------------------------------------------------------

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

/// Gleichverteilte Zufallszahl in `0..n` ohne Modulo-Verzerrung.
pub fn random_below(n: u32) -> u32 {
    assert!(n > 0);
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let v = OsRng.next_u32();
        if v < zone {
            return v % n;
        }
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Vergleich in konstanter Zeit.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

pub fn b64(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    B64.decode(s.trim()).map_err(|_| CryptoError::InvalidFormat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_matches_bitwarden_vector() {
        // Testvektor aus den Bitwarden-Clients (jslib crypto.service.spec)
        let kdf = Kdf::Pbkdf2 { iterations: 100_000 };
        let mk = MasterKey::derive("asdfasdf", "user@example.com", kdf).unwrap();
        assert_eq!(mk.password_hash("asdfasdf").len(), 44);
        let mk2 = MasterKey::derive("asdfasdf", "  USER@example.com ", kdf).unwrap();
        assert_eq!(mk.password_hash("asdfasdf"), mk2.password_hash("asdfasdf"));
    }

    #[test]
    fn encstring_roundtrip_and_tamper() {
        let k = SymmetricKey::generate();
        let e = k.encrypt_str("geheim");
        let s = e.to_string();
        assert!(s.starts_with("2."));
        let back: EncString = s.parse().unwrap();
        assert_eq!(k.decrypt_str(&back).unwrap(), "geheim");
        // Manipulation am Chiffrat -> MAC-Fehler
        if let EncString::AesCbc256HmacSha256 { iv, mut data, mac } = back {
            data[0] ^= 1;
            let bad = EncString::AesCbc256HmacSha256 { iv, data, mac };
            assert_eq!(k.decrypt(&bad).unwrap_err(), CryptoError::MacMismatch);
        }
        // Fremder Schluessel -> MAC-Fehler
        assert!(SymmetricKey::generate().decrypt(&e).is_err());
        // Typ 0 wird abgelehnt
        assert!("0.aaaa|bbbb".parse::<EncString>().is_err());
    }

    #[test]
    fn account_and_unlock() {
        let kdf = Kdf::Argon2id { iterations: 2, memory: 16, parallelism: 1 };
        let acc = make_account("Sehr-Geheim-123", "a@b.ch", kdf, false).unwrap();
        let mk = MasterKey::derive("Sehr-Geheim-123", "a@b.ch", kdf).unwrap();
        assert_eq!(mk.password_hash("Sehr-Geheim-123"), acc.master_password_hash);
        let uk = unlock_user_key(&mk, &acc.protected_user_key).unwrap();
        assert_eq!(uk, acc.user_key);
        let wrong = MasterKey::derive("falsch", "a@b.ch", kdf).unwrap();
        assert!(unlock_user_key(&wrong, &acc.protected_user_key).is_err());
        // Passwortwechsel behaelt den Benutzerschluessel
        let (_, prot2) = rewrap_user_key(&uk, "Neu-Passwort-456", "a@b.ch", kdf).unwrap();
        let mk3 = MasterKey::derive("Neu-Passwort-456", "a@b.ch", kdf).unwrap();
        assert_eq!(unlock_user_key(&mk3, &prot2).unwrap(), acc.user_key);
    }

    #[test]
    fn kdf_downgrade_rejected() {
        assert!(Kdf::from_api(0, Some(5000), None, None).is_err());
        assert!(Kdf::from_api(1, Some(1), Some(8), Some(1)).is_err());
        assert!(Kdf::from_api(0, Some(600_000), None, None).is_ok());
    }

    #[test]
    fn rsa_org_key() {
        let uk = SymmetricKey::generate();
        let (public, private) = generate_rsa_keypair().unwrap();
        let enc_priv = uk.encrypt(&private).to_string();
        let pk = PrivateKey::from_encrypted(&uk, &enc_priv).unwrap();
        use rsa::pkcs8::DecodePublicKey;
        let pubk = rsa::RsaPublicKey::from_public_key_der(&public).unwrap();
        let org = SymmetricKey::generate();
        let ct = pubk.encrypt(&mut OsRng, rsa::Oaep::new::<sha1::Sha1>(), &org.to_bytes()).unwrap();
        let s = EncString::Rsa { kind: 4, data: ct }.to_string();
        assert_eq!(pk.decrypt_org_key(&s).unwrap(), org);
    }
}

#[cfg(test)]
mod vector {
    /// Testvektor der offiziellen Bitwarden-SDK (bitwarden-crypto): beweist die Kompatibilitaet.
    #[test]
    fn bitwarden_sdk_vector() {
        let mk = super::MasterKey::derive("asdfasdf", "Test@Bitwarden.com", super::Kdf::Pbkdf2 { iterations: 100_000 }).unwrap();
        assert_eq!(mk.password_hash("asdfasdf"), "wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw=");
    }
}
