//! TOTP-Codes (RFC 6238) fuer Eintraege mit Authentifizierungsschluessel, inkl. Steam Guard.

use hmac::{Hmac, Mac};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Totp {
    pub secret: Vec<u8>,
    pub digits: u32,
    pub period: u64,
    pub algo: Algo,
    pub steam: bool,
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits: u64 = 0;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=' && *c != '-') {
        let v = A.iter().position(|a| *a == c.to_ascii_uppercase() as u8)? as u64;
        bits = (bits << 5) | v;
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
            bits &= (1 << n) - 1;
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn query_param<'a>(q: &'a str, key: &str) -> Option<String> {
    q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k.eq_ignore_ascii_case(key)).then(|| v.replace("%3D", "=").replace("%20", " "))
    })
}

impl Totp {
    /// Akzeptiert `otpauth://totp/...?secret=...`, `steam://SECRET` oder einen Base32-Schluessel.
    pub fn parse(input: &str) -> Option<Totp> {
        let s = input.trim();
        if let Some(rest) = s.strip_prefix("steam://") {
            return Some(Totp { secret: base32_decode(rest)?, digits: 5, period: 30, algo: Algo::Sha1, steam: true });
        }
        if s.to_lowercase().starts_with("otpauth://") {
            let q = s.split_once('?')?.1;
            let algo = match query_param(q, "algorithm").unwrap_or_default().to_uppercase().as_str() {
                "SHA256" => Algo::Sha256,
                "SHA512" => Algo::Sha512,
                _ => Algo::Sha1,
            };
            return Some(Totp {
                secret: base32_decode(&query_param(q, "secret")?)?,
                digits: query_param(q, "digits").and_then(|d| d.parse().ok()).filter(|d| (6..=10).contains(d)).unwrap_or(6),
                period: query_param(q, "period").and_then(|d| d.parse().ok()).filter(|p| *p > 0 && *p <= 300).unwrap_or(30),
                algo,
                steam: false,
            });
        }
        Some(Totp { secret: base32_decode(s)?, digits: 6, period: 30, algo: Algo::Sha1, steam: false })
    }

    pub fn code_at(&self, unix_secs: u64) -> String {
        let counter = (unix_secs / self.period).to_be_bytes();
        let h: Vec<u8> = match self.algo {
            Algo::Sha1 => mac_sha1(&self.secret, &counter),
            Algo::Sha256 => mac_sha256(&self.secret, &counter),
            Algo::Sha512 => mac_sha512(&self.secret, &counter),
        };
        let off = (h[h.len() - 1] & 0x0f) as usize;
        let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
        if self.steam {
            const CH: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";
            let mut v = bin;
            (0..5).map(|_| { let c = CH[(v % 26) as usize] as char; v /= 26; c }).collect()
        } else {
            format!("{:0width$}", bin % 10u32.pow(self.digits.min(9)), width = self.digits.min(9) as usize)
        }
    }

    pub fn remaining(&self, unix_secs: u64) -> u64 {
        self.period - unix_secs % self.period
    }
}

macro_rules! hmac_with {
    ($name:ident, $d:ty) => {
        fn $name(key: &[u8], msg: &[u8]) -> Vec<u8> {
            let mut m = <Hmac<$d> as Mac>::new_from_slice(key).expect("HMAC akzeptiert jede Laenge");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
    };
}
hmac_with!(mac_sha1, sha1::Sha1);
hmac_with!(mac_sha256, sha2::Sha256);
hmac_with!(mac_sha512, sha2::Sha512);

/// Erzeugt einen neuen zufaelligen TOTP-Schluessel (Base32, 160 Bit) – fuer die Zwei-Faktor-Einrichtung.
pub fn new_secret() -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    crate::crypto::random_bytes(20)
        .chunks(5)
        .flat_map(|c| {
            let v = c.iter().fold(0u64, |a, b| (a << 8) | *b as u64);
            (0..8).rev().map(move |i| A[((v >> (i * 5)) & 31) as usize] as char)
        })
        .collect()
}

/// Prueft einen Code mit +-1 Zeitfenster Toleranz.
pub fn verify(secret_b32: &str, code: &str, unix_secs: u64) -> bool {
    let Some(t) = Totp::parse(secret_b32) else { return false };
    let code = code.trim().replace(' ', "");
    [unix_secs.saturating_sub(30), unix_secs, unix_secs + 30]
        .iter()
        .any(|s| crate::crypto::ct_eq(t.code_at(*s).as_bytes(), code.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc6238_sha1() {
        // RFC 6238 Anhang B, Schluessel "12345678901234567890"
        let t = Totp { secret: b"12345678901234567890".to_vec(), digits: 8, period: 30, algo: Algo::Sha1, steam: false };
        assert_eq!(t.code_at(59), "94287082");
        assert_eq!(t.code_at(1111111109), "07081804");
    }
    #[test]
    fn parse_uri_and_verify() {
        let s = new_secret();
        let t = Totp::parse(&format!("otpauth://totp/x?secret={s}&issuer=nrz")).unwrap();
        assert!(verify(&s, &t.code_at(1_000_000), 1_000_000));
        assert!(!verify(&s, "000000", 1_000_000) || t.code_at(1_000_000) == "000000");
    }
}
