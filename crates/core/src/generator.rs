//! Passwort- und Passphrasen-Generator (kryptografisch sicherer Zufall, ohne Modulo-Verzerrung).

use crate::crypto::random_below;
use serde::{Deserialize, Serialize};

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*-_=+?.:;,~";
const AMBIGUOUS: &str = "Il1O0o";

static WORDS: &str = include_str!("../data/eff_large_wordlist.txt");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOptions {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        PasswordOptions { length: 20, upper: true, lower: true, digits: true, symbols: true, avoid_ambiguous: true }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        PassphraseOptions { words: 5, separator: "-".into(), capitalize: true, number: true }
    }
}

fn pick(set: &[char]) -> char {
    set[random_below(set.len() as u32) as usize]
}

/// Erzeugt ein Passwort, das jede gewaehlte Zeichengruppe mindestens einmal enthaelt.
pub fn password(o: &PasswordOptions) -> String {
    let clean = |s: &str| -> Vec<char> {
        s.chars().filter(|c| !(o.avoid_ambiguous && AMBIGUOUS.contains(*c))).collect()
    };
    let mut groups: Vec<Vec<char>> = Vec::new();
    if o.upper { groups.push(clean(UPPER)); }
    if o.lower { groups.push(clean(LOWER)); }
    if o.digits { groups.push(clean(DIGITS)); }
    if o.symbols { groups.push(clean(SYMBOLS)); }
    if groups.is_empty() { groups.push(clean(LOWER)); }
    let len = o.length.clamp(groups.len().max(5), 128);
    let all: Vec<char> = groups.iter().flatten().copied().collect();
    let mut out: Vec<char> = groups.iter().map(|g| pick(g)).collect();
    while out.len() < len {
        out.push(pick(&all));
    }
    // Fisher-Yates, damit die Pflichtzeichen nicht vorne stehen
    for i in (1..out.len()).rev() {
        let j = random_below(i as u32 + 1) as usize;
        out.swap(i, j);
    }
    out.into_iter().collect()
}

/// Passphrase aus der EFF-Wortliste (7776 Woerter, ca. 12,9 Bit je Wort).
pub fn passphrase(o: &PassphraseOptions) -> String {
    let words: Vec<&str> = WORDS.lines().filter(|l| !l.is_empty()).collect();
    let n = o.words.clamp(3, 20);
    let num_at = if o.number { Some(random_below(n as u32) as usize) } else { None };
    (0..n)
        .map(|i| {
            let w = words[random_below(words.len() as u32) as usize];
            let mut w = if o.capitalize {
                let mut c = w.chars();
                c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
            } else {
                w.to_string()
            };
            if num_at == Some(i) {
                w.push_str(&random_below(10).to_string());
            }
            w
        })
        .collect::<Vec<_>>()
        .join(&o.separator)
}

/// Starkes Standardpasswort fuer Vorschlaege der Browser-Erweiterung.
pub fn suggest() -> String {
    password(&PasswordOptions::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn has_all_groups() {
        for _ in 0..50 {
            let p = password(&PasswordOptions::default());
            assert_eq!(p.chars().count(), 20);
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
            assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
        }
    }
    #[test]
    fn passphrase_words() {
        let p = passphrase(&PassphraseOptions::default());
        assert_eq!(p.split('-').count(), 5);
    }
}
