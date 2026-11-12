//! Einfache, nachvollziehbare Passwortstaerke (0 = sehr schwach … 4 = sehr stark).

const COMMON: &[&str] = &[
    "123456", "password", "passwort", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567",
    "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein", "shadow", "master", "666666",
    "qwertz", "hallo", "hallo123", "schatz", "iloveyou", "admin", "welcome", "login", "princess", "sunshine",
    "geheim", "passw0rd", "starwars", "whatever", "trustno1", "000000", "asdf", "asdfgh", "killer", "test",
];

#[derive(Debug, Clone, PartialEq)]
pub struct Strength {
    pub score: u8,
    pub bits: f64,
    pub label: &'static str,
}

pub fn estimate(pw: &str) -> Strength {
    if pw.is_empty() {
        return Strength { score: 0, bits: 0.0, label: "leer" };
    }
    let lower = pw.to_lowercase();
    let mut pool = 0u32;
    if pw.chars().any(|c| c.is_ascii_lowercase()) { pool += 26; }
    if pw.chars().any(|c| c.is_ascii_uppercase()) { pool += 26; }
    if pw.chars().any(|c| c.is_ascii_digit()) { pool += 10; }
    if pw.chars().any(|c| c.is_ascii_punctuation() || c == ' ') { pool += 33; }
    if pw.chars().any(|c| !c.is_ascii()) { pool += 60; }
    // Wiederholungen und Folgen zaehlen nur halb
    let chars: Vec<char> = pw.chars().collect();
    let mut eff = 0.0;
    for (i, c) in chars.iter().enumerate() {
        let weak = i > 0 && (chars[i - 1] == *c || (*c as i32 - chars[i - 1] as i32).abs() == 1);
        eff += if weak { 0.4 } else { 1.0 };
    }
    let mut bits = eff * (pool.max(1) as f64).log2();
    if COMMON.iter().any(|c| lower.contains(c)) {
        bits = bits.min(18.0) * 0.6;
    }
    // Passphrasen (mehrere Woerter mit Trennzeichen) sind besser als ihre Zeichenklassen vermuten lassen
    let words = pw.split(|c: char| c == '-' || c == ' ' || c == '_' || c == '.').filter(|w| w.len() >= 3).count();
    if words >= 4 {
        bits = bits.max(words as f64 * 12.9);
    }
    let score = match bits {
        b if b < 28.0 => 0,
        b if b < 40.0 => 1,
        b if b < 60.0 => 2,
        b if b < 80.0 => 3,
        _ => 4,
    };
    let label = ["sehr schwach", "schwach", "mittel", "stark", "sehr stark"][score as usize];
    Strength { score, bits, label }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordering() {
        assert_eq!(estimate("123456").score, 0);
        assert!(estimate("Passwort1").score <= 1);
        assert!(estimate("x7#Kp2!qLm9@Zr4$Tw8&").score >= 4);
        assert!(estimate("Kanu-Wolke-Apfel-Zebra-Turm").score >= 3);
    }
}
