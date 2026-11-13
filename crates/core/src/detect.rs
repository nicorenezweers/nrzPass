//! Erkennung von Anmelde-, Registrierungs- und Passwort-aendern-Formularen.
//!
//! Die Browser-Erweiterung sammelt pro Eingabefeld ein [`FieldInfo`] und laesst es hier
//! einordnen. Die Logik ist rein und deshalb nativ testbar.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FieldInfo {
    pub input_type: String,
    pub name: String,
    pub id: String,
    pub autocomplete: String,
    pub placeholder: String,
    pub aria_label: String,
    pub label: String,
    pub visible: bool,
    /// `maxlength` (0 = nicht gesetzt)
    #[serde(default)]
    pub max_length: i64,
    /// `inputmode` (z. B. "numeric")
    #[serde(default)]
    pub input_mode: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldKind {
    Username,
    CurrentPassword,
    NewPassword,
    Totp,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FormKind {
    Login,
    Signup,
    ChangePassword,
    Totp,
    None,
}

impl FieldInfo {
    fn hay(&self) -> String {
        format!("{} {} {} {} {}", self.name, self.id, self.placeholder, self.aria_label, self.label).to_lowercase()
    }
}

const USER_WORDS: &[&str] = &[
    "user", "login", "email", "e-mail", "mail", "account", "benutzer", "anmelde", "konto", "identifier", "nutzer",
    "username", "userid", "kennung", "handle",
];
const NEW_WORDS: &[&str] = &[
    "new", "neu", "confirm", "bestaetig", "bestätig", "repeat", "wiederhol", "retype", "verify", "create", "register",
    "signup", "sign-up", "sign_up", "registrier",
];
const TOTP_WORDS: &[&str] = &[
    "otp", "totp", "2fa", "mfa", "one-time", "onetime", "einmal", "authenticator", "verification code", "sicherheitscode",
    "bestätigungscode", "bestaetigungscode", "security code", "auth code", "token", "two-factor", "two_factor",
    "twofactor", "2-step", "2step", "two-step", "zwei-faktor", "zweifaktor", "verifizierungscode", "authentication code",
    "authentifizierungscode", "login code", "anmeldecode", "app code", "tfa", "passcode", "sms code", "sms-code",
];
/// "Code"-Felder, die keine Einmalcodes sind.
const NOT_OTP_CODE: &[&str] = &["zip", "plz", "postal", "postleit", "promo", "voucher", "rabatt", "discount", "country", "area"];
const SEARCH_WORDS: &[&str] = &["search", "suche", "query", "coupon", "gutschein", "captcha", "newsletter"];

fn any(h: &str, words: &[&str]) -> bool {
    words.iter().any(|w| h.contains(w))
}

/// Einordnung eines einzelnen Feldes (ohne Formularkontext).
pub fn classify(f: &FieldInfo) -> FieldKind {
    let t = f.input_type.to_lowercase();
    let ac = f.autocomplete.to_lowercase();
    let hay = f.hay();
    if !f.visible || matches!(t.as_str(), "hidden" | "submit" | "button" | "checkbox" | "radio" | "file" | "image" | "reset") {
        return FieldKind::Other;
    }
    if ac.contains("one-time-code") {
        return FieldKind::Totp;
    }
    if t == "password" {
        if ac.contains("new-password") || any(&hay, NEW_WORDS) {
            return FieldKind::NewPassword;
        }
        return FieldKind::CurrentPassword;
    }
    if !matches!(t.as_str(), "text" | "email" | "tel" | "" | "number") {
        return FieldKind::Other;
    }
    if any(&hay, SEARCH_WORDS) || ac == "off" && any(&hay, SEARCH_WORDS) {
        return FieldKind::Other;
    }
    if any(&hay, TOTP_WORDS) && !any(&hay, USER_WORDS) {
        return FieldKind::Totp;
    }
    // "Code" mit Zifferntastatur oder 6–8 Stellen (z. B. "Bestätigungs-Code", "Enter code")
    let numeric = f.input_mode.eq_ignore_ascii_case("numeric") || matches!(t.as_str(), "tel" | "number");
    if hay.contains("code") && !any(&hay, NOT_OTP_CODE) && !any(&hay, USER_WORDS) && (numeric || (6..=8).contains(&f.max_length)) {
        return FieldKind::Totp;
    }
    if ac.contains("username") || ac.contains("email") || t == "email" || any(&hay, USER_WORDS) {
        return FieldKind::Username;
    }
    FieldKind::Other
}

/// Ordnet alle Felder eines Formulars ein. Bei Passwortfeldern entscheidet der Kontext:
/// zwei Passwortfelder = Registrierung (beide neu), drei = Passwort aendern (erstes = aktuell).
/// Fehlt ein erkanntes Benutzerfeld, gilt das letzte Textfeld vor dem ersten Passwortfeld.
pub fn classify_form(fields: &[FieldInfo]) -> (FormKind, Vec<FieldKind>) {
    let mut kinds: Vec<FieldKind> = fields.iter().map(classify).collect();
    let pw_idx: Vec<usize> = kinds
        .iter()
        .enumerate()
        .filter(|(_, k)| matches!(k, FieldKind::CurrentPassword | FieldKind::NewPassword))
        .map(|(i, _)| i)
        .collect();

    if pw_idx.is_empty() {
        // Einmalcode in Einzelfeldern (4–8 Felder mit je einem Zeichen)
        let single: Vec<usize> = fields
            .iter()
            .enumerate()
            .filter(|(i, f)| {
                f.visible && f.max_length == 1 && matches!(f.input_type.to_lowercase().as_str(), "text" | "tel" | "number" | "")
                    && matches!(kinds[*i], FieldKind::Other | FieldKind::Totp)
            })
            .map(|(i, _)| i)
            .collect();
        if (4..=8).contains(&single.len()) {
            for &i in &single {
                kinds[i] = FieldKind::Totp;
            }
        }
        if kinds.contains(&FieldKind::Totp) {
            return (FormKind::Totp, kinds);
        }
        // Mehrstufige Anmeldung (erst E-Mail, dann Passwort): einzelnes Benutzerfeld
        let users = kinds.iter().filter(|k| **k == FieldKind::Username).count();
        let others = fields.iter().zip(&kinds).filter(|(f, k)| f.visible && **k == FieldKind::Other && f.input_type != "hidden").count();
        if users == 1 && others == 0 {
            return (FormKind::Login, kinds);
        }
        return (FormKind::None, kinds);
    }

    let form = match pw_idx.len() {
        1 => {
            if kinds[pw_idx[0]] == FieldKind::NewPassword { FormKind::Signup } else { FormKind::Login }
        }
        2 => {
            if kinds[pw_idx[0]] == FieldKind::CurrentPassword && kinds[pw_idx[1]] == FieldKind::NewPassword {
                FormKind::ChangePassword
            } else {
                for &i in &pw_idx {
                    kinds[i] = FieldKind::NewPassword;
                }
                FormKind::Signup
            }
        }
        _ => {
            kinds[pw_idx[0]] = FieldKind::CurrentPassword;
            for &i in &pw_idx[1..] {
                kinds[i] = FieldKind::NewPassword;
            }
            FormKind::ChangePassword
        }
    };

    if !kinds.contains(&FieldKind::Username) && form != FormKind::ChangePassword {
        if let Some(i) = (0..pw_idx[0]).rev().find(|&i| {
            let t = fields[i].input_type.to_lowercase();
            fields[i].visible && matches!(t.as_str(), "text" | "email" | "tel" | "") && !any(&fields[i].hay(), SEARCH_WORDS)
        }) {
            kinds[i] = FieldKind::Username;
        }
    }
    (form, kinds)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn f(t: &str, name: &str, ac: &str) -> FieldInfo {
        FieldInfo { input_type: t.into(), name: name.into(), autocomplete: ac.into(), visible: true, ..Default::default() }
    }
    #[test]
    fn login() {
        let (k, kinds) = classify_form(&[f("text", "j_x1", ""), f("password", "pw", "")]);
        assert_eq!(k, FormKind::Login);
        assert_eq!(kinds, vec![FieldKind::Username, FieldKind::CurrentPassword]);
    }
    #[test]
    fn signup() {
        let (k, kinds) = classify_form(&[f("email", "email", ""), f("password", "password", ""), f("password", "password2", "")]);
        assert_eq!(k, FormKind::Signup);
        assert_eq!(kinds[1], FieldKind::NewPassword);
        assert_eq!(kinds[2], FieldKind::NewPassword);
    }
    #[test]
    fn change() {
        let (k, kinds) = classify_form(&[f("password", "old", ""), f("password", "new", "new-password"), f("password", "confirm", "")]);
        assert_eq!(k, FormKind::ChangePassword);
        assert_eq!(kinds[0], FieldKind::CurrentPassword);
    }
    #[test]
    fn totp_and_search() {
        assert_eq!(classify(&f("text", "otp_code", "")), FieldKind::Totp);
        assert_eq!(classify(&f("text", "q", "one-time-code")), FieldKind::Totp);
        assert_eq!(classify(&f("text", "search_user", "")), FieldKind::Other);
    }
    #[test]
    fn totp_variants() {
        let mut code = f("text", "code", "");
        assert_eq!(classify(&code), FieldKind::Other);
        code.input_mode = "numeric".into();
        assert_eq!(classify(&code), FieldKind::Totp);
        let mut plz = f("text", "zip_code", "");
        plz.input_mode = "numeric".into();
        assert_eq!(classify(&plz), FieldKind::Other);
        assert_eq!(classify(&f("text", "app_two_factor", "")), FieldKind::Totp);
        let mut six = f("text", "verify_code", "");
        six.max_length = 6;
        assert_eq!(classify(&six), FieldKind::Totp);
        // Sechs Einzelfelder
        let boxes: Vec<FieldInfo> = (0..6).map(|i| { let mut b = f("text", &format!("d{i}"), ""); b.max_length = 1; b }).collect();
        let (k, kinds) = classify_form(&boxes);
        assert_eq!(k, FormKind::Totp);
        assert!(kinds.iter().all(|k| *k == FieldKind::Totp));
    }
}
