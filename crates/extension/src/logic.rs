//! Reine Logik der Erweiterung: Abgleich mit dem Index und Entscheidung "speichern/aktualisieren".

use nrzpass_core::url;
use serde::{Deserialize, Serialize};

/// Ein Login im Sitzungs-Index (geschrieben vom Popup nach dem Entsperren).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct IndexItem {
    pub key: String,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Vec<(String, Option<i64>)>,
    pub reprompt: i64,
}

impl IndexItem {
    pub fn matches(&self, page: &str) -> bool {
        self.uris.iter().any(|(u, m)| url::matches(u, page, *m))
    }
    /// Nur Eintraege im eigenen nrzPass-Tresor koennen aus der Erweiterung geaendert werden.
    pub fn primary_id(&self) -> Option<&str> {
        self.key.strip_prefix("nrz:")
    }
}

pub fn parse_index(json: &str) -> Vec<IndexItem> {
    serde_json::from_str(json).unwrap_or_default()
}

pub fn matching<'a>(index: &'a [IndexItem], page: &str) -> Vec<&'a IndexItem> {
    if !(page.starts_with("http://") || page.starts_with("https://")) {
        return vec![];
    }
    index.iter().filter(|i| i.matches(page)).collect()
}

/// `https://host[:port]` einer Adresse (leer, wenn kein http/https).
pub fn origin_of(u: &str) -> String {
    let Some((scheme, rest)) = u.split_once("://") else { return String::new() };
    if scheme != "http" && scheme != "https" {
        return String::new();
    }
    let auth = rest.split(|c| c == '/' || c == '?' || c == '#').next().unwrap_or("");
    let auth = auth.rsplit('@').next().unwrap_or("");
    format!("{scheme}://{}", auth.to_lowercase())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum Decision {
    None,
    New,
    Update { key: String },
}

/// Soll nach dem Absenden eines Formulars "Speichern" oder "Aktualisieren" angeboten werden?
pub fn decide(index: &[IndexItem], page: &str, username: &str, password: &str, never: &[String]) -> Decision {
    if password.is_empty() || origin_of(page).is_empty() {
        return Decision::None;
    }
    let base = url::site_key(page);
    if never.iter().any(|n| *n == base) {
        return Decision::None;
    }
    let cands = matching(index, page);
    let user = username.trim().to_lowercase();
    let same_user: Vec<&&IndexItem> = cands
        .iter()
        .filter(|i| i.username.as_deref().unwrap_or("").trim().to_lowercase() == user)
        .collect();
    if let Some(i) = same_user.iter().find(|i| i.password.as_deref() == Some(password)) {
        let _ = i;
        return Decision::None;
    }
    if let Some(i) = same_user.iter().find(|i| i.primary_id().is_some()) {
        return Decision::Update { key: i.key.clone() };
    }
    if !same_user.is_empty() {
        // Eintrag liegt in einem verknuepften Konto (Vaultwarden): dort nicht aendern
        return Decision::None;
    }
    if user.is_empty() && cands.iter().any(|i| i.password.as_deref() == Some(password)) {
        return Decision::None;
    }
    Decision::New
}

/// Anzeigename fuer einen neuen Eintrag: Host ohne `www.`.
pub fn entry_name(page: &str) -> String {
    url::display_name(page)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(key: &str, user: &str, pw: &str, uri: &str) -> IndexItem {
        IndexItem {
            key: key.into(),
            name: "x".into(),
            username: Some(user.into()),
            password: Some(pw.into()),
            uris: vec![(uri.into(), None)],
            ..Default::default()
        }
    }

    #[test]
    fn parse_index_format() {
        let j = r#"[{"key":"nrz:1","name":"GitHub","username":"nico","password":"p","totp":null,"uris":[["https://github.com",null],["https://x.ch",3]],"reprompt":0}]"#;
        let i = parse_index(j);
        assert_eq!(i.len(), 1);
        assert_eq!(i[0].uris[1], ("https://x.ch".to_string(), Some(3)));
        assert!(i[0].matches("https://gist.github.com/a"));
    }

    #[test]
    fn decisions() {
        let idx = vec![item("nrz:1", "nico", "alt", "https://github.com"), item("vw1:2", "max", "pw", "https://github.com")];
        let p = "https://github.com/login";
        assert_eq!(decide(&idx, p, "nico", "alt", &[]), Decision::None);
        assert_eq!(decide(&idx, p, "Nico", "neu", &[]), Decision::Update { key: "nrz:1".into() });
        assert_eq!(decide(&idx, p, "max", "anders", &[]), Decision::None);
        assert_eq!(decide(&idx, p, "neu", "pw2", &[]), Decision::New);
        assert_eq!(decide(&idx, p, "neu", "pw2", &["github.com".into()]), Decision::None);
        assert_eq!(decide(&idx, p, "neu", "", &[]), Decision::None);
        assert_eq!(decide(&idx, "chrome://settings", "a", "b", &[]), Decision::None);
        assert_eq!(decide(&idx, "https://evil-github.com", "nico", "alt", &[]), Decision::New);
    }

    #[test]
    fn origins() {
        assert_eq!(origin_of("https://User@Example.com:8443/a?b"), "https://example.com:8443");
        assert_eq!(origin_of("javascript:alert(1)"), "");
        assert_eq!(entry_name("https://www.digitec.ch/login"), "digitec.ch");
    }

    #[test]
    fn port_aware_on_ip_addresses() {
        let idx = vec![item("nrz:a", "nico", "pw-git", "http://192.168.1.10:8390"), item("nrz:b", "nico", "pw-pass", "http://192.168.1.10:8490")];
        let m = matching(&idx, "http://192.168.1.10:8490/login");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].key, "nrz:b");
        assert!(matching(&idx, "http://192.168.1.10:9000/").is_empty());
        // Neuer Dienst auf anderem Port: Speichern anbieten statt "aktualisieren"
        assert!(matches!(decide(&idx, "http://192.168.1.10:9000/", "nico", "neu", &[]), Decision::New));
        assert_eq!(entry_name("http://192.168.1.10:9000/x"), "192.168.1.10:9000");
    }
}
