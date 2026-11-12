//! URL-Abgleich wie bei Bitwarden (Standard: gleiche Basis-Domain).

/// Zweistufige Endungen, bei denen die Basis-Domain drei Teile hat.
const MULTI_TLD: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "co.at", "or.at", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "ne.jp", "or.jp", "com.br", "com.cn", "com.mx", "co.za", "co.in", "com.tr", "com.ar", "gv.at",
    "github.io", "gitlab.io", "pages.dev", "vercel.app", "netlify.app", "herokuapp.com", "blogspot.com",
];

/// Host (ohne Port) einer URL, kleingeschrieben. Ohne Schema wird `https://` angenommen.
pub fn host_of(url: &str) -> String {
    let s = url.trim();
    let after = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let authority = after.split(|c| c == '/' || c == '?' || c == '#').next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or("");
    let host = if authority.starts_with('[') {
        authority.split(']').next().unwrap_or("").trim_start_matches('[')
    } else {
        authority.split(':').next().unwrap_or("")
    };
    host.trim_end_matches('.').to_lowercase()
}

fn host_port(url: &str) -> String {
    let s = url.trim();
    let after = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    after.split(|c| c == '/' || c == '?' || c == '#').next().unwrap_or("").rsplit('@').next().unwrap_or("").to_lowercase()
}

fn is_ip(host: &str) -> bool {
    host.contains(':') || host.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Basis-Domain, z. B. `login.example.co.uk` -> `example.co.uk`.
pub fn base_domain(host: &str) -> String {
    let host = host.to_lowercase();
    if is_ip(&host) || !host.contains('.') {
        return host;
    }
    let parts: Vec<&str> = host.split('.').collect();
    let n = parts.len();
    let take = if n >= 3 && MULTI_TLD.contains(&format!("{}.{}", parts[n - 2], parts[n - 1]).as_str()) { 3 } else { 2 };
    parts[n.saturating_sub(take)..].join(".")
}

fn normalize(u: &str) -> String {
    if u.contains("://") { u.to_string() } else { format!("https://{u}") }
}

/// Passt eine gespeicherte URI zur aktuellen Seite? `match_type` wie Bitwarden:
/// 0/None = Basis-Domain, 1 = Host, 2 = beginnt mit, 3 = exakt, 4 = Regex (nicht unterstuetzt), 5 = nie.
pub fn matches(stored: &str, page: &str, match_type: Option<i64>) -> bool {
    let stored = normalize(stored);
    let page = normalize(page);
    let scheme_ok = |s: &str| s.starts_with("http://") || s.starts_with("https://");
    match match_type.unwrap_or(0) {
        0 => {
            if !scheme_ok(&stored) || !scheme_ok(&page) {
                return false;
            }
            let (a, b) = (host_of(&stored), host_of(&page));
            !a.is_empty() && base_domain(&a) == base_domain(&b)
        }
        1 => host_port(&stored) == host_port(&page) && !host_port(&stored).is_empty(),
        2 => page.starts_with(&stored),
        3 => page == stored,
        _ => false,
    }
}

/// Startadresse zum Oeffnen (nur http/https, damit keine `javascript:`-Links entstehen).
pub fn launch_url(stored: &str) -> Option<String> {
    let t = stored.trim();
    if let Some((scheme, _)) = t.split_once(':') {
        let lower = scheme.to_lowercase();
        if lower != "http" && lower != "https" && !scheme.contains('.') && !scheme.contains('/') {
            return None; // javascript:, data:, file: …
        }
    }
    let u = normalize(t);
    (u.starts_with("https://") || u.starts_with("http://")).then_some(u)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domains() {
        assert_eq!(base_domain("login.example.co.uk"), "example.co.uk");
        assert_eq!(base_domain("accounts.google.com"), "google.com");
        assert!(matches("https://github.com/login", "https://gist.github.com/x", None));
        assert!(!matches("https://github.com", "https://github.com.evil.io", None));
        assert!(!matches("https://a.github.io", "https://b.github.io", None));
        assert!(matches("example.com", "https://www.example.com/a", Some(0)));
        assert!(!matches("https://example.com", "https://www.example.com", Some(1)));
        assert_eq!(launch_url("javascript:alert(1)"), None);
        assert_eq!(host_of("https://user:pw@Example.com:8443/p"), "example.com");
    }
}
