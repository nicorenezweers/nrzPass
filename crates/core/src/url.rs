//! URL-Abgleich wie bei Bitwarden (Standard: gleiche Basis-Domain) – mit einer Ausnahme:
//! IP-Adressen und lokale Namen (`localhost`, `*.local`, `*.lan`, Tailscale `*.ts.net`, Namen
//! ohne Punkt) stehen fuer einzelne Geraete, auf denen oft mehrere Dienste an verschiedenen Ports
//! laufen (z. B. Umbrel: nrzGit auf 8390, nrzPass auf 8490). Dort muessen Host **und Port**
//! uebereinstimmen. Bei oeffentlichen Domains zaehlt der Port nur, wenn er in der gespeicherten
//! Adresse ausdruecklich steht.

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

/// Port aus der Adresse, falls ausdruecklich angegeben.
pub fn explicit_port(url: &str) -> Option<u16> {
    let hp = host_port(url);
    let rest = if hp.starts_with('[') { hp.split(']').nth(1).unwrap_or("") } else { hp.as_str() };
    let p = if hp.starts_with('[') { rest.strip_prefix(':')? } else { rest.rsplit_once(':')?.1 };
    p.parse().ok()
}

fn scheme_of(url: &str) -> Option<String> {
    url.trim().split_once("://").map(|(s, _)| s.to_lowercase())
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "http" { 80 } else { 443 }
}

/// Port, der tatsaechlich verwendet wird (ausdruecklich oder Standard des Schemas).
pub fn effective_port(url: &str) -> u16 {
    explicit_port(url).unwrap_or_else(|| default_port(&scheme_of(url).unwrap_or_else(|| "https".into())))
}

/// Ein einzelnes Geraet statt einer oeffentlichen Domain? (IP, localhost, .local, Tailscale …)
pub fn is_local_host(host: &str) -> bool {
    const LOCAL: &[&str] = &[".local", ".lan", ".home", ".internal", ".localhost", ".home.arpa", ".ts.net", ".intranet", ".fritz.box"];
    let h = host.trim_end_matches('.').to_lowercase();
    !h.is_empty() && (is_ip(&h) || !h.contains('.') || h == "localhost" || LOCAL.iter().any(|s| h.ends_with(s)))
}

/// Schluessel einer "Seite" fuer Vergleiche (Speichern anbieten, "Nie fuer diese Seite"):
/// lokal `host:port`, sonst die Basis-Domain.
pub fn site_key(url: &str) -> String {
    let u = normalize(url);
    let host = host_of(&u);
    if is_local_host(&host) {
        format!("{}:{}", host, effective_port(&u))
    } else {
        base_domain(&host)
    }
}

/// Anzeigename fuer eine Seite: Host ohne `www.`, bei lokalen Geraeten mit Port.
pub fn display_name(url: &str) -> String {
    let u = normalize(url);
    let host = host_of(&u);
    let h = host.strip_prefix("www.").unwrap_or(&host).to_string();
    match explicit_port(&u) {
        Some(p) if is_local_host(&host) || p != default_port(&scheme_of(&u).unwrap_or_default()) => format!("{h}:{p}"),
        _ => h,
    }
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
    let raw_stored = stored;
    let stored = normalize(stored);
    let page = normalize(page);
    let scheme_ok = |s: &str| s.starts_with("http://") || s.starts_with("https://");
    match match_type.unwrap_or(0) {
        0 => {
            if !scheme_ok(&stored) || !scheme_ok(&page) {
                return false;
            }
            let (a, b) = (host_of(&stored), host_of(&page));
            if a.is_empty() {
                return false;
            }
            if is_local_host(&a) || is_local_host(&b) {
                // Ein Geraet, mehrere Dienste: Host und Port muessen passen
                return a == b && port_matches(raw_stored, &stored, &page);
            }
            base_domain(&a) == base_domain(&b)
                && explicit_port(&stored).map_or(true, |p| p == effective_port(&page))
        }
        1 => host_port(&stored) == host_port(&page) && !host_port(&stored).is_empty(),
        2 => page.starts_with(&stored),
        3 => page == stored,
        _ => false,
    }
}

/// Port-Vergleich fuer lokale Geraete. Ohne ausdruecklichen Port gilt der Standard-Port des
/// gespeicherten Schemas – steht auch kein Schema da, der des Schemas der Seite.
fn port_matches(raw_stored: &str, stored: &str, page: &str) -> bool {
    let want = match explicit_port(stored) {
        Some(p) => p,
        None => match scheme_of(raw_stored) {
            Some(s) => default_port(&s),
            None => default_port(&scheme_of(page).unwrap_or_else(|| "https".into())),
        },
    };
    want == effective_port(page)
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

    #[test]
    fn ports_on_local_devices() {
        // Gleiche IP, anderer Port = anderer Dienst
        assert!(matches("http://192.168.1.10:8390", "http://192.168.1.10:8390/user/login", None));
        assert!(!matches("http://192.168.1.10:8390", "http://192.168.1.10:8490/", None));
        assert!(!matches("http://100.78.107.162:8390/login", "http://100.78.107.162:8101/", None));
        // Ohne Port: Standard-Port
        assert!(matches("http://192.168.1.10", "http://192.168.1.10/admin", None));
        assert!(!matches("http://192.168.1.10", "http://192.168.1.10:8080/", None));
        assert!(matches("192.168.1.10", "http://192.168.1.10/", None));
        assert!(matches("192.168.1.10:8080", "http://192.168.1.10:8080/", None));
        // Lokale Namen und Tailscale
        assert!(!matches("http://umbrel.local:8390", "http://umbrel.local:8490", None));
        assert!(matches("http://umbrel.local:8490", "http://umbrel.local:8490/x", None));
        assert!(!matches("https://nas.tail1234.ts.net", "https://pi.tail1234.ts.net", None));
        assert!(!matches("http://localhost:3000", "http://localhost:5173", None));
        assert!(matches("http://[::1]:8080/a", "http://[::1]:8080/b", None));
        assert!(!matches("http://[::1]:8080/a", "http://[::1]:9090/b", None));
        // Oeffentliche Domain: Port nur, wenn gespeichert
        assert!(matches("https://example.com", "https://login.example.com:8443/", None));
        assert!(!matches("https://example.com:8443", "https://example.com/", None));
        assert!(matches("https://example.com:8443", "https://www.example.com:8443/", None));
        // Seiten-Schluessel und Anzeigename
        assert_eq!(site_key("http://192.168.1.10:8390/x"), "192.168.1.10:8390");
        assert_eq!(site_key("http://192.168.1.10/x"), "192.168.1.10:80");
        assert_eq!(site_key("https://accounts.google.com"), "google.com");
        assert_eq!(display_name("http://192.168.1.10:8390/x"), "192.168.1.10:8390");
        assert_eq!(display_name("https://www.github.com/login"), "github.com");
    }
}
