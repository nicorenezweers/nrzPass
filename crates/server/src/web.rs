//! Web-Tresor (von trunk gebaut, eingebettet), Sicherheits-Header und CORS.

use crate::St;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rust_embed::RustEmbed;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::path::PathBuf;
use tower_http::cors::{AllowOrigin, CorsLayer};

#[derive(RustEmbed)]
#[folder = "../../dist/web"]
struct Embedded;

pub struct WebAssets {
    dir: Option<PathBuf>,
    csp: String,
}

/// SHA-256-Hashes aller Inline-Skripte (`<script>` ohne `src`) fuer die CSP.
fn inline_script_hashes(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("<script") {
        let after = &rest[start..];
        let Some(tag_end) = after.find('>') else { break };
        let tag = &after[..tag_end];
        let body_start = tag_end + 1;
        let Some(close) = after[body_start..].find("</script>") else { break };
        let body = &after[body_start..body_start + close];
        if !tag.contains(" src=") && !body.trim().is_empty() {
            out.push(format!("'sha256-{}'", B64.encode(Sha256::digest(body.as_bytes()))));
        }
        rest = &after[body_start + close..];
    }
    out
}

impl WebAssets {
    pub fn load(dir: Option<PathBuf>) -> WebAssets {
        let index = match &dir {
            Some(d) => std::fs::read_to_string(d.join("index.html")).unwrap_or_default(),
            None => Embedded::get("index.html").map(|f| String::from_utf8_lossy(&f.data).to_string()).unwrap_or_default(),
        };
        let hashes: String = inline_script_hashes(&index).iter().map(|h| format!(" {h}")).collect();
        let csp = format!(
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'{hashes}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
             font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; \
             manifest-src 'self'; worker-src 'self'"
        )
        .replace("  ", " ");
        WebAssets { dir, csp }
    }

    fn get(&self, path: &str) -> Option<Cow<'static, [u8]>> {
        match &self.dir {
            Some(d) => {
                // Keine Pfad-Tricks: nur einfache Segmente
                if path.split('/').any(|s| s == ".." || s.starts_with('.') && !s.is_empty() || s.contains('\\')) {
                    return None;
                }
                let p = d.join(path);
                if p.is_file() { std::fs::read(p).ok().map(Cow::Owned) } else { None }
            }
            None => Embedded::get(path).map(|f| f.data),
        }
    }
}

/// trunk haengt einen 16-stelligen Hash an (`app-0123456789abcdef.js`): darf lange gecacht werden.
fn is_hashed(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or("");
    let stem = name.split('.').next().unwrap_or("");
    let stem = stem.strip_suffix("_bg").unwrap_or(stem);
    stem.rsplit('-').next().map(|h| h.len() == 16 && h.chars().all(|c| c.is_ascii_hexdigit())).unwrap_or(false)
}

fn is_api(path: &str) -> bool {
    path.starts_with("/api/") || path == "/api" || path.starts_with("/identity/") || path == "/alive"
}

pub async fn static_handler(State(st): State<St>, method: Method, uri: Uri) -> Response {
    let path = uri.path();
    if is_api(path) || path.starts_with("/downloads/") {
        return crate::error::ApiError::not_found().into_response();
    }
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let rel = path.trim_start_matches('/');
    let (data, rel, index) = match (!rel.is_empty()).then(|| st.web.get(rel)).flatten() {
        Some(d) => (d, rel, rel == "index.html"),
        None => {
            // SPA: unbekannte Pfade ohne Dateiendung liefern index.html
            let last = rel.rsplit('/').next().unwrap_or("");
            if !rel.is_empty() && last.contains('.') {
                return StatusCode::NOT_FOUND.into_response();
            }
            match st.web.get("index.html") {
                Some(d) => (d, "index.html", true),
                None => return StatusCode::NOT_FOUND.into_response(),
            }
        }
    };
    let mime = mime_guess::from_path(rel).first_or_octet_stream();
    let cache = if index || rel.ends_with("sw.js") || rel.ends_with(".webmanifest") {
        "no-store"
    } else if is_hashed(rel) {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=86400"
    };
    let mut r = Response::new(Body::from(data.into_owned()));
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_str(mime.as_ref()).unwrap_or(HeaderValue::from_static("application/octet-stream")));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    r
}

/// Sicherheits-Header fuer jede Antwort.
pub async fn security_headers(State(st): State<St>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let https = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(false);
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    let set = |h: &mut axum::http::HeaderMap, k: &'static str, v: &str| {
        if let Ok(v) = HeaderValue::from_str(v) {
            h.insert(k, v);
        }
    };
    set(h, "content-security-policy", &st.web.csp);
    set(h, "x-content-type-options", "nosniff");
    set(h, "x-frame-options", "DENY");
    set(h, "referrer-policy", "no-referrer");
    set(h, "permissions-policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()");
    set(h, "cross-origin-opener-policy", "same-origin");
    set(h, "x-robots-tag", "noindex, nofollow");
    if https {
        set(h, "strict-transport-security", "max-age=63072000; includeSubDomains");
    }
    if is_api(&path) {
        set(h, "cache-control", "no-store");
        set(h, "pragma", "no-cache");
    } else {
        set(h, "cross-origin-resource-policy", "same-origin");
    }
    r
}

/// CORS nur fuer die Browser-Erweiterung und die macOS-App (Tauri). Ohne Cookies: die Anmeldung
/// laeuft ueber Bearer-Tokens, die eine fremde Seite nicht kennt.
pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _| {
            let o = origin.to_str().unwrap_or("");
            o.starts_with("chrome-extension://")
                || o.starts_with("moz-extension://")
                || o.starts_with("safari-web-extension://")
                || o == "tauri://localhost"
                || o == "http://tauri.localhost"
                || o == "https://tauri.localhost"
        }))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::HeaderName::from_static("device-type"),
            header::HeaderName::from_static("bitwarden-client-name"),
            header::HeaderName::from_static("bitwarden-client-version"),
            header::HeaderName::from_static("auth-email"),
        ])
        .max_age(std::time::Duration::from_secs(3600))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hashes_and_cache() {
        let h = inline_script_hashes("<script src=\"/a.js\"></script><script type=\"module\">init()</script>");
        assert_eq!(h.len(), 1);
        assert!(is_hashed("nrzpass-web-0123456789abcdef_bg.wasm"));
        assert!(is_hashed("nrzpass-web-0123456789abcdef.js"));
        assert!(!is_hashed("index.html"));
    }
}
