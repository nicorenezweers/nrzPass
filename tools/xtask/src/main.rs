//! nrzPass Build-Werkzeug. Aufruf aus dem Repo:
//!
//! ```text
//! cargo xtask css                      Tailwind -> crates/web/assets/app.css
//! cargo xtask web                      Web-Tresor (Leptos/WASM) -> dist/web
//! cargo xtask serve                    Web-Tresor mit trunk serve (Port 8491) und Tailwind --watch
//! cargo xtask server                   Linux-Server amd64 + arm64 -> dist/server
//! cargo xtask mac                      macOS-App (Universal-DMG + signiertes Update) -> dist/mac
//! cargo xtask extension                Chrome + Firefox -> dist/extension
//! cargo xtask umbrel <version> [notiz] alles bauen, Zweig `umbrel` + Tag `umbrel-<version>` pushen
//! ```
//!
//! Umgebung: `SKIP_WEB=1` (extension), `SKIP_MAC=1`, `SKIP_EXTENSION=1`, `REMOTE`, `NOTES` (umbrel),
//! `TRUNK_CACHE`, `WASM_BINDGEN`, `WASM_OPT`, `NRZPASS_SIGNING_KEY`, `TAURI_SIGNING_PRIVATE_KEY`.

mod extension;
mod release;
mod util;
mod web;

use util::Result;

const USAGE: &str = "Aufruf: cargo xtask <css|web|serve|server|mac|extension|umbrel <version> [notiz]>";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = std::env::set_current_dir(util::root()).map_err(Into::into).and_then(|()| dispatch(&args)) {
        eprintln!("Fehler: {e}");
        std::process::exit(1);
    }
}

fn dispatch(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("css") => web::css(),
        Some("web") => web::build(),
        Some("serve") => web::serve(),
        Some("server") => release::server(),
        Some("mac") => release::mac(),
        Some("extension") => extension::build(util::flag("SKIP_WEB")),
        Some("umbrel") => {
            let version = args.get(1).ok_or(USAGE)?;
            let notes = args.get(2).cloned().or_else(|| std::env::var("NOTES").ok()).unwrap_or_else(|| format!("nrzPass {version}"));
            release::umbrel(version, &notes)
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}
