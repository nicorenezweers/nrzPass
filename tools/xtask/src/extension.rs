//! Browser-Erweiterung (Chrome/Edge/Brave/Arc und Firefox):
//!   dist/extension/chrome/  dist/extension/firefox/          entpackt
//!   dist/extension/nrzPass-{chrome,firefox}-<version>.zip    zum Verteilen
//! Popup = Web-Tresor (dist/web); Hintergrund und Inhaltsskript = crates/extension (Rust/WASM).
//! Braucht: Ziel wasm32-unknown-unknown, trunk (bringt wasm-bindgen/wasm-opt mit), zip.

use crate::util::{copy_dir, newest_tool, run, step, version, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Hintergrund-Dienst: nur ein Lader, die Logik steckt in Rust (bg/nrzpass_bg_bg.wasm).
/// Die Listener muessen synchron registriert werden, damit ein geweckter Service Worker keine
/// Nachricht verpasst; sie warten auf das WASM und geben dann an Rust weiter.
const BACKGROUND_JS: &str = r#"import init, * as nrz from './bg/nrzpass_bg.js';

const api = globalThis.browser ?? globalThis.chrome;
const ready = init({ module_or_path: api.runtime.getURL('bg/nrzpass_bg_bg.wasm') }).then(() => nrz.bg_init());

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  ready.then(() => nrz.bg_message(msg, sender)).then(sendResponse, (e) => sendResponse({ error: String(e) }));
  return true;
});
api.alarms.onAlarm.addListener((alarm) => { ready.then(() => nrz.bg_alarm(alarm.name)); });
api.tabs.onActivated.addListener((info) => { ready.then(() => nrz.bg_tab(info.tabId)); });
api.tabs.onUpdated.addListener((id, info) => { if (info.status === 'complete') ready.then(() => nrz.bg_tab(id)); });
"#;

/// Inhaltsskript: nur ein Lader; Formularerkennung, Vorschlaege und Ausfuellen sind Rust.
/// Fehler (Erweiterung neu geladen, Seite ohne Zugriff) beenden still.
const CONTENT_JS: &str = r#"(async () => {
  const api = globalThis.browser ?? globalThis.chrome;
  try {
    const m = await import(api.runtime.getURL('content/nrzpass_content.js'));
    await m.default({ module_or_path: api.runtime.getURL('content/nrzpass_content_bg.wasm') });
    m.start();
  } catch (_) {}
})();
"#;

const WASM_FEATURES: &[&str] = &[
    "--enable-bulk-memory", "--enable-bulk-memory-opt", "--enable-nontrapping-float-to-int", "--enable-sign-ext",
    "--enable-mutable-globals", "--enable-reference-types", "--enable-multivalue",
];

fn trunk_tool(var: &str, prefix: &str, rel: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(var) {
        return Some(PathBuf::from(p));
    }
    let cache = std::env::var("TRUNK_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join("Library/Caches/dev.trunkrs.trunk"));
    newest_tool(&cache, prefix, rel)
}

pub fn build(skip_web: bool) -> Result<()> {
    let version = version()?;
    let wbg = trunk_tool("WASM_BINDGEN", "wasm-bindgen-", "wasm-bindgen")
        .filter(|p| p.is_file())
        .ok_or("wasm-bindgen nicht gefunden (WASM_BINDGEN setzen oder einmal 'cargo xtask web' ausfuehren)")?;
    let wopt = trunk_tool("WASM_OPT", "wasm-opt-", "bin/wasm-opt").filter(|p| p.is_file());

    let out = Path::new("dist/extension");
    let work = out.join(".work");
    let _ = fs::remove_dir_all(out);
    fs::create_dir_all(&work)?;

    if !skip_web {
        crate::web::build()?;
    }
    if !Path::new("dist/web/index.html").exists() {
        return Err("dist/web fehlt - erst 'cargo xtask web'".into());
    }

    let wasm = "target/wasm32-unknown-unknown/wasm-release/nrzpass_extension.wasm";
    for part in ["content", "background"] {
        step(&format!("Rust/WASM: {part}"));
        run(Command::new("cargo")
            .args(["build", "-q", "-p", "nrzpass-extension", "--lib", "--target", "wasm32-unknown-unknown", "--profile", "wasm-release", "--features", part])
            .env("CARGO_PROFILE_WASM_RELEASE_STRIP", "false"))?;
        let name = if part == "background" { "nrzpass_bg" } else { "nrzpass_content" };
        let dir = work.join(part);
        run(Command::new(&wbg).args(["--target", "web", "--no-typescript", "--out-dir"]).arg(&dir).args(["--out-name", name, wasm]))?;
        if let Some(wopt) = &wopt {
            let file = dir.join(format!("{name}_bg.wasm"));
            let level = if part == "content" { "-Oz" } else { "-O3" };
            run(Command::new(wopt).args(WASM_FEATURES).args([level, "--strip-debug", "--strip-producers"]).arg(&file).arg("-o").arg(&file))?;
        }
    }

    step("Chrome und Firefox zusammenstellen");
    for target in ["chrome", "firefox"] {
        assemble(out, &work, target, &version)?;
    }
    fs::remove_dir_all(&work)?;
    println!("Fertig: {0}/nrzPass-chrome-{version}.zip und {0}/nrzPass-firefox-{version}.zip", out.display());
    Ok(())
}

/// Trunk-Ausgabe -> popup.html; das Inline-Skript muss in eine Datei (MV3 verbietet Inline-Skripte),
/// der Manifest-Link (PWA) ist in der Erweiterung sinnlos.
fn popup(index: &str) -> Result<(String, String)> {
    const OPEN: &str = "<script type=\"module\">";
    let start = index.find(OPEN).ok_or("Inline-Skript in dist/web/index.html nicht gefunden")?;
    let len = index[start..].find("</script>").ok_or("</script> fehlt in dist/web/index.html")?;
    let script = index[start + OPEN.len()..start + len].trim().to_string() + "\n";
    let mut html = format!("{}<script type=\"module\" src=\"/popup-boot.js\"></script>{}", &index[..start], &index[start + len + "</script>".len()..]);
    if let Some(m) = html.find("<link rel=\"manifest\"") {
        let end = m + html[m..].find('>').ok_or("Manifest-Link kaputt")? + 1;
        let begin = html[..m].trim_end_matches([' ', '\t', '\n', '\r']).len();
        html.replace_range(begin..end, "");
    }
    Ok((html, script))
}

fn assemble(out: &Path, work: &Path, target: &str, version: &str) -> Result<()> {
    let dst = out.join(target);
    copy_dir(Path::new("dist/web"), &dst, &[".trunk-lock", "index.html", ".stage", "site.webmanifest"])?;
    let (html, boot) = popup(&fs::read_to_string("dist/web/index.html")?)?;
    fs::write(dst.join("popup.html"), html)?;
    fs::write(dst.join("popup-boot.js"), boot)?;
    fs::write(dst.join("background.js"), BACKGROUND_JS)?;
    fs::write(dst.join("content.js"), CONTENT_JS)?;
    copy_dir(Path::new("extension/icons"), &dst.join("icons"), &[])?;
    copy_dir(&work.join("content"), &dst.join("content"), &[])?;
    copy_dir(&work.join("background"), &dst.join("bg"), &[])?;

    let tpl = fs::read_to_string("extension/manifest.template.json")?.replace("@VERSION@", version);
    let mut m: Value = serde_json::from_str(&tpl)?;
    if target == "firefox" {
        m["background"] = json!({ "scripts": ["background.js"], "type": "module" });
        m["browser_specific_settings"] = json!({ "gecko": { "id": "nrzpass@nrz.local", "strict_min_version": "128.0" } });
    } else {
        m["background"] = json!({ "service_worker": "background.js", "type": "module" });
        m["minimum_chrome_version"] = json!("116");
    }
    fs::write(dst.join("manifest.json"), serde_json::to_string_pretty(&m)? + "\n")?;

    let zip = format!("../nrzPass-{target}-{version}.zip");
    let _ = fs::remove_file(dst.join(&zip));
    run(Command::new("zip").args(["-qr", "-X", &zip, "."]).current_dir(&dst))
}

#[cfg(test)]
mod tests {
    #[test]
    fn popup_moves_inline_script() {
        let index = "<head>\n  <link rel=\"manifest\" href=\"/site.webmanifest\">\n<script type=\"module\">\nimport x from '/a.js';\n</script></head>";
        let (html, js) = super::popup(index).unwrap();
        assert_eq!(js, "import x from '/a.js';\n");
        assert_eq!(html, "<head>\n<script type=\"module\" src=\"/popup-boot.js\"></script></head>");
    }
}
