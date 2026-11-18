//! Server (Linux), macOS-App und das Umbrel-Paket.

use crate::util::{flag, newest, output, run, sha256sums, step, version, Result};
use serde_json::json;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;

/// nrzPass-Server fuer Linux (umbrel): amd64 und arm64, quer-kompiliert mit cargo-zigbuild
/// (glibc 2.31, laeuft auf debian:trixie-slim und aelter) -> dist/server/nrzpass-<arch>.gz + SHA256SUMS.
/// Die Web-Oberflaeche (dist/web) wird eingebettet.
pub fn server() -> Result<()> {
    let out = Path::new("dist/server");
    let _ = fs::remove_dir_all(out);
    fs::create_dir_all(out)?;
    if !Path::new("dist/web/index.html").exists() {
        eprintln!("Hinweis: dist/web fehlt - es wird nur eine Platzhalterseite eingebettet.");
    }
    for (arch, target) in [("amd64", "x86_64-unknown-linux-gnu"), ("arm64", "aarch64-unknown-linux-gnu")] {
        step(&format!("nrzpass linux/{arch} ({target})"));
        let _ = output(Command::new("rustup").args(["target", "add", target]));
        run(Command::new("cargo").args(["zigbuild", "--release", "-p", "nrzpass-server", "--target", &format!("{target}.2.31")]))?;
        let gz = File::create(out.join(format!("nrzpass-{arch}.gz")))?;
        run(Command::new("gzip").args(["-9", "-c", &format!("target/{target}/release/nrzpass")]).stdout(gz))?;
    }
    println!("{}", sha256sums(out, &["nrzpass-amd64.gz", "nrzpass-arm64.gz"])?);
    Ok(())
}

/// macOS-App (Tauri) als Universal-DMG -> dist/mac/nrzPass-<version>-macOS.dmg + signiertes Update-Paket.
/// Nicht notarisiert: beim ersten Start Rechtsklick -> Oeffnen.
pub fn mac() -> Result<()> {
    let version = version()?;
    let built = fs::read_to_string("dist/web/index.html").is_ok_and(|s| s.contains("wasm"));
    if !built {
        crate::web::build()?;
    }
    for t in ["aarch64-apple-darwin", "x86_64-apple-darwin"] {
        let _ = output(Command::new("rustup").args(["target", "add", t]));
    }
    // Update-Pakete signieren (minisign). Der private Schluessel liegt nie im Repo:
    // ~/.tauri/nrzpass.key (oder TAURI_SIGNING_PRIVATE_KEY setzen). Oeffentlicher Schluessel: tauri.conf.json.
    let mut cmd = Command::new("cargo");
    cmd.args(["tauri", "build", "--target", "universal-apple-darwin", "--bundles", "app,dmg"]).current_dir("crates/desktop");
    if std::env::var("TAURI_SIGNING_PRIVATE_KEY").map_or(true, |k| k.is_empty()) {
        let key = std::env::var("NRZPASS_SIGNING_KEY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".tauri/nrzpass.key"));
        let secret = fs::read_to_string(&key)
            .map_err(|_| format!("Signierschluessel fehlt ({}) - ohne ihn gibt es keine Updates fuer die macOS-App.", key.display()))?;
        cmd.env("TAURI_SIGNING_PRIVATE_KEY", secret.trim_end());
        cmd.env("TAURI_SIGNING_PRIVATE_KEY_PASSWORD", std::env::var("TAURI_SIGNING_PRIVATE_KEY_PASSWORD").unwrap_or_default());
    }
    run(&mut cmd)?;

    let out = Path::new("dist/mac");
    fs::create_dir_all(out)?;
    let bundle = Path::new("target/universal-apple-darwin/release/bundle");
    let dmg = newest(&bundle.join("dmg"), "", ".dmg").ok_or("kein DMG gebaut")?;
    let name = format!("nrzPass-{version}-macOS.dmg");
    fs::copy(dmg, out.join(&name))?;
    for f in ["nrzPass.app.tar.gz", "nrzPass.app.tar.gz.sig"] {
        fs::copy(bundle.join("macos").join(f), out.join(f))?;
    }
    println!("dist/mac/{name} (+ signiertes Update-Paket)");
    Ok(())
}

/// Entfernt den temporaeren Worktree auch bei Fehlern.
struct Worktree(PathBuf);

impl Drop for Worktree {
    fn drop(&mut self) {
        let _ = output(Command::new("git").args(["worktree", "remove", "--force"]).arg(&self.0));
    }
}

/// Umbrel-Paket ohne Registry und ohne Login: baut alles und legt es als Commit auf den Zweig
/// `umbrel` mit dem Tag `umbrel-<version>`. `hooks/pre-start` der App `nrz-pass` im nrzStore laedt
/// die Dateien auf dem Geraet von nrzGit; mit dem Tag aktualisiert nrzGit den Store selbst
/// (nrzStore.json, tagPrefix "umbrel-"). Gepusht wird auf $REMOTE (Standard: origin = nrzGit).
pub fn umbrel(version: &str, notes: &str) -> Result<()> {
    let remote = std::env::var("REMOTE").unwrap_or_else(|_| "origin".into());
    let tag = format!("umbrel-{version}");
    let cargo_version = crate::util::version()?;
    if cargo_version != version {
        return Err(format!("Version {version} passt nicht zu Cargo.toml ({cargo_version}) - erst dort und in crates/desktop/tauri.conf.json anheben.").into());
    }
    if Command::new("git").args(["rev-parse", "-q", "--verify", &format!("refs/tags/{tag}")]).output()?.status.success() {
        return Err(format!("Tag {tag} gibt es schon - neue Version waehlen.").into());
    }

    crate::web::build()?;
    server()?;
    if !flag("SKIP_MAC") {
        mac()?;
    }
    if !flag("SKIP_EXTENSION") {
        crate::extension::build(true)?;
    }

    let out = PathBuf::from(format!("dist/umbrel/{version}"));
    let _ = fs::remove_dir_all(&out);
    fs::create_dir_all(out.join("downloads"))?;
    fs::create_dir_all(out.join("updates"))?;
    for arch in ["amd64", "arm64"] {
        let f = format!("nrzpass-{arch}.gz");
        fs::copy(Path::new("dist/server").join(&f), out.join(&f))?;
    }
    let downloads = [
        ("dist/mac", "", "-macOS.dmg", "nrzPass-macOS.dmg"),
        ("dist/extension", "nrzPass-chrome-", ".zip", "nrzPass-chrome.zip"),
        ("dist/extension", "nrzPass-firefox-", ".zip", "nrzPass-firefox.zip"),
    ];
    for (dir, prefix, suffix, name) in downloads {
        if let Some(f) = newest(Path::new(dir), prefix, suffix) {
            fs::copy(f, out.join("downloads").join(name))?;
        }
    }

    let raw = format!("http://100.78.107.162:8390/nicorenezweers/nrzPass/raw/tag/{tag}");
    let date = output(Command::new("date").args(["-u", "+%Y-%m-%dT%H:%M:%SZ"]))?;
    if let Ok(sig) = fs::read_to_string("dist/mac/nrzPass.app.tar.gz.sig") {
        for f in ["nrzPass.app.tar.gz", "nrzPass.app.tar.gz.sig"] {
            fs::copy(Path::new("dist/mac").join(f), out.join("updates").join(f))?;
        }
        let p = json!({ "signature": sig.trim_end(), "url": format!("{raw}/updates/nrzPass.app.tar.gz") });
        let latest = json!({
            "version": version, "notes": notes, "pub_date": date,
            "platforms": { "darwin-aarch64": p, "darwin-x86_64": p, "darwin-universal": p },
        });
        fs::write(out.join("latest.json"), serde_json::to_string_pretty(&latest)? + "\n")?;
    }
    let update = json!({
        "version": version, "notes": notes, "date": date,
        "downloads": {
            "chrome": format!("{raw}/downloads/nrzPass-chrome.zip"),
            "firefox": format!("{raw}/downloads/nrzPass-firefox.zip"),
            "mac": format!("{raw}/downloads/nrzPass-macOS.dmg"),
        },
    });
    fs::write(out.join("update.json"), serde_json::to_string_pretty(&update)? + "\n")?;
    let sums = sha256sums(&out, &["nrzpass-amd64.gz", "nrzpass-arm64.gz", "downloads/*", "updates/*"])?;

    step(&format!("Zweig umbrel, Tag {tag}"));
    let dir = std::env::temp_dir().join(format!("nrzpass-umbrel-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let _ = output(Command::new("git").args(["fetch", "-q", &remote, "umbrel"]));
    let has_remote = Command::new("git").args(["rev-parse", "-q", "--verify", &format!("refs/remotes/{remote}/umbrel")]).output()?.status.success();
    let mut add = Command::new("git");
    add.args(["worktree", "add", "-q"]);
    if has_remote {
        add.args(["-B", "umbrel"]).arg(&dir).arg(format!("{remote}/umbrel"));
    } else {
        add.args(["--orphan", "-b", "umbrel"]).arg(&dir);
    }
    run(&mut add)?;
    let wt = Worktree(dir.clone());

    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
        if name.ends_with(".gz") || name.ends_with(".json") || name == "SHA256SUMS" {
            fs::remove_file(&path)?;
        } else if name == "downloads" || name == "updates" {
            fs::remove_dir_all(&path)?;
        }
    }
    crate::util::copy_dir(&out, &dir, &[])?;
    let head = output(Command::new("git").args(["rev-parse", "--short", "HEAD"]))?;
    fs::write(dir.join("README.md"), format!(
"# nrzPass – Umbrel-Paket

Dieser Zweig enthält nur fertige Dateien für die Umbrel-App `nrz-pass` (nrzStore). Der
Quellcode liegt auf `main`.

| Datei | Inhalt |
|---|---|
| `nrzpass-<arch>.gz` | Server mit eingebettetem Web-Tresor, amd64/arm64 (glibc) |
| `downloads/nrzPass-macOS.dmg` | macOS-App (Tauri, Universal) |
| `downloads/nrzPass-chrome.zip` | Browser-Erweiterung für Chrome, Edge, Brave, Arc |
| `downloads/nrzPass-firefox.zip` | Browser-Erweiterung für Firefox |
| `updates/nrzPass.app.tar.gz` (+ `.sig`) | signiertes Update-Paket der macOS-App |
| `latest.json` | Update-Info für die macOS-App (Tauri-Updater) |
| `update.json` | Update-Info für die Browser-Erweiterung |
| `SHA256SUMS` | Prüfsummen |

Stand: nrzPass {version}, gebaut aus `{head}` mit `cargo xtask umbrel {version}`.
"))?;

    let git_cfg = |key: &str, default: &str| output(Command::new("git").args(["config", key])).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.into());
    let (name, email) = (git_cfg("user.name", "nrz"), git_cfg("user.email", "nrz@localhost"));
    run(Command::new("git").arg("-C").arg(&dir).args(["add", "-A"]))?;
    run(Command::new("git").arg("-C").arg(&dir)
        .args(["-c", &format!("user.name={name}"), "-c", &format!("user.email={email}"), "commit", "-q", "-m", &format!("Umbrel-Paket nrzPass {version}")]))?;
    run(Command::new("git").arg("-C").arg(&dir).args(["tag", "-a", &tag, "-m", notes]))?;
    run(Command::new("git").args(["push", "-q", &remote, "umbrel", &format!("refs/tags/{tag}")]))?;
    drop(wt);
    println!("Fertig: {tag} auf {remote} (Zweig umbrel).\n{sums}");
    Ok(())
}
