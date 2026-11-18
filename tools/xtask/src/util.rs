//! Kleine Helfer: Befehle ausfuehren, Dateien kopieren, Version lesen.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Wurzel des Repos (tools/xtask/../..).
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("Repo-Wurzel")
}

pub fn flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v == "1")
}

pub fn step(msg: &str) {
    println!("==> {msg}");
}

/// Befehl ausfuehren, Fehler bei Exit-Code != 0.
pub fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd.status().map_err(|e| format!("{}: {e}", describe(cmd)))?;
    if !status.success() {
        return Err(format!("{} fehlgeschlagen ({status})", describe(cmd)).into());
    }
    Ok(())
}

/// Befehl ausfuehren und stdout (ohne Zeilenende) zurueckgeben.
pub fn output(cmd: &mut Command) -> Result<String> {
    let out = cmd.output().map_err(|e| format!("{}: {e}", describe(cmd)))?;
    if !out.status.success() {
        return Err(format!("{} fehlgeschlagen: {}", describe(cmd), String::from_utf8_lossy(&out.stderr).trim()).into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

fn describe(cmd: &Command) -> String {
    let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    format!("{} {}", cmd.get_program().to_string_lossy(), args.join(" "))
}

/// Version aus [workspace.package] in Cargo.toml.
pub fn version() -> Result<String> {
    let toml = fs::read_to_string("Cargo.toml")?;
    toml.lines()
        .find_map(|l| l.strip_prefix("version = \"").and_then(|r| r.strip_suffix('"')))
        .map(str::to_string)
        .ok_or_else(|| "version in Cargo.toml nicht gefunden".into())
}

pub fn copy_dir(src: &Path, dst: &Path, skip: &[&str]) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if skip.iter().any(|s| name == *s) {
            continue;
        }
        let to = dst.join(&name);
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &to, &[])?;
        } else {
            fs::copy(entry.path(), to)?;
        }
    }
    Ok(())
}

/// Dateien eines Ordners mit Endung `ext`, neueste zuerst.
pub fn newest(dir: &Path, prefix: &str, suffix: &str) -> Option<PathBuf> {
    let mut files: Vec<_> = fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with(prefix) && n.ends_with(suffix)
        })
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    files.sort();
    files.pop().map(|(_, p)| p)
}

/// Hoechste Version eines Werkzeugs im Trunk-Cache (`<dir>/<prefix>-<x.y.z>/<rel>`).
pub fn newest_tool(dir: &Path, prefix: &str, rel: &str) -> Option<PathBuf> {
    let key = |name: &str| -> Vec<u64> { name.split(|c: char| !c.is_ascii_digit()).filter_map(|p| p.parse().ok()).collect() };
    fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let path = e.path().join(rel);
            (name.starts_with(prefix) && path.is_file()).then(|| (key(&name[prefix.len()..]), path))
        })
        .max()
        .map(|(_, p)| p)
}

/// `shasum -a 256` im Ordner `dir` ueber `files` (Muster erlaubt) -> SHA256SUMS.
pub fn sha256sums(dir: &Path, files: &[&str]) -> Result<String> {
    let sums = output(Command::new("sh").current_dir(dir).arg("-c").arg(format!("shasum -a 256 {}", files.join(" "))))?;
    fs::write(dir.join("SHA256SUMS"), format!("{sums}\n"))?;
    Ok(sums)
}
