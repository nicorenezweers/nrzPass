//! Web-Tresor: Tailwind-Eingabe und Trunk-Einstieg werden hier erzeugt, dann `trunk build`.

use crate::util::{run, step, Result};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

const CSS_IN: &str = "target/xtask/tailwind.css";
const CSS_OUT: &str = "crates/web/assets/app.css";
const INDEX: &str = "crates/web/index.html";

/// Trunk-Einstieg; Trunk ersetzt die data-trunk-Links durch die gehashten Dateien.
const INDEX_HTML: &str = r##"<!doctype html>
<html lang="de" class="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="theme-color" content="#141414">
  <meta name="color-scheme" content="dark">
  <meta name="referrer" content="no-referrer">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="nrzPass">
  <title>nrzPass</title>
  <link rel="icon" href="/assets/brand/icon-32.png" type="image/png" sizes="32x32">
  <link rel="apple-touch-icon" href="/assets/brand/apple-touch-icon.png" sizes="180x180">
  <link rel="manifest" href="/site.webmanifest">
  <link data-trunk rel="copy-dir" href="assets/fonts" data-target-path="assets/fonts">
  <link data-trunk rel="copy-dir" href="assets/brand" data-target-path="assets/brand">
  <link data-trunk rel="copy-file" href="assets/site.webmanifest">
  <link data-trunk rel="css" href="assets/app.css">
  <link data-trunk rel="rust" data-wasm-opt="3" data-wasm-opt-params="--enable-bulk-memory --enable-bulk-memory-opt --enable-nontrapping-float-to-int --enable-sign-ext --enable-mutable-globals --enable-reference-types --enable-multivalue" data-bin="nrzpass-web" data-cargo-profile="wasm-release" data-integrity="none" />
</head>
<body class="bg-background text-foreground font-sans antialiased"></body>
</html>
"##;

/// Tailwind-Eingabe (nrzTheme). Pfade relativ zu target/xtask/.
const TAILWIND: &str = r#"@import "tailwindcss";

/* Klassen stehen in den Rust-Komponenten (Web-Tresor und Erweiterung) */
@source "../../crates/web/src";
@source "../../crates/extension/src";

@font-face {
  font-family: "Geist Mono";
  src: url("/assets/fonts/GeistMono-Variable.woff2") format("woff2");
  font-weight: 100 900;
  font-style: normal;
  font-display: swap;
}

@font-face {
  font-family: "Geist";
  src: url("/assets/fonts/Geist-Variable.woff2") format("woff2");
  font-weight: 100 900;
  font-style: normal;
  font-display: swap;
}

/* nrzTheme: Rust/UI-Farben (dunkel), wie nrzWebsite und nrzMail */
:root {
  --background: #141414;
  --foreground: #f5f5f5;
  --sidebar: #181818;
  --card: #1a1a1a;
  --card-foreground: #f5f5f5;
  --popover: #1c1c1c;
  --primary: #f5f5f5;
  --primary-foreground: #141414;
  --secondary: #262626;
  --secondary-foreground: #f5f5f5;
  --muted: #262626;
  --muted-foreground: #a1a1a1;
  --accent: #262626;
  --accent-foreground: #f5f5f5;
  --destructive: oklch(0.577 0.22 27);
  --success: oklch(0.72 0.17 150);
  --warning: oklch(0.8 0.15 80);
  --border: #262626;
  --input: #303030;
  --ring: #5a5a5a;
  color-scheme: dark;
}

@theme inline {
  --font-mono: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  --font-sans: "Geist", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  --color-background: var(--background);
  --color-sidebar: var(--sidebar);
  --color-foreground: var(--foreground);
  --color-card: var(--card);
  --color-card-foreground: var(--card-foreground);
  --color-popover: var(--popover);
  --color-primary: var(--primary);
  --color-primary-foreground: var(--primary-foreground);
  --color-secondary: var(--secondary);
  --color-secondary-foreground: var(--secondary-foreground);
  --color-muted: var(--muted);
  --color-muted-foreground: var(--muted-foreground);
  --color-accent: var(--accent);
  --color-accent-foreground: var(--accent-foreground);
  --color-destructive: var(--destructive);
  --color-success: var(--success);
  --color-warning: var(--warning);
  --color-border: var(--border);
  --color-input: var(--input);
  --color-ring: var(--ring);
}

html, body { height: 100%; }
body { overscroll-behavior: none; -webkit-tap-highlight-color: transparent; }
::selection { background: rgb(255 255 255 / 0.15); color: #fff; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-thumb { background: #2e2e2e; border-radius: 10px; border: 3px solid transparent; background-clip: content-box; }

/* iPhone: Notch und Home-Indikator */
.safe-top { padding-top: env(safe-area-inset-top); }
.safe-bottom { padding-bottom: env(safe-area-inset-bottom); }
.pb-nav { padding-bottom: calc(4.5rem + env(safe-area-inset-bottom)); }
@media (min-width: 768px) { .pb-nav { padding-bottom: 0; } }

/* Hintergrund wie nrzWebsite: weiche, graue Lichtflecken */
.drift { pointer-events: none; }
.drift span { position: absolute; display: block; border-radius: 50%; filter: blur(70px); will-change: transform; }
.drift-a { width: 44vmax; height: 44vmax; left: -10vmax; top: -12vmax; background: radial-gradient(circle, rgb(255 255 255 / .06), transparent 65%); animation: drift-a 32s ease-in-out infinite; }
.drift-b { width: 38vmax; height: 38vmax; right: -12vmax; top: 18vh; background: radial-gradient(circle, rgb(210 220 235 / .05), transparent 65%); animation: drift-b 40s ease-in-out infinite; }
@keyframes drift-a { 0%, 100% { transform: translate3d(0,0,0) scale(1); } 50% { transform: translate3d(40vw, 30vh, 0) scale(1.1); } }
@keyframes drift-b { 0%, 100% { transform: translate3d(0,0,0) scale(1); } 50% { transform: translate3d(-40vw, 10vh, 0) scale(.95); } }
@media (prefers-reduced-motion: reduce) { .drift-a, .drift-b { animation-duration: 160s; } }

.toast { animation: toast-in .2s ease-out; }
@keyframes toast-in { from { opacity: 0; transform: translateY(8px); } }
.fade-in { animation: fade-in .15s ease-out; }
@keyframes fade-in { from { opacity: 0; } }
.sheet-in { animation: sheet-in .2s ease-out; }
@keyframes sheet-in { from { opacity: 0; transform: translateY(16px); } }

/* TOTP-Ring */
.ring-track { stroke: #303030; }
.ring-value { stroke: var(--foreground); transition: stroke-dashoffset 1s linear; }

/* Passwort-Anzeige: Ziffern und Sonderzeichen hervorheben */
.pw-digit { color: oklch(0.75 0.12 240); }
.pw-symbol { color: oklch(0.78 0.13 50); }

/* Erweiterungs-Popup: Wunschgroesse 400x600 (Chrome erlaubt max. 800x600), Inhalt scrollt innen.
   Ist das Fenster kleiner (Zoom, kleiner Bildschirm, Firefox-Ueberlaufmenue), setzt main.rs
   --popup-w/--popup-h auf die echte Groesse, damit Kopf- und Navigationsleiste sichtbar bleiben. */
html:has(body.popup) { overflow: hidden; }
body.popup { width: var(--popup-w, 400px); height: var(--popup-h, 600px); min-width: 240px; overflow: hidden; }
body.popup .pb-nav { padding-bottom: 0; }
/* Im Popup gelten die kompakten Desktop-Groessen (die md:-Klassen greifen bei 400px nicht) */
body.popup [data-name="Input"], body.popup [data-name="Select"], body.popup #vault-search { height: 2.25rem; font-size: 0.875rem; }
body.popup [data-name="Textarea"] { font-size: 0.875rem; }
body.popup button.size-10 { width: 2.25rem; height: 2.25rem; }
body.popup ::-webkit-scrollbar { width: 6px; }
body.popup ::-webkit-scrollbar-thumb { border-width: 1px; }
"#;

fn tailwind() -> Result<Command> {
    if !Path::new("node_modules/.bin/tailwindcss").exists() {
        run(Command::new("npm").args(["install", "--silent"]))?;
    }
    fs::create_dir_all("target/xtask")?;
    fs::write(CSS_IN, TAILWIND)?;
    let mut cmd = Command::new("node_modules/.bin/tailwindcss");
    cmd.args(["-i", CSS_IN, "-o", CSS_OUT]);
    Ok(cmd)
}

/// Erzeugt die Trunk-Eingaben (index.html, app.css).
fn prepare() -> Result<()> {
    fs::write(INDEX, INDEX_HTML)?;
    css()
}

pub fn css() -> Result<()> {
    run(tailwind()?.arg("--minify"))
}

pub fn build() -> Result<()> {
    step("Web-Tresor");
    prepare()?;
    run(Command::new("trunk").args(["build", "--release"]).current_dir("crates/web"))?;
    println!("dist/web fertig");
    Ok(())
}

pub fn serve() -> Result<()> {
    prepare()?;
    let mut watch = tailwind()?.arg("--watch").stdin(Stdio::null()).spawn()?;
    let r = run(Command::new("trunk").arg("serve").current_dir("crates/web"));
    let _ = watch.kill();
    r
}
