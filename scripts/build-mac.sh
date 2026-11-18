#!/bin/sh
# macOS-App (Tauri) als Universal-DMG (Apple Silicon + Intel):
#   scripts/build-mac.sh  ->  dist/mac/nrzPass-<version>-macOS.dmg
# Die App ist nicht notarisiert: beim ersten Start Rechtsklick -> Oeffnen.
set -eu
cd "$(dirname "$0")/.."
version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
[ -f dist/web/index.html ] && grep -q wasm dist/web/index.html || scripts/build-web.sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null 2>&1 || true
# Update-Pakete signieren (minisign). Der private Schluessel liegt nie im Repo:
# ~/.tauri/nrzpass.key (oder TAURI_SIGNING_PRIVATE_KEY setzen). Oeffentlicher Schluessel: tauri.conf.json.
key="${NRZPASS_SIGNING_KEY:-$HOME/.tauri/nrzpass.key}"
if [ -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ] && [ -f "$key" ]; then
  TAURI_SIGNING_PRIVATE_KEY="$(cat "$key")"
  export TAURI_SIGNING_PRIVATE_KEY
  export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}"
fi
if [ -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ]; then
  echo "Signierschluessel fehlt ($key) - ohne ihn gibt es keine Updates fuer die macOS-App." >&2
  exit 1
fi
(cd crates/desktop && cargo tauri build --target universal-apple-darwin --bundles app,dmg)
mkdir -p dist/mac
bundle=target/universal-apple-darwin/release/bundle
dmg="$(ls -t $bundle/dmg/*.dmg | head -1)"
cp "$dmg" "dist/mac/nrzPass-$version-macOS.dmg"
cp "$bundle/macos/nrzPass.app.tar.gz" "dist/mac/nrzPass.app.tar.gz"
cp "$bundle/macos/nrzPass.app.tar.gz.sig" "dist/mac/nrzPass.app.tar.gz.sig"
echo "dist/mac/nrzPass-$version-macOS.dmg (+ signiertes Update-Paket)"
