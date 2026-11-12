#!/bin/sh
# macOS-App (Tauri) als Universal-DMG (Apple Silicon + Intel):
#   scripts/build-mac.sh  ->  dist/mac/nrzPass-<version>-macOS.dmg
# Die App ist nicht notarisiert: beim ersten Start Rechtsklick -> Oeffnen.
set -eu
cd "$(dirname "$0")/.."
version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
[ -f dist/web/index.html ] && grep -q wasm dist/web/index.html || scripts/build-web.sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null 2>&1 || true
(cd crates/desktop && cargo tauri build --target universal-apple-darwin --bundles dmg)
mkdir -p dist/mac
dmg="$(ls -t target/universal-apple-darwin/release/bundle/dmg/*.dmg | head -1)"
cp "$dmg" "dist/mac/nrzPass-$version-macOS.dmg"
echo "dist/mac/nrzPass-$version-macOS.dmg"
