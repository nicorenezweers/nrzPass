#!/bin/sh
# Web-Tresor (Leptos/WASM) bauen: Tailwind-CSS, dann trunk -> dist/web
# (wird vom Server eingebettet, von der macOS-App gebuendelt und ist das Erweiterungs-Popup).
set -eu
cd "$(dirname "$0")/.."
[ -d node_modules ] || npm install --silent
npm run css --silent
(cd crates/web && trunk build --release)
echo "dist/web fertig"
