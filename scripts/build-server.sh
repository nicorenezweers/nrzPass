#!/bin/sh
# nrzPass-Server fuer Linux (umbrel): amd64 und arm64, quer-kompiliert mit cargo-zigbuild
# (glibc 2.31, laeuft auf debian:trixie-slim und aelter). Ergebnis:
#   dist/server/nrzpass-amd64.gz  dist/server/nrzpass-arm64.gz  dist/server/SHA256SUMS
# Die Web-Oberflaeche (dist/web) wird eingebettet – vorher scripts/build-web.sh ausfuehren.
set -eu
cd "$(dirname "$0")/.."

out="dist/server"
rm -rf "$out"
mkdir -p "$out"

if [ ! -f dist/web/index.html ]; then
  echo "Hinweis: dist/web fehlt – es wird nur eine Platzhalterseite eingebettet." >&2
fi

for pair in "amd64:x86_64-unknown-linux-gnu" "arm64:aarch64-unknown-linux-gnu"; do
  arch="${pair%%:*}"
  target="${pair#*:}"
  echo "==> nrzpass linux/$arch ($target)"
  rustup target add "$target" >/dev/null 2>&1 || true
  cargo zigbuild --release -p nrzpass-server --target "$target.2.31"
  gzip -9 -c "target/$target/release/nrzpass" > "$out/nrzpass-$arch.gz"
done

(cd "$out" && shasum -a 256 nrzpass-amd64.gz nrzpass-arm64.gz > SHA256SUMS)
cat "$out/SHA256SUMS"
