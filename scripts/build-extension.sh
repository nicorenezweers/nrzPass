#!/bin/sh
# nrzPass Browser-Erweiterung bauen (Chrome/Edge/Brave/Arc und Firefox):
#   scripts/build-extension.sh
# Ergebnis:
#   dist/extension/chrome/                    entpackt (chrome://extensions → "Entpackte Erweiterung laden")
#   dist/extension/firefox/                   entpackt (about:debugging → "Temporaeres Add-on laden")
#   dist/extension/nrzPass-chrome-<v>.zip     zum Verteilen (nrzStore-Downloadseite)
#   dist/extension/nrzPass-firefox-<v>.zip
# Popup = Web-Tresor (crates/web, Trunk); Hintergrund und Inhaltsskript = crates/extension (Rust/WASM).
# Braucht: cargo + Ziel wasm32-unknown-unknown, trunk, npm (Tailwind), python3, zip.
# SKIP_WEB=1 ueberspringt CSS + Trunk (wenn dist/web schon aktuell ist).
set -eu
cd "$(dirname "$0")/.."

version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
cache="${TRUNK_CACHE:-$HOME/Library/Caches/dev.trunkrs.trunk}"
wbg="${WASM_BINDGEN:-$(ls "$cache"/wasm-bindgen-*/wasm-bindgen 2>/dev/null | sort -V | tail -1)}"
wopt="${WASM_OPT:-$(ls "$cache"/wasm-opt-*/bin/wasm-opt 2>/dev/null | sort -V | tail -1)}"
[ -x "$wbg" ] || { echo "wasm-bindgen nicht gefunden (WASM_BINDGEN setzen oder einmal 'trunk build' ausfuehren)" >&2; exit 1; }
features="--enable-bulk-memory --enable-bulk-memory-opt --enable-nontrapping-float-to-int --enable-sign-ext --enable-mutable-globals --enable-reference-types --enable-multivalue"

out="dist/extension"
work="$out/.work"
rm -rf "$out"
mkdir -p "$work"

if [ "${SKIP_WEB:-0}" != "1" ]; then
  echo "==> Popup (Web-Tresor)"
  npm run css --silent
  (cd crates/web && trunk build --release)
fi
[ -f dist/web/index.html ] || { echo "dist/web fehlt – erst trunk build" >&2; exit 1; }

wasm="target/wasm32-unknown-unknown/wasm-release/nrzpass_extension.wasm"
for part in content background; do
  echo "==> Rust/WASM: $part"
  CARGO_PROFILE_WASM_RELEASE_STRIP=false cargo build -q -p nrzpass-extension --lib --target wasm32-unknown-unknown --profile wasm-release --features "$part"
  name="nrzpass_$part"; [ "$part" = background ] && name="nrzpass_bg"
  dir="$work/$part"
  "$wbg" --target web --no-typescript --out-dir "$dir" --out-name "$name" "$wasm"
  if [ -x "$wopt" ]; then
    level="-O3"; [ "$part" = content ] && level="-Oz"
    # shellcheck disable=SC2086
    "$wopt" $features $level --strip-debug --strip-producers "$dir/${name}_bg.wasm" -o "$dir/${name}_bg.wasm"
  fi
done

assemble() {
  target="$1"
  dst="$out/$target"
  mkdir -p "$dst/content" "$dst/bg" "$dst/icons"
  # Popup: Trunk-Ausgabe; das Inline-Skript muss in eine Datei (MV3 verbietet Inline-Skripte)
  cp -R dist/web/. "$dst/"
  rm -f "$dst/.trunk-lock" "$dst/index.html"
  rm -rf "$dst/.stage"
  python3 -I - "dist/web/index.html" "$dst/popup.html" "$dst/popup-boot.js" <<'PY'
import re, sys
src, html_out, js_out = sys.argv[1:4]
html = open(src, encoding="utf-8").read()
m = re.search(r'<script type="module">(.*?)</script>', html, re.S)
if not m:
    sys.exit("Inline-Skript in dist/web/index.html nicht gefunden")
open(js_out, "w", encoding="utf-8").write(m.group(1).strip() + "\n")
html = html.replace(m.group(0), '<script type="module" src="/popup-boot.js"></script>')
# Manifest/PWA-Links sind in der Erweiterung sinnlos
html = re.sub(r'\s*<link rel="manifest"[^>]*>', "", html)
open(html_out, "w", encoding="utf-8").write(html)
PY
  rm -f "$dst/site.webmanifest"
  cp extension/content.js extension/background.js "$dst/"
  cp extension/icons/*.png "$dst/icons/"
  cp "$work/content/"* "$dst/content/"
  cp "$work/background/"* "$dst/bg/"
  python3 -I - "$target" "$version" extension/manifest.template.json "$dst/manifest.json" <<'PY'
import json, sys
target, version, tpl, dst = sys.argv[1:5]
m = json.loads(open(tpl, encoding="utf-8").read().replace("@VERSION@", version))
if target == "firefox":
    m["background"] = {"scripts": ["background.js"], "type": "module"}
    m["browser_specific_settings"] = {"gecko": {"id": "nrzpass@nrz.local", "strict_min_version": "128.0"}}
else:
    m["background"] = {"service_worker": "background.js", "type": "module"}
    m["minimum_chrome_version"] = "116"
open(dst, "w", encoding="utf-8").write(json.dumps(m, indent=2, ensure_ascii=False) + "\n")
PY
  (cd "$dst" && rm -f "../nrzPass-$target-$version.zip" && zip -qr -X "../nrzPass-$target-$version.zip" .)
}

echo "==> Chrome und Firefox zusammenstellen"
assemble chrome
assemble firefox
rm -rf "$work"
ls -la "$out"
du -sh "$out/chrome/content" "$out/chrome/bg"
echo "Fertig: $out/nrzPass-chrome-$version.zip und $out/nrzPass-firefox-$version.zip"
