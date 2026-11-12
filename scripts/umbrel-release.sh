#!/bin/sh
# Umbrel-Paket ohne Registry und ohne Login:
#   scripts/umbrel-release.sh 1.0.0
# baut Web-Tresor, Server (linux/amd64 + arm64, Web eingebettet), macOS-DMG und die
# Browser-Erweiterungen und legt alles als Commit auf den Zweig `umbrel` mit dem Tag
# `umbrel-<version>`:
#   nrzpass-<arch>.gz  downloads/nrzPass-macOS.dmg  downloads/nrzPass-chrome.zip
#   downloads/nrzPass-firefox.zip  SHA256SUMS
# `hooks/pre-start` der App `nrz-pass` im nrzStore laedt diese Dateien auf dem Geraet von
# http://localhost:8390/nicorenezweers/nrzPass/raw/tag/umbrel-<version>/… (nrzGit). Mit dem
# Tag aktualisiert nrzGit den Store selbst (nrzStore.json, tagPrefix "umbrel-").
# Gepusht wird auf $REMOTE (Standard: origin = nrzGit).
set -eu
cd "$(dirname "$0")/.."

version="${1:-}"
if [ -z "$version" ]; then
  echo "Aufruf: $0 <version>   (z. B. $0 1.0.0)" >&2
  exit 1
fi
remote="${REMOTE:-origin}"
tag="umbrel-$version"
out="dist/umbrel/$version"

if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "Tag $tag gibt es schon - neue Version waehlen." >&2
  exit 1
fi

scripts/build-web.sh
scripts/build-server.sh
[ "${SKIP_MAC:-}" = 1 ] || scripts/build-mac.sh
[ "${SKIP_EXTENSION:-}" = 1 ] || scripts/build-extension.sh

rm -rf "$out"
mkdir -p "$out/downloads"
cp dist/server/nrzpass-amd64.gz dist/server/nrzpass-arm64.gz "$out/"
ls dist/mac/*-macOS.dmg >/dev/null 2>&1 && cp "$(ls -t dist/mac/*-macOS.dmg | head -1)" "$out/downloads/nrzPass-macOS.dmg"
ls dist/extension/nrzPass-chrome-*.zip >/dev/null 2>&1 && cp "$(ls -t dist/extension/nrzPass-chrome-*.zip | head -1)" "$out/downloads/nrzPass-chrome.zip"
ls dist/extension/nrzPass-firefox-*.zip >/dev/null 2>&1 && cp "$(ls -t dist/extension/nrzPass-firefox-*.zip | head -1)" "$out/downloads/nrzPass-firefox.zip"
(cd "$out" && shasum -a 256 nrzpass-amd64.gz nrzpass-arm64.gz downloads/* > SHA256SUMS)

echo "==> Zweig umbrel, Tag $tag"
worktree="$(mktemp -d -t nrzpass-umbrel.XXXXXX)"
rmdir "$worktree"
trap 'git worktree remove --force "$worktree" >/dev/null 2>&1 || true' EXIT
git fetch -q "$remote" umbrel 2>/dev/null || true
if git rev-parse -q --verify "refs/remotes/$remote/umbrel" >/dev/null; then
  git worktree add -q -B umbrel "$worktree" "$remote/umbrel"
else
  git worktree add -q --orphan -b umbrel "$worktree"
fi
rm -rf "$worktree"/*.gz "$worktree"/downloads "$worktree"/SHA256SUMS
cp -R "$out"/* "$worktree/"
cat > "$worktree/README.md" <<EOT
# nrzPass – Umbrel-Paket

Dieser Zweig enthält nur fertige Dateien für die Umbrel-App \`nrz-pass\` (nrzStore). Der
Quellcode liegt auf \`main\`.

| Datei | Inhalt |
|---|---|
| \`nrzpass-<arch>.gz\` | Server mit eingebettetem Web-Tresor, amd64/arm64 (glibc) |
| \`downloads/nrzPass-macOS.dmg\` | macOS-App (Tauri, Universal) |
| \`downloads/nrzPass-chrome.zip\` | Browser-Erweiterung für Chrome, Edge, Brave, Arc |
| \`downloads/nrzPass-firefox.zip\` | Browser-Erweiterung für Firefox |
| \`SHA256SUMS\` | Prüfsummen |

Stand: nrzPass $version, gebaut aus \`$(git rev-parse --short HEAD)\` mit \`scripts/umbrel-release.sh $version\`.
EOT
git -C "$worktree" add -A
git -C "$worktree" -c user.name="$(git config user.name || echo nrz)" -c user.email="$(git config user.email || echo nrz@localhost)" \
  commit -q -m "Umbrel-Paket nrzPass $version"
git -C "$worktree" tag -a "$tag" -m "nrzPass $version"
git push -q "$remote" umbrel "refs/tags/$tag"
echo "Fertig: $tag auf $remote (Zweig umbrel)."
cat "$out/SHA256SUMS"
