# nrzPass – Umbrel-Paket

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

Stand: nrzPass 1.0.6, gebaut aus `cefb7f8` mit `scripts/umbrel-release.sh 1.0.6`.
