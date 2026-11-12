# nrzPass

Passwort-Manager komplett in Rust – Webseite, macOS-App und Browser-Erweiterung, im klassischen
nrzTheme (Leptos + Komponenten von [Rust/UI](https://rust-ui.com)). Zero-Knowledge, mit
verschlüsselter [Turso](https://turso.tech)-Datenbank und **Vaultwarden/Bitwarden-kompatibel**.

| Teil | Technik | Ordner |
|---|---|---|
| Server + Web-Tresor | axum, Turso (AEGIS-256), Web eingebettet | `crates/server` |
| Web-Tresor (auch Oberfläche von App und Popup) | Leptos CSR → WASM, Rust/UI, Tailwind | `crates/web` |
| Krypto, Modelle, Generator, TOTP, Formularerkennung | reines Rust, nativ + WASM | `crates/core` |
| macOS-App | Tauri 2 (Universal-DMG) | `crates/desktop` |
| Browser-Erweiterung (Chrome, Edge, Brave, Firefox) | Rust → WASM, MV3 | `crates/extension`, `extension/` |
| Umbrel-Paket (nrzStore `nrz-pass`) | `debian:trixie-slim` + Programm per `pre-start` | `umbrel/`, `nrzStore.json` |

Das Grundprinzip ist die Webseite: Der Server liefert den Web-Tresor aus, die macOS-App bündelt
genau diesen Build lokal (kein Code aus dem Netz), und das Erweiterungs-Popup ist derselbe Build.

## Sicherheit

- **Zero-Knowledge wie Bitwarden:** Master-Schlüssel = Argon2id (64 MiB, 3 Durchläufe, 4 Threads)
  bzw. PBKDF2 aus Master-Passwort + E-Mail. Zum Server geht nur ein abgeleiteter Hash; der
  zufällige 512-Bit-Benutzerschlüssel liegt dort nur verschlüsselt. Jeder Wert im Tresor ist ein
  `EncString` (AES-256-CBC + HMAC-SHA256, encrypt-then-MAC, MAC-Vergleich in konstanter Zeit).
  Veraltete Typen ohne MAC werden abgelehnt, schwache KDF-Vorgaben eines Servers ebenso
  (Downgrade-Schutz). Kompatibilität ist mit dem Testvektor der offiziellen Bitwarden-SDK belegt.
- **Server:** Hash des Hashes mit Argon2id, undurchsichtige Tokens (nur SHA-256 gespeichert),
  Refresh-Token-Rotation mit Diebstahlerkennung, Brute-Force-Schutz (pro IP und pro Konto mit
  wachsender Sperre), TOTP-Zwei-Faktor mit Replay-Schutz, Geräteverwaltung,
  Sicherheitsprotokoll, strenge CSP (nur eigene Skripte, Hash für den WASM-Lader), HSTS hinter
  HTTPS, `frame-ancestors 'none'`, keine Cookies.
- **Datenbank:** Turso mit nativer Verschlüsselung (AEGIS-256); Schlüssel aus `NRZPASS_SEED`
  (auf Umbrel `APP_SEED`) per HKDF. TOTP-Geheimnisse zusätzlich mit XChaCha20-Poly1305.
- **Client:** Schlüssel nur im Arbeitsspeicher und beim Sperren überschrieben; gespeicherte
  Tokens zusätzlich mit dem Benutzerschlüssel verschlüsselt; Auto-Sperre, Sperre im
  Hintergrund, Zwischenablage wird geleert, Master-Passwort-Abfrage pro Eintrag, Export
  standardmäßig passwortgeschützt. macOS-App: Fensterinhalt vor Bildschirmfotos geschützt.
- **Erweiterung:** Ausfüllen nur, wenn die Adresse des Frames zum Eintrag passt (Phishing-Schutz),
  Popup fragt bei fremden Seiten nach; Schlüssel nur in `chrome.storage.session`.

## Vaultwarden

nrzPass spricht die Bitwarden-API in beide Richtungen:

- **Vaultwarden-Konto hinzufügen:** Im Tresor unter *Konten & Vaultwarden*. Einträge erscheinen
  neben deinen nrzPass-Einträgen, lassen sich bearbeiten und mit *In nrzPass übernehmen*
  kopieren. Organisationen werden entschlüsselt (RSA-OAEP). Im Browser läuft die Verbindung über
  den eigenen nrzPass-Server (Vaultwarden erlaubt keine fremden Webseiten), in App und
  Erweiterung direkt – Ende-zu-Ende-verschlüsselt bleibt es immer.
- **Import:** Bitwarden/Vaultwarden-JSON (auch passwortgeschützt), Bitwarden-CSV, Chrome, Firefox,
  Safari, Edge.
- **Bitwarden-Clients:** Der Server implementiert die wichtigsten Endpunkte (`/identity/connect/token`,
  `/api/sync`, Ciphers, Ordner, 2FA) – offizielle Bitwarden-Apps können ihn als eigenen Server
  verwenden (nicht alle Funktionen, z. B. keine Organisationen/Sends).

## Bauen

Voraussetzungen: Rust (mit `wasm32-unknown-unknown`), `trunk`, `cargo-tauri`, Node (nur für
Tailwind), für Linux-Server `cargo-zigbuild` + `zig`.

```sh
scripts/build-web.sh          # dist/web (Web-Tresor)
cargo run -p nrzpass-server   # http://localhost:8490
scripts/build-mac.sh          # dist/mac/nrzPass-<version>-macOS.dmg
scripts/build-extension.sh    # dist/extension/nrzPass-{chrome,firefox}-<version>.zip
scripts/build-server.sh       # dist/server/nrzpass-{amd64,arm64}.gz
scripts/umbrel-release.sh 1.0.1   # alles bauen, Zweig umbrel + Tag -> nrzStore aktualisiert sich
cargo test                    # Kern + Server (inkl. kompletter API-Ablauf)
```

## Server-Einstellungen

| Variable | Standard | Bedeutung |
|---|---|---|
| `NRZPASS_ADDRESS` / `NRZPASS_PORT` | `0.0.0.0` / `8490` | Adresse |
| `DATA_DIR` | `./data` | Datenbank (`nrzpass.db`), ggf. `db.key` |
| `NRZPASS_SEED` / `NRZPASS_DB_KEY` | – | Schlüsselquelle (Seed → HKDF, oder 64 Hex-Zeichen); sonst zufälliger `db.key` |
| `SIGNUPS_ALLOWED` | `false` | Registrierung offen (das erste Konto darf immer) |
| `SIGNUPS_DOMAINS` | – | nur diese E-Mail-Domains (kommagetrennt) |
| `TRUST_PROXY` | `0` | Client-IP aus `X-Forwarded-For` (hinter Reverse-Proxy) |
| `PROXY_ENABLED` | `true` | Vaultwarden-Proxy für den Web-Tresor |
| `DOWNLOAD_DIR` | `<exe>/downloads` | Dateien für *Apps & Erweiterung* |
| `WEB_DIR` | eingebettet | Web-Tresor von der Platte statt eingebettet |

## Installation

- **Umbrel:** nrzStore → *nrzPass* (`nrz-pass`, Port 8490, braucht nrzGit).
- **macOS:** Im Tresor unter *Apps & Erweiterung* das DMG laden, App nach „Programme“ ziehen,
  beim ersten Start Rechtsklick → Öffnen (nicht notarisiert), Server-Adresse eintragen.
- **Chrome/Edge/Brave/Arc:** ZIP entpacken → `chrome://extensions` → Entwicklermodus →
  „Entpackte Erweiterung laden“.
- **Firefox:** `about:debugging#/runtime/this-firefox` → „Temporäres Add-on laden“.
- **iPhone/Android:** Seite öffnen → „Zum Home-Bildschirm“.

Lizenz: MIT. Schriften: Geist / Geist Mono (OFL). Symbole: Lucide (ISC). Wortliste: EFF (CC BY 3.0 US).
