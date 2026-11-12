//! nrzPass Browser-Erweiterung in Rust/WASM.
//!
//! Ein Crate, zwei WASM-Dateien:
//! * `--features background` – Service Worker: Sitzung, Abgleich, Ausfuellen, Speichern (mit Krypto).
//! * `--features content` – Inhaltsskript in jeder Seite: Login-Felder erkennen, Vorschlaege
//!   anzeigen, ausfuellen, neue Passwoerter zum Speichern anbieten.
//!
//! [`logic`] ist reine Logik und nativ getestet.

pub mod logic;

#[cfg(any(feature = "content", feature = "background"))]
mod ext;

#[cfg(feature = "background")]
mod background;

#[cfg(feature = "content")]
mod content;
