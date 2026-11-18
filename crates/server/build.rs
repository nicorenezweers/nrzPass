//! Sorgt dafuer, dass `dist/web` (von trunk gebaut) existiert, damit rust-embed immer kompiliert.
//! Fehlt die Web-Oberflaeche, wird eine Platzhalterseite eingebettet.
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dist/web");
    let index = dir.join("index.html");
    if !index.exists() {
        std::fs::create_dir_all(&dir).expect("dist/web anlegen");
        std::fs::write(
            &index,
            "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\"><title>nrzPass</title></head>\
             <body><p>nrzPass: Die Web-Oberflaeche wurde noch nicht gebaut (trunk build).</p></body></html>",
        )
        .expect("Platzhalter schreiben");
    }
    println!("cargo:rerun-if-changed=../../dist/web");
}
