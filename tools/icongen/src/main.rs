//! Erzeugt alle nrzPass-Symbole (Store, Favicon, PWA, macOS, Erweiterung) aus einem SVG.
//!   cargo run --release --manifest-path tools/icongen/Cargo.toml -- <ausgabeordner>
use resvg::{tiny_skia, usvg};
use std::path::Path;

/// Vollflaechig (Store/Umbrel rundet selbst, Favicon, PWA, Erweiterung).
const FLAT: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
<rect width="256" height="256" fill="#18181b"/>
<path d="M128 40 196 66v50c0 47-28.6 81-68 96-39.4-15-68-49-68-96V66Z" fill="#52525b"/>
<path d="M128 58 182 79v40c0 38.5-22.4 66.8-54 80-31.6-13.2-54-41.5-54-80V79Z" fill="#e4e4e7"/>
<circle cx="128" cy="112" r="22" fill="#52525b"/>
<rect x="118" y="126" width="20" height="46" rx="10" fill="#52525b"/>
</svg>"##;

/// macOS: abgerundetes Quadrat mit Rand (Apple-Raster, 824/1024).
const MAC: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">
<rect x="100" y="100" width="824" height="824" rx="185" fill="#18181b"/>
<g transform="translate(100 100) scale(3.21875)">
<path d="M128 40 196 66v50c0 47-28.6 81-68 96-39.4-15-68-49-68-96V66Z" fill="#52525b"/>
<path d="M128 58 182 79v40c0 38.5-22.4 66.8-54 80-31.6-13.2-54-41.5-54-80V79Z" fill="#e4e4e7"/>
<circle cx="128" cy="112" r="22" fill="#52525b"/>
<rect x="118" y="126" width="20" height="46" rx="10" fill="#52525b"/>
</g>
</svg>"##;

fn render(svg: &str, size: u32, out: &Path) {
    let tree = usvg::Tree::from_str(svg, &usvg::Options::default()).expect("SVG");
    let mut pix = tiny_skia::Pixmap::new(size, size).unwrap();
    let s = size as f32 / tree.size().width();
    resvg::render(&tree, tiny_skia::Transform::from_scale(s, s), &mut pix.as_mut());
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    pix.save_png(out).expect("PNG");
    println!("{} ({size}x{size})", out.display());
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    let d = Path::new(&dir);
    render(FLAT, 256, &d.join("icon.png"));
    for s in [16, 32, 48, 128, 192, 512] {
        render(FLAT, s, &d.join(format!("icon-{s}.png")));
    }
    render(FLAT, 180, &d.join("apple-touch-icon.png"));
    render(MAC, 1024, &d.join("mac-1024.png"));
    std::fs::write(d.join("icon.svg"), FLAT).unwrap();
}
