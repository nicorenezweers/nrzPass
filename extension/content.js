// nrzPass – Inhaltsskript. Nur ein Lader: Formularerkennung, Vorschlaege und Ausfuellen sind
// Rust (content/nrzpass_content_bg.wasm).
(async () => {
  const api = globalThis.browser ?? globalThis.chrome;
  try {
    const m = await import(api.runtime.getURL('content/nrzpass_content.js'));
    await m.default({ module_or_path: api.runtime.getURL('content/nrzpass_content_bg.wasm') });
    m.start();
  } catch (_) {
    // Erweiterung neu geladen oder Seite ohne Zugriff – still beenden
  }
})();
