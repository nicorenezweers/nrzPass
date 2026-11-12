//! Laufzeitumgebung: Webseite, macOS-App (Tauri) oder Browser-Erweiterung.
//! Speicher, Zwischenablage, Downloads und Browser-APIs je nach Umgebung.

use js_sys::{Function, Object, Promise, Reflect};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Platform {
    Web,
    Tauri,
    Extension,
}

pub fn window() -> web_sys::Window {
    web_sys::window().expect("window")
}

fn global() -> JsValue {
    js_sys::global().into()
}

fn get(obj: &JsValue, key: &str) -> Option<JsValue> {
    Reflect::get(obj, &JsValue::from_str(key)).ok().filter(|v| !v.is_undefined() && !v.is_null())
}

fn path(keys: &[&str]) -> Option<JsValue> {
    let mut cur = global();
    for k in keys {
        cur = get(&cur, k)?;
    }
    Some(cur)
}

pub fn platform() -> Platform {
    if path(&["__TAURI_INTERNALS__"]).is_some() {
        return Platform::Tauri;
    }
    let proto = window().location().protocol().unwrap_or_default();
    if proto.ends_with("-extension:") {
        return Platform::Extension;
    }
    Platform::Web
}

/// Popup der Erweiterung (klein) statt Vollansicht im Tab.
pub fn is_popup() -> bool {
    platform() == Platform::Extension && !window().location().search().unwrap_or_default().contains("full=1")
}

pub fn is_firefox() -> bool {
    window().location().protocol().unwrap_or_default() == "moz-extension:"
}

/// Bitwarden-Geraetetyp und Client-Name fuer die Anmeldung.
pub fn device() -> (i64, &'static str, &'static str) {
    match platform() {
        Platform::Web => (9, "web", "nrzPass Web"),
        Platform::Tauri => (7, "desktop", "nrzPass macOS"),
        Platform::Extension if is_firefox() => (3, "browser", "nrzPass Firefox"),
        Platform::Extension => (2, "browser", "nrzPass Chrome"),
    }
}

/// Eigene Adresse, wenn nrzPass als Webseite vom Server kommt.
pub fn origin() -> String {
    window().location().origin().unwrap_or_default()
}

pub fn now_ms() -> f64 {
    js_sys::Date::now()
}

pub fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

pub fn now_iso() -> String {
    js_sys::Date::new_0().to_iso_string().as_string().unwrap_or_default()
}

pub fn format_date(iso: &str) -> String {
    let d = js_sys::Date::new(&JsValue::from_str(iso));
    if d.get_time().is_nan() {
        return iso.to_string();
    }
    let opts = Object::new();
    let _ = Reflect::set(&opts, &"dateStyle".into(), &"medium".into());
    let _ = Reflect::set(&opts, &"timeStyle".into(), &"short".into());
    d.to_locale_string("de-CH", &opts).as_string().unwrap_or_default()
}

async fn await_promise(v: JsValue) -> Result<JsValue, String> {
    let p: Promise = v.dyn_into().map_err(|_| "keine Promise".to_string())?;
    JsFuture::from(p).await.map_err(js_err)
}

pub fn js_err(e: JsValue) -> String {
    if let Some(s) = e.as_string() {
        return s;
    }
    get(&e, "message").and_then(|m| m.as_string()).unwrap_or_else(|| format!("{e:?}"))
}

fn call(obj: &JsValue, method: &str, args: &[JsValue]) -> Result<JsValue, String> {
    let f: Function = get(obj, method).ok_or(format!("{method} fehlt"))?.dyn_into().map_err(|_| format!("{method} ist keine Funktion"))?;
    let arr = js_sys::Array::new();
    for a in args {
        arr.push(a);
    }
    f.apply(obj, &arr).map_err(js_err)
}

fn ext_api() -> Option<JsValue> {
    path(&["browser"]).or_else(|| path(&["chrome"]))
}

// ---------------------------------------------------------------------------------------------
// Speicher
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Area {
    /// Bleibt erhalten (localStorage bzw. chrome.storage.local).
    Local,
    /// Nur im Arbeitsspeicher bis zum Neustart des Browsers (chrome.storage.session).
    /// Auf der Webseite: nichts (nach Neuladen ist der Tresor gesperrt).
    Session,
}

fn ext_storage(area: Area) -> Option<JsValue> {
    let name = if area == Area::Local { "local" } else { "session" };
    get(&get(&ext_api()?, "storage")?, name)
}

pub async fn store_get(area: Area, key: &str) -> Option<String> {
    if platform() == Platform::Extension {
        let st = ext_storage(area)?;
        let res = await_promise(call(&st, "get", &[JsValue::from_str(key)]).ok()?).await.ok()?;
        return get(&res, key).and_then(|v| v.as_string());
    }
    if area == Area::Session {
        return None;
    }
    window().local_storage().ok()??.get_item(key).ok()?
}

pub async fn store_set(area: Area, key: &str, value: &str) {
    if platform() == Platform::Extension {
        if let Some(st) = ext_storage(area) {
            let obj = Object::new();
            let _ = Reflect::set(&obj, &JsValue::from_str(key), &JsValue::from_str(value));
            if let Ok(p) = call(&st, "set", &[obj.into()]) {
                let _ = await_promise(p).await;
            }
        }
        return;
    }
    if area == Area::Local {
        if let Some(ls) = window().local_storage().ok().flatten() {
            let _ = ls.set_item(key, value);
        }
    }
}

pub async fn store_remove(area: Area, key: &str) {
    if platform() == Platform::Extension {
        if let Some(st) = ext_storage(area) {
            if let Ok(p) = call(&st, "remove", &[JsValue::from_str(key)]) {
                let _ = await_promise(p).await;
            }
        }
        return;
    }
    if area == Area::Local {
        if let Some(ls) = window().local_storage().ok().flatten() {
            let _ = ls.remove_item(key);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Tauri
// ---------------------------------------------------------------------------------------------

pub async fn tauri_invoke(cmd: &str, args: JsValue) -> Result<JsValue, String> {
    let internals = path(&["__TAURI_INTERNALS__"]).ok_or("Tauri nicht verfügbar")?;
    await_promise(call(&internals, "invoke", &[JsValue::from_str(cmd), args])?).await
}

// ---------------------------------------------------------------------------------------------
// Zwischenablage und Dateien
// ---------------------------------------------------------------------------------------------

thread_local! {
    static CLIP_GEN: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Kopiert Text; nach `clear_after` Sekunden wird die Zwischenablage geleert (wenn nicht
/// inzwischen etwas anderes aus nrzPass kopiert wurde).
pub async fn copy(text: &str, clear_after: u32) -> bool {
    let ok = write_clipboard(text).await;
    if ok && clear_after > 0 {
        let gen = CLIP_GEN.with(|g| {
            g.set(g.get().wrapping_add(1));
            g.get()
        });
        wasm_bindgen_futures::spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(clear_after * 1000).await;
            if CLIP_GEN.with(|g| g.get()) == gen {
                let _ = write_clipboard("").await;
            }
        });
    }
    ok
}

async fn write_clipboard(text: &str) -> bool {
    if platform() == Platform::Tauri {
        let args = Object::new();
        let _ = Reflect::set(&args, &"text".into(), &JsValue::from_str(text));
        if tauri_invoke("clipboard_write", args.into()).await.is_ok() {
            return true;
        }
    }
    let nav = window().navigator();
    if window().is_secure_context() {
        if JsFuture::from(nav.clipboard().write_text(text)).await.is_ok() {
            return true;
        }
    }
    // Fallback fuer http:// (z. B. im Heimnetz ohne Zertifikat)
    let doc = window().document().unwrap();
    let Ok(el) = doc.create_element("textarea") else { return false };
    let ta: web_sys::HtmlTextAreaElement = el.unchecked_into();
    ta.set_value(text);
    let _ = ta.set_attribute("readonly", "");
    let _ = ta.set_attribute("class", "fixed -left-[9999px] opacity-0");
    let body = doc.body().unwrap();
    let _ = body.append_child(&ta);
    ta.select();
    let html_doc: web_sys::HtmlDocument = doc.clone().unchecked_into();
    let ok = html_doc.exec_command("copy").unwrap_or(false);
    let _ = body.remove_child(&ta);
    ok
}

/// Datei speichern (Export). In der macOS-App mit nativem Dialog.
pub async fn save_file(name: &str, content: &str) -> Result<(), String> {
    if platform() == Platform::Tauri {
        let args = Object::new();
        let _ = Reflect::set(&args, &"name".into(), &JsValue::from_str(name));
        let _ = Reflect::set(&args, &"contents".into(), &JsValue::from_str(content));
        return tauri_invoke("save_file", args.into()).await.map(|_| ());
    }
    let parts = js_sys::Array::of1(&JsValue::from_str(content));
    let bag = web_sys::BlobPropertyBag::new();
    bag.set_type("application/octet-stream");
    let blob = web_sys::Blob::new_with_str_sequence_and_options(&parts, &bag).map_err(js_err)?;
    let url = web_sys::Url::create_object_url_with_blob(&blob).map_err(js_err)?;
    let doc = window().document().unwrap();
    let a: web_sys::HtmlAnchorElement = doc.create_element("a").map_err(js_err)?.unchecked_into();
    a.set_href(&url);
    a.set_download(name);
    doc.body().unwrap().append_child(&a).map_err(js_err)?;
    a.click();
    let _ = doc.body().unwrap().remove_child(&a);
    let _ = web_sys::Url::revoke_object_url(&url);
    Ok(())
}

pub async fn read_file(file: web_sys::File) -> Result<String, String> {
    let p = call(&file.into(), "text", &[])?;
    await_promise(p).await?.as_string().ok_or("Datei nicht lesbar".into())
}

/// Oeffnet eine Adresse in einem neuen Tab bzw. im Standardbrowser.
pub fn open_url(url: &str) {
    if platform() == Platform::Tauri {
        let args = Object::new();
        let _ = Reflect::set(&args, &"url".into(), &JsValue::from_str(url));
        wasm_bindgen_futures::spawn_local(async move {
            let _ = tauri_invoke("open_url", args.into()).await;
        });
        return;
    }
    let _ = window().open_with_url_and_target_and_features(url, "_blank", "noopener,noreferrer");
}

// ---------------------------------------------------------------------------------------------
// Browser-Erweiterung
// ---------------------------------------------------------------------------------------------

/// Adresse und ID des aktiven Tabs (nur Erweiterung).
pub async fn active_tab() -> Option<(i32, String)> {
    let tabs = get(&ext_api()?, "tabs")?;
    let q = Object::new();
    let _ = Reflect::set(&q, &"active".into(), &JsValue::TRUE);
    let _ = Reflect::set(&q, &"currentWindow".into(), &JsValue::TRUE);
    let res = await_promise(call(&tabs, "query", &[q.into()]).ok()?).await.ok()?;
    let tab = Reflect::get(&res, &JsValue::from(0)).ok()?;
    let id = get(&tab, "id")?.as_f64()? as i32;
    let url = get(&tab, "url")?.as_string()?;
    Some((id, url))
}

/// Nachricht an das Inhaltsskript eines Tabs (z. B. Felder ausfuellen).
pub async fn send_to_tab(tab_id: i32, msg: &serde_json::Value) -> Result<JsValue, String> {
    let tabs = get(&ext_api().ok_or("keine Erweiterung")?, "tabs").ok_or("tabs fehlt")?;
    let v = js_sys::JSON::parse(&msg.to_string()).map_err(js_err)?;
    await_promise(call(&tabs, "sendMessage", &[JsValue::from(tab_id), v])?).await
}

/// Nachricht an den Hintergrund-Dienst der Erweiterung.
pub async fn send_to_background(msg: &serde_json::Value) -> Result<JsValue, String> {
    let rt = get(&ext_api().ok_or("keine Erweiterung")?, "runtime").ok_or("runtime fehlt")?;
    let v = js_sys::JSON::parse(&msg.to_string()).map_err(js_err)?;
    await_promise(call(&rt, "sendMessage", &[v])?).await
}

/// Vollansicht der Erweiterung in einem Tab oeffnen.
pub fn open_extension_tab() {
    let Some(api) = ext_api() else { return };
    let (Some(rt), Some(tabs)) = (get(&api, "runtime"), get(&api, "tabs")) else { return };
    let Ok(url) = call(&rt, "getURL", &[JsValue::from_str("popup.html?full=1")]) else { return };
    let opts = Object::new();
    let _ = Reflect::set(&opts, &"url".into(), &url);
    let _ = call(&tabs, "create", &[opts.into()]);
    let _ = window().close();
}

pub fn close_popup() {
    if is_popup() {
        let _ = window().close();
    }
}
