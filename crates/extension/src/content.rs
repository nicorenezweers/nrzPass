//! Inhaltsskript: erkennt Login-, Registrierungs- und Passwort-aendern-Formulare, zeigt
//! Vorschlaege unter dem Feld, fuellt aus, schlaegt starke Passwoerter vor und bietet nach dem
//! Absenden "In nrzPass speichern" an.
//!
//! Die Oberflaeche lebt in einem geschlossenen Shadow-DOM: die Seite kann weder hineinsehen noch
//! Klicks darin ausloesen (zusaetzlich zaehlen nur echte Klicks, `isTrusted`). Passwoerter
//! erreichen die Seite nur durch das Ausfuellen selbst.

use crate::ext;
use crate::logic;
use nrzpass_core::detect::{self, FieldInfo, FieldKind, FormKind};
use serde_json::json;
use std::cell::RefCell;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{Document, Element, HtmlElement, HtmlInputElement, ShadowRoot};

const CSS: &str = r#"
:host { all: initial !important; }
* { box-sizing: border-box; }
.dd { position: fixed; z-index: 2147483647; min-width: 260px; max-width: 380px; padding: 4px; background: #1c1c1c; color: #f5f5f5;
  border: 1px solid #2e2e2e; border-radius: 10px; box-shadow: 0 12px 32px rgba(0,0,0,.45), 0 0 0 1px rgba(0,0,0,.2);
  font: 13px/1.35 Geist, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; display: none; }
.dd.open { display: block; animation: in .12s ease-out; }
@keyframes in { from { opacity: 0; transform: translateY(-4px); } }
.item { display: flex; align-items: center; gap: 10px; padding: 7px 8px; border-radius: 7px; cursor: pointer; user-select: none; }
.item:hover, .item.sel { background: #262626; }
.av { width: 28px; height: 28px; border-radius: 7px; background: #2e2e33; color: #e4e4e7; display: grid; place-items: center;
  font-weight: 600; font-size: 12px; flex-shrink: 0; }
.t { min-width: 0; flex: 1; }
.n { font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.s { color: #a1a1a1; font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.pw { font-family: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: #d4d4d4; word-break: break-all; white-space: normal; }
.msg { padding: 9px 10px; color: #a1a1a1; }
.err { padding: 9px 10px; color: #f87171; }
.foot { display: flex; align-items: center; gap: 6px; padding: 6px 8px 3px; margin-top: 4px; border-top: 1px solid #262626; color: #737373; font-size: 11px; }
.bar { position: fixed; z-index: 2147483647; top: 16px; right: 16px; width: 340px; max-width: calc(100vw - 32px); padding: 14px;
  background: #1c1c1c; color: #f5f5f5; border: 1px solid #2e2e2e; border-radius: 12px; box-shadow: 0 16px 40px rgba(0,0,0,.5);
  font: 13px/1.4 Geist, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; display: none; }
.bar.open { display: block; animation: in .15s ease-out; }
.row { display: flex; align-items: flex-start; gap: 10px; }
.title { font-weight: 600; }
.sub { color: #a1a1a1; font-size: 12px; margin-top: 2px; word-break: break-all; }
.x { margin-left: auto; background: none; border: 0; color: #a1a1a1; cursor: pointer; font-size: 16px; line-height: 1; padding: 2px 4px; border-radius: 6px; }
.x:hover { color: #f5f5f5; background: #262626; }
.btns { display: flex; gap: 8px; margin-top: 12px; }
.btn { flex: 1; height: 32px; border-radius: 7px; border: 1px solid #303030; background: transparent; color: #f5f5f5; font: inherit;
  font-weight: 500; cursor: pointer; }
.btn:hover { background: #262626; }
.btn.primary { background: #f5f5f5; color: #141414; border-color: #f5f5f5; }
.btn.primary:hover { background: #e5e5e5; }
svg { display: block; flex-shrink: 0; }
"#;

const LOGO: &str = r##"<svg viewBox="0 0 256 256" width="SIZE" height="SIZE"><rect width="256" height="256" rx="56" fill="#18181b"/><path d="M128 40 196 66v50c0 47-28.6 81-68 96-39.4-15-68-49-68-96V66Z" fill="#52525b"/><path d="M128 58 182 79v40c0 38.5-22.4 66.8-54 80-31.6-13.2-54-41.5-54-80V79Z" fill="#e4e4e7"/><circle cx="128" cy="112" r="22" fill="#52525b"/><rect x="118" y="126" width="20" height="46" rx="10" fill="#52525b"/></svg>"##;

fn logo(size: u32) -> String {
    LOGO.replace("SIZE", &size.to_string())
}

#[derive(Clone)]
struct Field {
    el: HtmlInputElement,
    kind: FieldKind,
}

#[derive(Clone)]
struct Group {
    form: Option<web_sys::HtmlFormElement>,
    kind: FormKind,
    fields: Vec<Field>,
}

impl Group {
    fn of(&self, k: FieldKind) -> Vec<HtmlInputElement> {
        self.fields.iter().filter(|f| f.kind == k).map(|f| f.el.clone()).collect()
    }
    fn contains(&self, el: &HtmlInputElement) -> bool {
        self.fields.iter().any(|f| &f.el == el)
    }
}

#[derive(Clone)]
enum Action {
    Fill(String),
    Generate(String),
    Totp(String),
}

struct Ui {
    root: ShadowRoot,
    dd: HtmlElement,
    bar: HtmlElement,
}

#[derive(Default)]
struct State {
    groups: Vec<Group>,
    tracked: Option<js_sys::WeakSet>,
    ui: Option<Ui>,
    target: Option<HtmlInputElement>,
    actions: Vec<Action>,
    selected: i32,
    filling: bool,
    scan_timer: Option<i32>,
    last_remember: (String, String, f64),
}

thread_local! {
    static ST: RefCell<State> = RefCell::new(State::default());
}

fn doc() -> Document {
    web_sys::window().unwrap().document().unwrap()
}

fn win() -> web_sys::Window {
    web_sys::window().unwrap()
}

fn page_url() -> String {
    win().location().href().unwrap_or_default()
}

fn is_top() -> bool {
    win().top().ok().flatten().map(|t| JsValue::from(t) == JsValue::from(win())).unwrap_or(true)
}

fn listen(target: &web_sys::EventTarget, ev: &str, capture: bool, f: impl FnMut(web_sys::Event) + 'static) {
    let cb = Closure::<dyn FnMut(web_sys::Event)>::new(f);
    let _ = target.add_event_listener_with_callback_and_bool(ev, cb.as_ref().unchecked_ref(), capture);
    cb.forget();
}

fn spawn(f: impl std::future::Future<Output = ()> + 'static) {
    wasm_bindgen_futures::spawn_local(f);
}

// ---------------------------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------------------------

#[wasm_bindgen]
pub fn start() {
    let proto = win().location().protocol().unwrap_or_default();
    if proto != "http:" && proto != "https:" {
        return;
    }
    ST.with(|s| s.borrow_mut().tracked = Some(js_sys::WeakSet::new()));
    scan();
    // Feld hatte schon beim Laden den Fokus (z. B. 2FA-Seite mit autofocus)
    if let Some(el) = doc().active_element().and_then(|a| a.dyn_into::<HtmlInputElement>().ok()) {
        on_focus(el);
    }

    // Neue Felder (Single-Page-Apps, Dialoge) – entprellt neu einlesen
    let cb = Closure::<dyn FnMut()>::new(schedule_scan);
    if let Ok(mo) = web_sys::MutationObserver::new(cb.as_ref().unchecked_ref()) {
        let opts = web_sys::MutationObserverInit::new();
        opts.set_child_list(true);
        opts.set_subtree(true);
        opts.set_attributes(true);
        opts.set_attribute_filter(&js_sys::Array::of2(&"type".into(), &"style".into()));
        if let Some(root) = doc().document_element() {
            let _ = mo.observe_with_options(&root, &opts);
        }
    }
    cb.forget();

    let d: web_sys::EventTarget = doc().into();
    listen(&d, "focusin", true, |e| {
        if let Some(el) = e.target().and_then(|t| t.dyn_into::<HtmlInputElement>().ok()) {
            on_focus(el);
        }
    });
    listen(&d, "mousedown", true, |e| {
        if !e.is_trusted() {
            return;
        }
        if let Some(el) = e.target().and_then(|t| t.dyn_into::<HtmlInputElement>().ok()) {
            let focused = doc().active_element().map(|a| JsValue::from(a) == JsValue::from(el.clone())).unwrap_or(false);
            if focused && !dropdown_open() {
                on_focus(el);
            }
        }
    });
    listen(&d, "focusout", true, |e| {
        let Some(el) = e.target().and_then(|t| t.dyn_into::<HtmlInputElement>().ok()) else { return };
        let is_target = ST.with(|s| s.borrow().target.as_ref() == Some(&el));
        if is_target {
            let cb = Closure::once_into_js(move || {
                let still = doc().active_element().map(|a| JsValue::from(a) == JsValue::from(el)).unwrap_or(false);
                if !still {
                    close_dropdown();
                }
            });
            let _ = win().set_timeout_with_callback_and_timeout_and_arguments_0(cb.unchecked_ref(), 150);
        }
    });
    listen(&d, "keydown", true, |e| {
        if let Some(k) = e.dyn_ref::<web_sys::KeyboardEvent>() {
            on_key(k);
        }
    });
    listen(&d, "submit", true, |e| {
        if let Some(form) = e.target().and_then(|t| t.dyn_into::<web_sys::HtmlFormElement>().ok()) {
            let g = ST.with(|s| s.borrow().groups.iter().find(|g| g.form.as_ref() == Some(&form)).cloned());
            if let Some(g) = g {
                remember_group(&g);
            }
        }
    });
    listen(&d, "click", true, |e| {
        if e.is_trusted() {
            on_click(&e);
        }
    });
    let w: web_sys::EventTarget = win().into();
    listen(&w, "scroll", true, |_| close_dropdown());
    listen(&w, "resize", false, |_| close_dropdown());

    // Ausfuellen aus dem Popup
    if let Some(rt) = ext::path(&["runtime"]) {
        if let Some(on_msg) = ext::get(&rt, "onMessage") {
            let cb = Closure::<dyn FnMut(JsValue, JsValue, js_sys::Function) -> JsValue>::new(on_runtime_message);
            let _ = ext::call(&on_msg, "addListener", &[cb.as_ref().clone()]);
            cb.forget();
        }
    }

    // Nach einer Weiterleitung: noch offenes "Speichern?"
    if is_top() {
        spawn(async {
            let r = ext::send(json!({"type": "get_pending"})).await;
            let p = &r["pending"];
            if p.is_object() {
                show_bar(p["action"].as_str().unwrap_or("new"), p["host"].as_str().unwrap_or(""), p["username"].as_str().unwrap_or(""));
            }
        });
    }
}

// ---------------------------------------------------------------------------------------------
// Felder erkennen
// ---------------------------------------------------------------------------------------------

fn schedule_scan() {
    let pending = ST.with(|s| s.borrow().scan_timer.is_some());
    if pending {
        return;
    }
    let cb = Closure::once_into_js(|| {
        ST.with(|s| s.borrow_mut().scan_timer = None);
        scan();
    });
    let id = win().set_timeout_with_callback_and_timeout_and_arguments_0(cb.unchecked_ref(), 400).ok();
    ST.with(|s| s.borrow_mut().scan_timer = id);
}

fn attr(el: &Element, name: &str) -> String {
    el.get_attribute(name).unwrap_or_default()
}

fn visible(el: &HtmlInputElement) -> bool {
    let r = el.get_bounding_client_rect();
    if r.width() < 2.0 || r.height() < 2.0 {
        return false;
    }
    match win().get_computed_style(el) {
        Ok(Some(cs)) => cs.get_property_value("visibility").map(|v| v != "hidden").unwrap_or(true),
        _ => true,
    }
}

fn label_text(el: &HtmlInputElement) -> String {
    let mut out = String::new();
    if let Some(list) = el.labels() {
        for i in 0..list.length().min(3) {
            if let Some(n) = list.item(i) {
                out.push_str(&n.text_content().unwrap_or_default());
                out.push(' ');
            }
        }
    }
    out.chars().take(120).collect()
}

fn info(el: &HtmlInputElement) -> FieldInfo {
    FieldInfo {
        input_type: el.type_().to_lowercase(),
        name: attr(el, "name"),
        id: el.id(),
        autocomplete: attr(el, "autocomplete"),
        placeholder: attr(el, "placeholder"),
        aria_label: attr(el, "aria-label"),
        label: label_text(el),
        visible: visible(el) && !el.disabled() && !el.read_only(),
        max_length: el.max_length().max(0) as i64,
        input_mode: attr(el, "inputmode"),
    }
}

fn scan() {
    let Ok(list) = doc().query_selector_all("input") else { return };
    let mut raw: Vec<(Option<web_sys::HtmlFormElement>, Vec<(HtmlInputElement, FieldInfo)>)> = Vec::new();
    for i in 0..list.length().min(400) {
        let Some(el) = list.item(i).and_then(|n| n.dyn_into::<HtmlInputElement>().ok()) else { continue };
        let fi = info(&el);
        let form = el.form();
        match raw.iter_mut().find(|(f, _)| *f == form) {
            Some((_, v)) => v.push((el, fi)),
            None => raw.push((form, vec![(el, fi)])),
        }
    }
    let tracked = ST.with(|s| s.borrow().tracked.clone()).unwrap_or_else(js_sys::WeakSet::new);
    let mut groups = Vec::new();
    for (form, fields) in raw {
        let infos: Vec<FieldInfo> = fields.iter().map(|(_, i)| i.clone()).collect();
        let (kind, kinds) = detect::classify_form(&infos);
        if kind == FormKind::None {
            continue;
        }
        let fs: Vec<Field> = fields
            .into_iter()
            .zip(kinds)
            .filter(|(_, k)| *k != FieldKind::Other)
            .map(|((el, _), kind)| {
                tracked.add(&el);
                Field { el, kind }
            })
            .collect();
        if !fs.is_empty() {
            groups.push(Group { form, kind, fields: fs });
        }
    }
    ST.with(|s| s.borrow_mut().groups = groups);
}

fn group_of(el: &HtmlInputElement) -> Option<(Group, FieldKind)> {
    let find = || {
        ST.with(|s| {
            let st = s.borrow();
            st.groups.iter().find_map(|g| g.fields.iter().find(|f| &f.el == el).map(|f| (g.clone(), f.kind)))
        })
    };
    find().or_else(|| {
        scan();
        find()
    })
}

// ---------------------------------------------------------------------------------------------
// Oberflaeche (geschlossenes Shadow-DOM)
// ---------------------------------------------------------------------------------------------

fn ui() -> Option<(ShadowRoot, HtmlElement, HtmlElement)> {
    if let Some(u) = ST.with(|s| s.borrow().ui.as_ref().map(|u| (u.root.clone(), u.dd.clone(), u.bar.clone()))) {
        if u.0.host().is_connected() {
            return Some(u);
        }
    }
    let d = doc();
    let host: HtmlElement = d.create_element("nrzpass-root").ok()?.dyn_into().ok()?;
    let st = host.style();
    let _ = st.set_property_with_priority("all", "initial", "important");
    let _ = st.set_property_with_priority("position", "fixed", "important");
    let _ = st.set_property_with_priority("top", "0", "important");
    let _ = st.set_property_with_priority("left", "0", "important");
    let _ = st.set_property_with_priority("width", "0", "important");
    let _ = st.set_property_with_priority("height", "0", "important");
    let _ = st.set_property_with_priority("z-index", "2147483647", "important");
    let _ = st.set_property_with_priority("display", "block", "important");
    let root = host.attach_shadow(&web_sys::ShadowRootInit::new(web_sys::ShadowRootMode::Closed)).ok()?;
    // Konstruierbares Stylesheet (CSSOM) – nicht von der CSP der Seite blockiert
    let mut styled = false;
    if let Ok(sheet) = web_sys::CssStyleSheet::new() {
        if sheet.replace_sync(CSS).is_ok() {
            root.set_adopted_style_sheets(&js_sys::Array::of1(&sheet));
            styled = true;
        }
    }
    if !styled {
        let style = d.create_element("style").ok()?;
        style.set_text_content(Some(CSS));
        root.append_child(&style).ok()?;
    }
    let dd: HtmlElement = d.create_element("div").ok()?.dyn_into().ok()?;
    dd.set_class_name("dd");
    let _ = dd.set_attribute("role", "listbox");
    let bar: HtmlElement = d.create_element("div").ok()?.dyn_into().ok()?;
    bar.set_class_name("bar");
    let _ = bar.set_attribute("role", "dialog");
    root.append_child(&dd).ok()?;
    root.append_child(&bar).ok()?;
    d.document_element()?.append_child(&host).ok()?;

    let r: web_sys::EventTarget = dd.clone().into();
    // Fokus im Feld lassen
    listen(&r, "mousedown", false, |e| e.prevent_default());
    listen(&r, "click", false, |e| {
        if !e.is_trusted() {
            return;
        }
        let item = e.target().and_then(|t| t.dyn_into::<Element>().ok()).and_then(|t| t.closest("[data-i]").ok().flatten());
        if let Some(i) = item.and_then(|el| el.get_attribute("data-i")).and_then(|s| s.parse::<usize>().ok()) {
            activate(i);
        }
    });
    let b: web_sys::EventTarget = bar.clone().into();
    listen(&b, "click", false, |e| {
        if !e.is_trusted() {
            return;
        }
        let act = e.target().and_then(|t| t.dyn_into::<Element>().ok()).and_then(|t| t.closest("[data-act]").ok().flatten()).and_then(|el| el.get_attribute("data-act"));
        if let Some(a) = act {
            bar_action(&a);
        }
    });
    ST.with(|s| s.borrow_mut().ui = Some(Ui { root: root.clone(), dd: dd.clone(), bar: bar.clone() }));
    Some((root, dd, bar))
}

fn el(tag: &str, class: &str, text: Option<&str>) -> Element {
    let e = doc().create_element(tag).unwrap();
    if !class.is_empty() {
        e.set_class_name(class);
    }
    if let Some(t) = text {
        e.set_text_content(Some(t));
    }
    e
}

fn dropdown_open() -> bool {
    ST.with(|s| s.borrow().ui.as_ref().map(|u| u.dd.class_list().contains("open")).unwrap_or(false))
}

fn close_dropdown() {
    ST.with(|s| {
        let mut st = s.borrow_mut();
        st.target = None;
        st.actions.clear();
        st.selected = -1;
        if let Some(u) = &st.ui {
            let _ = u.dd.class_list().remove_1("open");
            u.dd.set_inner_html("");
        }
    });
}

enum Row {
    Login { name: String, user: String },
    Totp { name: String, user: String },
    Generate(String),
    Msg(String),
    Err(String),
}

fn render(anchor: &HtmlInputElement, rows: Vec<Row>) {
    let Some((_, dd, _)) = ui() else { return };
    dd.set_inner_html("");
    let mut i = 0usize;
    for r in rows {
        match r {
            Row::Login { name, user } => {
                let item = el("div", "item", None);
                let _ = item.set_attribute("data-i", &i.to_string());
                let _ = item.set_attribute("role", "option");
                i += 1;
                let letter = name.chars().find(|c| c.is_alphanumeric()).map(|c| c.to_uppercase().to_string()).unwrap_or("•".into());
                item.append_child(&el("div", "av", Some(&letter))).ok();
                let t = el("div", "t", None);
                t.append_child(&el("div", "n", Some(&name))).ok();
                t.append_child(&el("div", "s", Some(&if user.is_empty() { "ohne Benutzername".to_string() } else { format!("Anmelden als {user}") }))).ok();
                item.append_child(&t).ok();
                dd.append_child(&item).ok();
            }
            Row::Totp { name, user } => {
                let item = el("div", "item", None);
                let _ = item.set_attribute("data-i", &i.to_string());
                let _ = item.set_attribute("role", "option");
                i += 1;
                let av = el("div", "av", None);
                // Schild mit Uhr: 2FA-Code
                av.set_inner_html(r#"<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 8v4l2 1.5"/></svg>"#);
                item.append_child(&av).ok();
                let t = el("div", "t", None);
                t.append_child(&el("div", "n", Some(&name))).ok();
                t.append_child(&el("div", "s", Some(&if user.is_empty() { "2FA-Code einfügen".to_string() } else { format!("2FA-Code einfügen · {user}") }))).ok();
                item.append_child(&t).ok();
                dd.append_child(&item).ok();
            }
            Row::Generate(pw) => {
                let item = el("div", "item", None);
                let _ = item.set_attribute("data-i", &i.to_string());
                let _ = item.set_attribute("role", "option");
                i += 1;
                let av = el("div", "av", None);
                av.set_inner_html(r#"<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.64 3.64-1.28-1.28a1.21 1.21 0 0 0-1.72 0L2.36 18.64a1.21 1.21 0 0 0 0 1.72l1.28 1.28a1.2 1.2 0 0 0 1.72 0L21.64 5.36a1.2 1.2 0 0 0 0-1.72"/><path d="m14 7 3 3"/><path d="M5 6v4"/><path d="M19 14v4"/><path d="M10 2v2"/><path d="M7 8H3"/><path d="M21 16h-4"/></svg>"#);
                item.append_child(&av).ok();
                let t = el("div", "t", None);
                t.append_child(&el("div", "n", Some("Starkes Passwort vorschlagen"))).ok();
                t.append_child(&el("div", "pw", Some(&pw))).ok();
                item.append_child(&t).ok();
                dd.append_child(&item).ok();
            }
            Row::Msg(m) => {
                dd.append_child(&el("div", "msg", Some(&m))).ok();
            }
            Row::Err(m) => {
                dd.append_child(&el("div", "err", Some(&m))).ok();
            }
        }
    }
    let foot = el("div", "foot", None);
    foot.set_inner_html(&format!("{}<span>nrzPass</span>", logo(14)));
    dd.append_child(&foot).ok();
    let _ = dd.class_list().add_1("open");
    position(anchor, &dd);
}

fn position(anchor: &HtmlInputElement, dd: &HtmlElement) {
    let r = anchor.get_bounding_client_rect();
    let vw = win().inner_width().ok().and_then(|v| v.as_f64()).unwrap_or(1024.0);
    let vh = win().inner_height().ok().and_then(|v| v.as_f64()).unwrap_or(768.0);
    let width = r.width().clamp(260.0, 380.0).min(vw - 16.0);
    let left = r.left().min(vw - width - 8.0).max(8.0);
    let st = dd.style();
    let _ = st.set_property("width", &format!("{width}px"));
    let _ = st.set_property("left", &format!("{left}px"));
    let h = dd.get_bounding_client_rect().height();
    let top = if r.bottom() + 6.0 + h > vh && r.top() - 6.0 - h > 0.0 { r.top() - 6.0 - h } else { r.bottom() + 6.0 };
    let _ = st.set_property("top", &format!("{top}px"));
}

fn highlight() {
    ST.with(|s| {
        let st = s.borrow();
        if let Some(u) = &st.ui {
            if let Ok(items) = u.dd.query_selector_all("[data-i]") {
                for i in 0..items.length() {
                    if let Some(e) = items.item(i).and_then(|n| n.dyn_into::<Element>().ok()) {
                        let _ = if i as i32 == st.selected { e.class_list().add_1("sel") } else { e.class_list().remove_1("sel") };
                    }
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------------------------
// Vorschlaege
// ---------------------------------------------------------------------------------------------

fn on_focus(input: HtmlInputElement) {
    if ST.with(|s| s.borrow().filling) {
        return;
    }
    let tracked = ST.with(|s| s.borrow().tracked.as_ref().map(|t| t.has(&input)).unwrap_or(false));
    if !tracked {
        scan();
    }
    let Some((group, kind)) = group_of(&input) else { return };
    if !matches!(kind, FieldKind::Username | FieldKind::CurrentPassword | FieldKind::NewPassword | FieldKind::Totp) {
        return;
    }
    // Einzelfelder: Vorschlag nur am ersten (leeren) Feld, nicht bei jeder Ziffer
    if kind == FieldKind::Totp {
        let boxes = group.of(FieldKind::Totp);
        if boxes.len() > 1 && (boxes.first() != Some(&input) || !input.value().is_empty()) {
            return;
        }
    }
    spawn(async move {
        let mut rows = Vec::new();
        let mut actions = Vec::new();
        let mut preselect = -1;
        if kind == FieldKind::Totp {
            let r = ext::send(json!({"type": "get_totps"})).await;
            if r.is_null() {
                return;
            }
            if r["locked"].as_bool().unwrap_or(true) {
                rows.push(Row::Msg("nrzPass ist gesperrt – für den 2FA-Code auf das nrzPass-Symbol klicken.".into()));
            } else {
                for it in r["items"].as_array().into_iter().flatten() {
                    if it["reprompt"].as_bool().unwrap_or(false) {
                        continue;
                    }
                    rows.push(Row::Totp {
                        name: it["name"].as_str().unwrap_or("").to_string(),
                        user: it["username"].as_str().unwrap_or("").to_string(),
                    });
                    actions.push(Action::Totp(it["key"].as_str().unwrap_or("").to_string()));
                }
                // Gerade ausgefuellter Login oder nur ein Treffer: mit Enter direkt einfuegen
                if !actions.is_empty() && (actions.len() == 1 || r["last"].is_string()) {
                    preselect = 0;
                }
            }
        } else if kind == FieldKind::NewPassword {
            let r = ext::send(json!({"type": "generate"})).await;
            if let Some(pw) = r["password"].as_str() {
                rows.push(Row::Generate(pw.to_string()));
                actions.push(Action::Generate(pw.to_string()));
            }
        } else {
            let r = ext::send(json!({"type": "get_logins"})).await;
            if r.is_null() {
                return;
            }
            if r["locked"].as_bool().unwrap_or(true) {
                if kind == FieldKind::CurrentPassword {
                    rows.push(Row::Msg("nrzPass ist gesperrt – klicke auf das nrzPass-Symbol in der Symbolleiste.".into()));
                }
            } else {
                for it in r["items"].as_array().into_iter().flatten() {
                    rows.push(Row::Login {
                        name: it["name"].as_str().unwrap_or("").to_string(),
                        user: it["username"].as_str().unwrap_or("").to_string(),
                    });
                    actions.push(Action::Fill(it["key"].as_str().unwrap_or("").to_string()));
                }
            }
        }
        if rows.is_empty() {
            return;
        }
        // Fokus inzwischen woanders?
        let still = doc().active_element().map(|a| JsValue::from(a) == JsValue::from(input.clone())).unwrap_or(false);
        if !still {
            return;
        }
        ST.with(|s| {
            let mut st = s.borrow_mut();
            st.target = Some(input.clone());
            st.actions = actions;
            st.selected = preselect;
        });
        render(&input, rows);
        highlight();
    });
}

fn on_key(e: &web_sys::KeyboardEvent) {
    let target = e.target().and_then(|t| t.dyn_into::<HtmlInputElement>().ok());
    let open = dropdown_open();
    if open {
        let n = ST.with(|s| s.borrow().actions.len()) as i32;
        match e.key().as_str() {
            "ArrowDown" if n > 0 => {
                e.prevent_default();
                ST.with(|s| {
                    let mut st = s.borrow_mut();
                    st.selected = (st.selected + 1).rem_euclid(n);
                });
                highlight();
                return;
            }
            "ArrowUp" if n > 0 => {
                e.prevent_default();
                ST.with(|s| {
                    let mut st = s.borrow_mut();
                    st.selected = if st.selected <= 0 { n - 1 } else { st.selected - 1 };
                });
                highlight();
                return;
            }
            "Enter" => {
                let sel = ST.with(|s| s.borrow().selected);
                if sel >= 0 {
                    e.prevent_default();
                    e.stop_propagation();
                    activate(sel as usize);
                    return;
                }
            }
            "Escape" => {
                close_dropdown();
                return;
            }
            _ => {}
        }
    }
    if e.key() == "Enter" {
        if let Some(t) = target {
            if let Some((g, _)) = group_of(&t) {
                remember_group(&g);
            }
        }
    }
}

fn activate(i: usize) {
    let (action, target) = ST.with(|s| {
        let st = s.borrow();
        (st.actions.get(i).cloned(), st.target.clone())
    });
    let (Some(action), Some(target)) = (action, target) else { return };
    let Some((group, _)) = group_of(&target) else { return };
    match action {
        Action::Generate(pw) => {
            let fields = group.of(FieldKind::NewPassword);
            fill_fields(&fields, &pw);
            close_dropdown();
        }
        Action::Totp(key) => {
            spawn(async move {
                let r = ext::send(json!({"type": "get_totp", "key": key})).await;
                match r["totp"].as_str() {
                    Some(code) => {
                        ST.with(|s| s.borrow_mut().filling = true);
                        fill_totp(&group, code);
                        ST.with(|s| s.borrow_mut().filling = false);
                        close_dropdown();
                    }
                    None => {
                        render(&target, vec![Row::Err(r["error"].as_str().unwrap_or("2FA-Code nicht verfügbar").to_string())]);
                        ST.with(|s| s.borrow_mut().actions.clear());
                    }
                }
            });
        }
        Action::Fill(key) => {
            spawn(async move {
                let r = ext::send(json!({"type": "get_fill", "key": key})).await;
                if let Some(err) = r["error"].as_str() {
                    render(&target, vec![Row::Err(err.to_string())]);
                    ST.with(|s| s.borrow_mut().actions.clear());
                    return;
                }
                fill_group(&group, r["username"].as_str(), r["password"].as_str(), r["totp"].as_str());
                close_dropdown();
            });
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Ausfuellen
// ---------------------------------------------------------------------------------------------

fn set_value(el: &HtmlInputElement, value: &str) {
    let _ = el.focus();
    el.set_value(value);
    let init = web_sys::EventInit::new();
    init.set_bubbles(true);
    for ev in ["input", "change"] {
        if let Ok(e) = web_sys::Event::new_with_event_init_dict(ev, &init) {
            let _ = el.dispatch_event(&e);
        }
    }
}

fn fill_fields(fields: &[HtmlInputElement], value: &str) {
    ST.with(|s| s.borrow_mut().filling = true);
    for f in fields {
        set_value(f, value);
    }
    ST.with(|s| s.borrow_mut().filling = false);
}

fn fill_group(g: &Group, username: Option<&str>, password: Option<&str>, totp: Option<&str>) {
    ST.with(|s| s.borrow_mut().filling = true);
    if let Some(u) = username.filter(|u| !u.is_empty()) {
        for f in g.of(FieldKind::Username) {
            set_value(&f, u);
        }
    }
    if let Some(p) = password.filter(|p| !p.is_empty()) {
        let mut pw = g.of(FieldKind::CurrentPassword);
        if pw.is_empty() && g.kind == FormKind::Login {
            pw = g.of(FieldKind::NewPassword);
        }
        for f in pw {
            set_value(&f, p);
        }
    }
    if let Some(t) = totp.filter(|t| !t.is_empty()) {
        fill_totp(g, t);
    }
    ST.with(|s| s.borrow_mut().filling = false);
}

/// Einmalcode einfuegen; bei Einzelfeldern (je ein Zeichen) Ziffer fuer Ziffer.
fn fill_totp(g: &Group, code: &str) {
    let fields = g.of(FieldKind::Totp);
    let digits: Vec<char> = code.chars().collect();
    if fields.len() > 1 && fields.iter().all(|f| f.max_length() == 1) {
        for (f, c) in fields.iter().zip(digits.iter()) {
            set_value(f, &c.to_string());
        }
    } else {
        for f in &fields {
            set_value(f, code);
        }
    }
}

/// Nachricht aus dem Popup: `{"type":"fill", username, password, totp, url}`.
fn on_runtime_message(msg: JsValue, _sender: JsValue, respond: js_sys::Function) -> JsValue {
    let m = ext::from_js(&msg);
    if m["type"].as_str() != Some("fill") {
        return JsValue::FALSE;
    }
    // Nur im Frame mit demselben Ursprung wie der Tab, den das Popup geprueft hat
    let here = logic::origin_of(&page_url());
    if here.is_empty() || here != logic::origin_of(m["url"].as_str().unwrap_or("")) {
        return JsValue::FALSE;
    }
    scan();
    let active = doc().active_element().and_then(|a| a.dyn_into::<HtmlInputElement>().ok());
    let g = ST.with(|s| {
        let st = s.borrow();
        active
            .as_ref()
            .and_then(|a| st.groups.iter().find(|g| g.contains(a)).cloned())
            .or_else(|| st.groups.iter().find(|g| g.kind == FormKind::Login && !g.of(FieldKind::CurrentPassword).is_empty()).cloned())
            .or_else(|| st.groups.iter().find(|g| !g.of(FieldKind::CurrentPassword).is_empty()).cloned())
            .or_else(|| st.groups.iter().find(|g| !g.of(FieldKind::Username).is_empty()).cloned())
            .or_else(|| st.groups.iter().find(|g| g.kind == FormKind::Totp).cloned())
    });
    let Some(g) = g else { return JsValue::FALSE };
    fill_group(&g, m["username"].as_str(), m["password"].as_str(), m["totp"].as_str());
    // Fuer den 2FA-Schritt danach merken, welcher Eintrag ausgefuellt wurde
    if let Some(key) = m["key"].as_str().map(String::from) {
        spawn(async move {
            ext::send(json!({"type": "filled", "key": key})).await;
        });
    }
    let _ = respond.call1(&JsValue::NULL, &ext::to_js(&json!({"filled": true})));
    JsValue::FALSE
}

// ---------------------------------------------------------------------------------------------
// Neue Passwoerter merken
// ---------------------------------------------------------------------------------------------

fn on_click(e: &web_sys::Event) {
    let Some(t) = e.target().and_then(|t| t.dyn_into::<Element>().ok()) else { return };
    let Some(btn) = t.closest("button, input[type=submit], input[type=button], [role=button], a").ok().flatten() else { return };
    let text = format!(
        "{} {} {}",
        btn.text_content().unwrap_or_default(),
        attr(&btn, "value"),
        attr(&btn, "aria-label")
    )
    .to_lowercase();
    let is_submit = attr(&btn, "type").eq_ignore_ascii_case("submit");
    const WORDS: &[&str] = &[
        "log in", "login", "sign in", "signin", "anmelden", "einloggen", "weiter", "continue", "next", "submit", "registrier",
        "sign up", "signup", "konto erstellen", "create", "erstellen", "speichern", "save", "passwort ändern", "change password",
        "bestätigen", "confirm", "absenden",
    ];
    if !is_submit && !WORDS.iter().any(|w| text.contains(w)) {
        return;
    }
    let form = btn.closest("form").ok().flatten().and_then(|f| f.dyn_into::<web_sys::HtmlFormElement>().ok());
    scan();
    let g = ST.with(|s| {
        let st = s.borrow();
        match &form {
            Some(f) => st.groups.iter().find(|g| g.form.as_ref() == Some(f)).cloned(),
            None => st
                .groups
                .iter()
                .find(|g| g.fields.iter().any(|f| f.el.type_() == "password" && !f.el.value().is_empty()))
                .cloned()
                .or_else(|| st.groups.iter().find(|g| g.kind == FormKind::Login && g.fields.iter().all(|f| f.kind == FieldKind::Username)).cloned()),
        }
    });
    if let Some(g) = g {
        remember_group(&g);
    }
}

fn remember_group(g: &Group) {
    let username = g.of(FieldKind::Username).first().map(|e| e.value()).unwrap_or_default();
    let password = match g.kind {
        FormKind::Signup | FormKind::ChangePassword => g.of(FieldKind::NewPassword).first().map(|e| e.value()),
        _ => g.of(FieldKind::CurrentPassword).first().map(|e| e.value()).or_else(|| g.of(FieldKind::NewPassword).first().map(|e| e.value())),
    }
    .unwrap_or_default();
    if username.is_empty() && password.is_empty() {
        return;
    }
    let now = ext::now_ms();
    let dup = ST.with(|s| {
        let st = s.borrow();
        st.last_remember.0 == username && st.last_remember.1 == password && now - st.last_remember.2 < 3000.0
    });
    if dup {
        return;
    }
    ST.with(|s| s.borrow_mut().last_remember = (username.clone(), password.clone(), now));
    spawn(async move {
        let r = ext::send(json!({"type": "remember_login", "username": username, "password": password})).await;
        match r["action"].as_str() {
            Some(a @ ("new" | "update")) => show_bar(a, r["host"].as_str().unwrap_or(""), r["username"].as_str().unwrap_or("")),
            _ => {}
        }
    });
}

fn show_bar(action: &str, host: &str, username: &str) {
    let Some((_, _, bar)) = ui() else { return };
    bar.set_inner_html("");
    let row = el("div", "row", None);
    let lg = el("div", "", None);
    lg.set_inner_html(&logo(28));
    row.append_child(&lg).ok();
    let t = el("div", "t", None);
    let title = if action == "update" {
        format!("Passwort für {} aktualisieren?", if username.is_empty() { host } else { username })
    } else {
        format!("Passwort für {host} in nrzPass speichern?")
    };
    t.append_child(&el("div", "title", Some(&title))).ok();
    let sub = if username.is_empty() { host.to_string() } else { format!("{username} · {host}") };
    t.append_child(&el("div", "sub", Some(&sub))).ok();
    row.append_child(&t).ok();
    let x = el("button", "x", Some("×"));
    let _ = x.set_attribute("data-act", "dismiss");
    let _ = x.set_attribute("aria-label", "Schliessen");
    row.append_child(&x).ok();
    bar.append_child(&row).ok();
    let btns = el("div", "btns", None);
    let save = el("button", "btn primary", Some(if action == "update" { "Aktualisieren" } else { "Speichern" }));
    let _ = save.set_attribute("data-act", "save");
    let never = el("button", "btn", Some("Nie für diese Seite"));
    let _ = never.set_attribute("data-act", "never");
    btns.append_child(&save).ok();
    btns.append_child(&never).ok();
    bar.append_child(&btns).ok();
    let _ = bar.class_list().add_1("open");
}

fn hide_bar(after_ms: i32) {
    let cb = Closure::once_into_js(|| {
        ST.with(|s| {
            if let Some(u) = &s.borrow().ui {
                let _ = u.bar.class_list().remove_1("open");
            }
        })
    });
    let _ = win().set_timeout_with_callback_and_timeout_and_arguments_0(cb.unchecked_ref(), after_ms);
}

fn bar_text(title: &str, sub: &str) {
    ST.with(|s| {
        if let Some(u) = &s.borrow().ui {
            u.bar.set_inner_html("");
            let row = el("div", "row", None);
            let lg = el("div", "", None);
            lg.set_inner_html(&logo(28));
            row.append_child(&lg).ok();
            let t = el("div", "t", None);
            t.append_child(&el("div", "title", Some(title))).ok();
            if !sub.is_empty() {
                t.append_child(&el("div", "sub", Some(sub))).ok();
            }
            row.append_child(&t).ok();
            u.bar.append_child(&row).ok();
        }
    });
}

fn bar_action(a: &str) {
    match a {
        "save" => {
            bar_text("Wird verschlüsselt und gespeichert …", "");
            spawn(async {
                let r = ext::send(json!({"type": "save_pending"})).await;
                match r["error"].as_str() {
                    Some(e) => {
                        bar_text("Speichern fehlgeschlagen", e);
                        hide_bar(5000);
                    }
                    None => {
                        bar_text("In nrzPass gespeichert ✓", "Ende-zu-Ende verschlüsselt");
                        hide_bar(1800);
                    }
                }
            });
        }
        "never" => {
            spawn(async {
                let _ = ext::send(json!({"type": "never_pending"})).await;
            });
            hide_bar(0);
        }
        _ => {
            spawn(async {
                let _ = ext::send(json!({"type": "dismiss_pending"})).await;
            });
            hide_bar(0);
        }
    }
}

