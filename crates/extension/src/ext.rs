//! Duenne Bruecke zu den Erweiterungs-APIs (`browser` in Firefox, `chrome` in Chromium).
#![allow(dead_code)]

use js_sys::{Array, Function, Object, Promise, Reflect};
use serde_json::Value;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

pub const KEYS: &str = "nrzpass.keys";
pub const INDEX: &str = "nrzpass.index";
pub const SESSION: &str = "nrzpass.session";
pub const NEVER: &str = "nrzpass.never";
pub const LAST_USED: &str = "nrzpass.lastUsed";

pub fn global() -> JsValue {
    js_sys::global().into()
}

pub fn get(obj: &JsValue, key: &str) -> Option<JsValue> {
    Reflect::get(obj, &JsValue::from_str(key)).ok().filter(|v| !v.is_undefined() && !v.is_null())
}

pub fn api() -> JsValue {
    get(&global(), "browser").or_else(|| get(&global(), "chrome")).unwrap_or(JsValue::UNDEFINED)
}

pub fn path(keys: &[&str]) -> Option<JsValue> {
    let mut cur = api();
    for k in keys {
        cur = get(&cur, k)?;
    }
    Some(cur)
}

pub fn call(obj: &JsValue, method: &str, args: &[JsValue]) -> Result<JsValue, JsValue> {
    let f: Function = get(obj, method).ok_or_else(|| JsValue::from_str(&format!("{method} fehlt")))?.dyn_into()?;
    let arr = Array::new();
    for a in args {
        arr.push(a);
    }
    f.apply(obj, &arr)
}

pub async fn promise(v: JsValue) -> Result<JsValue, JsValue> {
    match v.dyn_into::<Promise>() {
        Ok(p) => JsFuture::from(p).await,
        Err(v) => Ok(v),
    }
}

pub fn to_js(v: &Value) -> JsValue {
    js_sys::JSON::parse(&v.to_string()).unwrap_or(JsValue::NULL)
}

pub fn from_js(v: &JsValue) -> Value {
    if v.is_undefined() {
        return Value::Null;
    }
    js_sys::JSON::stringify(v).ok().and_then(|s| s.as_string()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null)
}

pub fn err_str(e: JsValue) -> String {
    e.as_string().or_else(|| get(&e, "message").and_then(|m| m.as_string())).unwrap_or_else(|| "Fehler".into())
}

pub fn obj(pairs: &[(&str, JsValue)]) -> JsValue {
    let o = Object::new();
    for (k, v) in pairs {
        let _ = Reflect::set(&o, &JsValue::from_str(k), v);
    }
    o.into()
}

pub fn now_ms() -> f64 {
    js_sys::Date::now()
}

// ---------------------------------------------------------------------------------------------
// Speicher: Werte sind JSON-Texte, genau wie das Popup (crates/web) sie schreibt.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub enum Area {
    Local,
    Session,
}

fn area(a: Area) -> Option<JsValue> {
    path(&["storage", match a { Area::Local => "local", Area::Session => "session" }])
}

pub async fn store_get(a: Area, key: &str) -> Option<String> {
    let st = area(a)?;
    let res = promise(call(&st, "get", &[JsValue::from_str(key)]).ok()?).await.ok()?;
    get(&res, key).and_then(|v| v.as_string())
}

pub async fn store_set(a: Area, key: &str, value: &str) {
    if let Some(st) = area(a) {
        if let Ok(p) = call(&st, "set", &[obj(&[(key, JsValue::from_str(value))])]) {
            let _ = promise(p).await;
        }
    }
}

pub async fn store_remove(a: Area, keys: &[&str]) {
    if let Some(st) = area(a) {
        let arr = Array::new();
        for k in keys {
            arr.push(&JsValue::from_str(k));
        }
        if let Ok(p) = call(&st, "remove", &[arr.into()]) {
            let _ = promise(p).await;
        }
    }
}

/// Nachricht an den Hintergrund-Dienst (aus dem Inhaltsskript).
#[cfg(feature = "content")]
pub async fn send(msg: Value) -> Value {
    let Some(rt) = path(&["runtime"]) else { return Value::Null };
    match call(&rt, "sendMessage", &[to_js(&msg)]) {
        Ok(p) => promise(p).await.map(|v| from_js(&v)).unwrap_or(Value::Null),
        Err(_) => Value::Null,
    }
}
