//! nrzPass Web-Tresor: Leptos (CSR) mit Komponenten im Stil von Rust/UI.
//! Dieselbe Oberflaeche laeuft als Webseite, in der macOS-App (Tauri) und als Popup der
//! Browser-Erweiterung. Alle Ver- und Entschluesselung passiert hier im Client (WASM).

mod env;
mod net;
mod state;
mod ui;
mod updates;

use leptos::prelude::*;
use leptos::task::spawn_local;
use state::{App, Phase};
use std::time::Duration;
use wasm_bindgen::JsCast;

#[component]
fn Root() -> impl IntoView {
    let app = App::new();
    provide_context(app);
    spawn_local(async move { app.boot().await });

    // Aktivitaet merken (Auto-Sperre) und regelmaessig pruefen
    let doc = env::window().document().unwrap();
    for ev in ["pointerdown", "keydown", "scroll", "touchstart"] {
        let cb = wasm_bindgen::closure::Closure::<dyn Fn()>::new(move || app.last_activity.set_value(env::now_ms()));
        let _ = doc.add_event_listener_with_callback_and_bool(ev, cb.as_ref().unchecked_ref(), true);
        cb.forget();
    }
    let vis = wasm_bindgen::closure::Closure::<dyn Fn()>::new(move || {
        let hidden = env::window().document().map(|d| d.hidden()).unwrap_or(false);
        app.hidden_since.set_value(if hidden { Some(env::now_ms()) } else { None });
        if !hidden {
            app.tick();
        }
    });
    let _ = doc.add_event_listener_with_callback("visibilitychange", vis.as_ref().unchecked_ref());
    vis.forget();
    let _ = set_interval_with_handle(move || app.tick(), Duration::from_secs(10));

    // Tastenkuerzel: "/" oder Cmd/Ctrl+F = Suche, Cmd/Ctrl+L = sperren
    let keys = wasm_bindgen::closure::Closure::<dyn Fn(web_sys::KeyboardEvent)>::new(move |ev: web_sys::KeyboardEvent| {
        if app.phase.get_untracked() != Phase::Unlocked {
            return;
        }
        let meta = ev.meta_key() || ev.ctrl_key();
        let in_field = ev
            .target()
            .and_then(|t| t.dyn_into::<web_sys::Element>().ok())
            .map(|e| matches!(e.tag_name().as_str(), "INPUT" | "TEXTAREA" | "SELECT"))
            .unwrap_or(false);
        if (ev.key() == "/" && !in_field) || (meta && ev.key() == "f") {
            if let Some(el) = env::window().document().and_then(|d| d.get_element_by_id("vault-search")) {
                ev.prevent_default();
                let _ = el.unchecked_into::<web_sys::HtmlElement>().focus();
            }
        } else if meta && ev.key() == "l" {
            ev.prevent_default();
            app.lock();
        } else if ev.key() == "Escape" && !in_field {
            app.editing.set(None);
            app.selected.set(None);
        }
    });
    let _ = doc.add_event_listener_with_callback("keydown", keys.as_ref().unchecked_ref());
    keys.forget();

    if env::is_popup() {
        let _ = doc.body().map(|b| b.class_list().add_1("popup"));
    }

    view! {
        {move || match app.phase.get() {
            Phase::Loading => view! {
                <div class="flex h-dvh items-center justify-center"><ui::kit::Spinner class="size-6 text-muted-foreground" /></div>
            }.into_any(),
            Phase::Setup => view! { <ui::auth::Setup /> }.into_any(),
            Phase::Locked => view! { <ui::auth::Lock /> }.into_any(),
            Phase::Unlocked => view! { <ui::shell::Shell /> }.into_any(),
        }}
        <ui::shell::Toasts />
    }
}

fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(Root);
}
