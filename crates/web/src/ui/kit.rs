//! Komponenten im Stil von Rust/UI (https://rust-ui.com) fuer Leptos CSR – wie dort ueblich als
//! Quellcode im Projekt. Klassen werden mit `tw_merge` zusammengefuehrt, damit `class=` die
//! Standardwerte ueberschreiben kann.
#![allow(dead_code)]

use leptos::prelude::*;
use tw_merge::*;

#[derive(TwClass, Clone, Copy)]
#[tw(
    class = "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors cursor-pointer select-none focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
)]
pub struct ButtonClass {
    pub variant: ButtonVariant,
    pub size: ButtonSize,
}

#[derive(TwVariant)]
pub enum ButtonVariant {
    #[tw(default, class = "bg-primary text-primary-foreground hover:bg-primary/90")]
    Default,
    #[tw(class = "bg-destructive text-white hover:bg-destructive/90")]
    Destructive,
    #[tw(class = "border border-input bg-transparent hover:bg-accent hover:text-accent-foreground")]
    Outline,
    #[tw(class = "bg-secondary text-secondary-foreground hover:bg-secondary/80")]
    Secondary,
    #[tw(class = "hover:bg-accent hover:text-accent-foreground")]
    Ghost,
    #[tw(class = "text-primary underline-offset-4 hover:underline")]
    Link,
}

#[derive(TwVariant)]
pub enum ButtonSize {
    #[tw(default, class = "h-9 px-4 py-2")]
    Default,
    #[tw(class = "h-8 rounded-md px-3 text-xs")]
    Sm,
    #[tw(class = "h-10 rounded-md px-6")]
    Lg,
    #[tw(class = "size-8")]
    Icon,
}

#[component]
pub fn Button(
    #[prop(optional)] variant: ButtonVariant,
    #[prop(optional)] size: ButtonSize,
    #[prop(into, optional)] class: String,
    #[prop(into, optional, default = "button".into())] r#type: String,
    #[prop(into, optional)] disabled: Signal<bool>,
    #[prop(into, optional)] title: Option<String>,
    #[prop(optional)] on_click: Option<Callback<()>>,
    children: Children,
) -> impl IntoView {
    let class = ButtonClass { variant, size }.with_class(class);
    view! {
        <button data-name="Button" class=class type=r#type disabled=move || disabled.get() title=title.clone()
            aria-label=title
            on:click=move |_| { if let Some(cb) = on_click { cb.run(()) } }>
            {children()}
        </button>
    }
}

const FIELD: &str = "flex w-full rounded-md border border-input bg-transparent px-3 py-1 text-base md:text-sm shadow-xs transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50";

/// Eingabefeld, an ein Signal gebunden.
#[component]
pub fn Input(
    value: RwSignal<String>,
    #[prop(into, optional)] placeholder: String,
    #[prop(into, optional, default = "text".into())] r#type: Signal<String>,
    #[prop(into, optional)] id: Option<String>,
    #[prop(into, optional)] autocomplete: Option<String>,
    #[prop(optional)] autofocus: bool,
    #[prop(optional)] required: bool,
    #[prop(optional)] mono: bool,
    #[prop(into, optional)] class: String,
    #[prop(into, optional)] disabled: Signal<bool>,
    #[prop(optional)] on_enter: Option<Callback<()>>,
) -> impl IntoView {
    let class = tw_merge!(FIELD, "h-10 md:h-9", if mono { "font-mono" } else { "" }, class);
    let node = NodeRef::<leptos::html::Input>::new();
    if autofocus {
        Effect::new(move |_| {
            if let Some(el) = node.get() {
                let _ = el.focus();
            }
        });
    }
    view! {
        <input data-name="Input" node_ref=node class=class type=move || r#type.get() id=id name=autocomplete.clone()
            placeholder=placeholder required=required autocomplete=autocomplete.unwrap_or_else(|| "off".into())
            spellcheck="false" autocapitalize="off" disabled=move || disabled.get()
            prop:value=move || value.get()
            on:input=move |ev| value.set(event_target_value(&ev))
            on:keydown=move |ev| {
                if ev.key() == "Enter" { if let Some(cb) = on_enter { ev.prevent_default(); cb.run(()) } }
            } />
    }
}

#[component]
pub fn Textarea(
    value: RwSignal<String>,
    #[prop(into, optional)] placeholder: String,
    #[prop(optional, default = 4)] rows: u32,
    #[prop(into, optional)] class: String,
    #[prop(optional)] mono: bool,
) -> impl IntoView {
    let class = tw_merge!(FIELD, "min-h-16 py-2", if mono { "font-mono" } else { "" }, class);
    view! {
        <textarea data-name="Textarea" class=class rows=rows placeholder=placeholder spellcheck="false"
            prop:value=move || value.get() on:input=move |ev| value.set(event_target_value(&ev))></textarea>
    }
}

#[component]
pub fn Label(#[prop(into, optional)] r#for: Option<String>, #[prop(into, optional)] class: String, children: Children) -> impl IntoView {
    let class = tw_merge!("text-xs font-medium text-muted-foreground select-none", class);
    view! { <label data-name="Label" class=class for=r#for>{children()}</label> }
}

/// Label + Feld + optionaler Hinweis untereinander.
#[component]
pub fn Field(#[prop(into)] label: String, #[prop(into, optional)] hint: Option<String>, children: Children) -> impl IntoView {
    view! {
        <div data-name="Field" class="grid gap-1.5">
            <Label>{label}</Label>
            {children()}
            {hint.map(|h| view! { <p class="text-xs text-muted-foreground">{h}</p> })}
        </div>
    }
}

macro_rules! clx {
    ($name:ident, $element:ident, $base:expr) => {
        #[component]
        pub fn $name(#[prop(into, optional)] class: String, children: Children) -> impl IntoView {
            let class = tw_merge!($base, class);
            view! { <$element data-name=stringify!($name) class=class>{children()}</$element> }
        }
    };
}

clx!(Card, div, "rounded-xl border border-border bg-card text-card-foreground shadow-sm");
clx!(CardHeader, div, "flex flex-col gap-1.5 p-5");
clx!(CardTitle, h3, "font-semibold leading-none tracking-tight");
clx!(CardDescription, p, "text-sm text-muted-foreground");
clx!(CardContent, div, "p-5 pt-0");
clx!(CardFooter, div, "flex items-center gap-2 p-5 pt-0");

#[derive(TwClass, Clone, Copy)]
#[tw(class = "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium transition-colors w-fit")]
pub struct BadgeClass {
    pub variant: BadgeVariant,
}

#[derive(TwVariant)]
pub enum BadgeVariant {
    #[tw(default, class = "border-transparent bg-primary text-primary-foreground")]
    Default,
    #[tw(class = "border-transparent bg-secondary text-secondary-foreground")]
    Secondary,
    #[tw(class = "text-muted-foreground border-border")]
    Outline,
    #[tw(class = "border-transparent bg-destructive/15 text-destructive")]
    Destructive,
    #[tw(class = "border-transparent bg-success/15 text-success")]
    Success,
    #[tw(class = "border-transparent bg-warning/15 text-warning")]
    Warning,
}

#[component]
pub fn Badge(#[prop(optional)] variant: BadgeVariant, #[prop(into, optional)] class: String, children: Children) -> impl IntoView {
    let class = BadgeClass { variant }.with_class(class);
    view! { <span data-name="Badge" class=class>{children()}</span> }
}

#[component]
pub fn Separator(#[prop(into, optional)] class: String) -> impl IntoView {
    let class = tw_merge!("shrink-0 bg-border h-px w-full", class);
    view! { <div data-name="Separator" role="separator" class=class></div> }
}

/// Schalter (an/aus).
#[component]
pub fn Switch(checked: RwSignal<bool>, #[prop(into, optional)] label: Option<String>) -> impl IntoView {
    view! {
        <button type="button" role="switch" aria-checked=move || checked.get().to_string() aria-label=label.clone()
            class=move || format!("relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border border-transparent transition-colors {}",
                if checked.get() { "bg-primary" } else { "bg-input" })
            on:click=move |_| checked.update(|c| *c = !*c)>
            <span class=move || format!("pointer-events-none block size-4 rounded-full bg-background shadow-lg ring-0 transition-transform {}",
                if checked.get() { "translate-x-4" } else { "translate-x-0.5" })></span>
        </button>
    }
}

/// Auswahlliste (`<select>`) mit (Wert, Beschriftung).
#[component]
pub fn Select(value: RwSignal<String>, options: Signal<Vec<(String, String)>>, #[prop(into, optional)] class: String) -> impl IntoView {
    let class = tw_merge!(FIELD, "h-10 md:h-9 bg-background pr-8", class);
    view! {
        <select data-name="Select" class=class on:change=move |ev| value.set(event_target_value(&ev))
            prop:value=move || value.get()>
            {move || options.get().into_iter().map(|(v, l)| {
                let sel = value.get_untracked() == v;
                view! { <option value=v selected=sel>{l}</option> }
            }).collect_view()}
        </select>
    }
}

#[component]
pub fn Spinner(#[prop(into, optional)] class: String) -> impl IntoView {
    let class = tw_merge!("size-4 animate-spin rounded-full border-2 border-current border-t-transparent", class);
    view! { <span class=class role="status" aria-label="Laedt"></span> }
}

/// Modaler Dialog; auf dem Handy als Blatt von unten.
#[component]
pub fn Dialog(open: RwSignal<bool>, #[prop(into)] title: String, children: ChildrenFn) -> impl IntoView {
    let children = StoredValue::new(children);
    view! {
        <Show when=move || open.get()>
            <div class="fixed inset-0 z-50 flex items-end md:items-center justify-center bg-black/60 fade-in"
                on:click=move |_| open.set(false)>
                <div class="w-full md:max-w-md max-h-[90dvh] overflow-y-auto rounded-t-2xl md:rounded-xl border border-border bg-popover p-5 shadow-2xl sheet-in safe-bottom"
                    role="dialog" aria-modal="true" on:click=|ev| ev.stop_propagation()>
                    <div class="mb-4 flex items-center justify-between gap-2">
                        <h2 class="text-base font-semibold">{title.clone()}</h2>
                        <button class="rounded-md p-1 text-muted-foreground hover:bg-accent hover:text-foreground cursor-pointer"
                            aria-label="Schliessen" on:click=move |_| open.set(false)>
                            <crate::ui::icons::Icon name="x" />
                        </button>
                    </div>
                    {children.with_value(|c| c())}
                </div>
            </div>
        </Show>
    }
}

/// Leerer Zustand mit Symbol.
#[component]
pub fn Empty(#[prop(into)] icon: String, #[prop(into)] title: String, #[prop(into, optional)] text: String) -> impl IntoView {
    view! {
        <div class="flex flex-col items-center justify-center gap-2 py-16 text-center text-muted-foreground">
            <crate::ui::icons::Icon name=icon class="size-10 opacity-40" />
            <p class="text-sm font-medium text-foreground/80">{title}</p>
            <p class="text-xs max-w-64">{text}</p>
        </div>
    }
}

/// Staerkeanzeige fuer Passwoerter (0–4).
#[component]
pub fn StrengthMeter(password: Signal<String>) -> impl IntoView {
    let s = Memo::new(move |_| nrzpass_core::strength::estimate(&password.get()));
    view! {
        <div class="grid gap-1">
            <div class="flex gap-1">
                {(0..4u8).map(|i| view! {
                    <div class=move || {
                        let sc = s.get().score;
                        let color = match sc { 0 | 1 => "bg-destructive", 2 => "bg-warning", _ => "bg-success" };
                        format!("h-1 flex-1 rounded-full transition-colors {}", if password.get().is_empty() || i >= sc.max(1) { "bg-input" } else { color })
                    }></div>
                }).collect_view()}
            </div>
            <p class="text-xs text-muted-foreground">{move || if password.get().is_empty() { String::new() } else {
                let st = s.get(); format!("{} · ca. {:.0} Bit", st.label, st.bits) }}</p>
        </div>
    }
}

/// Passwort mit farbigen Ziffern und Sonderzeichen.
#[component]
pub fn ColoredPassword(#[prop(into)] value: Signal<String>, #[prop(into, optional)] class: String) -> impl IntoView {
    let class = tw_merge!("font-mono break-all", class);
    view! {
        <span class=class>{move || value.get().chars().map(|c| {
            let cls = if c.is_ascii_digit() { "pw-digit" } else if c.is_ascii_alphabetic() || !c.is_ascii() { "" } else { "pw-symbol" };
            view! { <span class=cls>{c.to_string()}</span> }
        }).collect_view()}</span>
    }
}
