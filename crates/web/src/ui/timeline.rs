//! Zeitleiste: wann welche Eintraege angelegt und Passwoerter geaendert wurden.
//! Nur Metadaten (Daten, Namen) – dafuer wird nichts Geheimes entschluesselt.

use crate::state::{app, Entry, View};
use crate::ui::icons::Icon;
use crate::ui::vault::type_icon;
use leptos::prelude::*;
use nrzpass_core::api::cipher_type;

/// Gedaempfte Farben der Linie (wie eine Infografik, passend zum dunklen nrzTheme).
const PALETTE: &[&str] = &["#3f9a8f", "#b0759f", "#d9822b", "#7c3f6e", "#3f6fb5", "#c0473a", "#2f7d6d", "#4fb3c4"];

const MONTHS: [&str; 12] = ["Jan.", "Feb.", "März", "Apr.", "Mai", "Juni", "Juli", "Aug.", "Sep.", "Okt.", "Nov.", "Dez."];

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Created,
    PasswordChanged,
}

#[derive(Clone, PartialEq)]
struct Event {
    /// ISO-Zeitpunkt (UTC, sortierbar)
    when: String,
    kind: Kind,
    entry: Entry,
    /// Ortszeit
    year: i32,
    month: u32,
    day: u32,
    time: String,
}

fn valid(iso: &str) -> bool {
    iso.len() >= 10 && iso.as_bytes()[4] == b'-' && iso[..4].chars().all(|c| c.is_ascii_digit())
}

fn event(when: &str, kind: Kind, entry: &Entry) -> Option<Event> {
    if !valid(when) {
        return None;
    }
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_str(when));
    if d.get_time().is_nan() {
        return None;
    }
    Some(Event {
        when: when.to_string(),
        kind,
        entry: entry.clone(),
        year: d.get_full_year() as i32,
        month: d.get_month() + 1,
        day: d.get_date(),
        time: format!("{:02}:{:02}", d.get_hours(), d.get_minutes()),
    })
}

/// "12. Nov."
fn day_month(month: u32, day: u32) -> String {
    format!("{day}. {}", MONTHS.get(month.saturating_sub(1) as usize).copied().unwrap_or(""))
}

fn events(entries: &[Entry]) -> Vec<Event> {
    let mut out = vec![];
    for e in entries.iter().filter(|e| !e.deleted() && !e.broken) {
        let c = &e.cipher;
        if let Some(ev) = c.creation_date.as_deref().and_then(|d| event(d, Kind::Created, e)) {
            out.push(ev);
        }
        // Passwortwechsel: Verlauf (Zeitpunkt, ab dem das alte Passwort ersetzt war) und letzter Wechsel
        let mut changes: Vec<String> = c.password_history.iter().flatten().map(|h| h.last_used_date.clone()).collect();
        if let Some(d) = c.login.as_ref().and_then(|l| l.password_revision_date.clone()) {
            changes.push(d);
        }
        changes.sort();
        // gleicher Zeitpunkt (auf die Minute) nur einmal
        changes.dedup_by(|a, b| a.get(..16) == b.get(..16));
        out.extend(changes.iter().filter_map(|d| event(d, Kind::PasswordChanged, e)));
    }
    out
}

/// Ein Punkt auf der Linie: alle Ereignisse derselben Art am selben Tag.
#[derive(Clone, PartialEq)]
struct Group {
    kind: Kind,
    year: i32,
    month: u32,
    day: u32,
    time: String,
    entries: Vec<Entry>,
}

fn group(events: Vec<Event>) -> Vec<Group> {
    let mut out: Vec<Group> = vec![];
    for ev in events {
        match out.last_mut() {
            Some(g) if g.kind == ev.kind && (g.year, g.month, g.day) == (ev.year, ev.month, ev.day) => {
                if !g.entries.iter().any(|e| e.key() == ev.entry.key()) {
                    g.entries.push(ev.entry);
                }
            }
            _ => out.push(Group { kind: ev.kind, year: ev.year, month: ev.month, day: ev.day, time: ev.time, entries: vec![ev.entry] }),
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq)]
enum Show {
    All,
    Created,
    Changed,
}

const PAGE: usize = 120;

#[component]
pub fn TimelinePage() -> impl IntoView {
    let app = app();
    let show = RwSignal::new(Show::All);
    let newest_first = RwSignal::new(false);
    let limit = RwSignal::new(PAGE);

    let all = Memo::new(move |_| app.entries.with(|e| events(e)));
    let list = Memo::new(move |_| {
        let mut v: Vec<Event> = all.with(|a| {
            a.iter()
                .filter(|ev| match show.get() {
                    Show::All => true,
                    Show::Created => ev.kind == Kind::Created,
                    Show::Changed => ev.kind == Kind::PasswordChanged,
                })
                .cloned()
                .collect()
        });
        v.sort_by(|a, b| a.when.cmp(&b.when));
        if newest_first.get() {
            v.reverse();
        }
        group(v)
    });
    let stats = Memo::new(move |_| {
        all.with(|a| {
            let created = a.iter().filter(|e| e.kind == Kind::Created).count();
            let changed = a.len() - created;
            let first = a.iter().filter(|e| e.kind == Kind::Created).min_by(|x, y| x.when.cmp(&y.when)).map(|e| (e.year, e.month, e.day));
            (created, changed, first)
        })
    });

    let chip = move |label: &'static str, v: Show| {
        view! {
            <button class=move || format!("rounded-full px-3 py-1 text-xs transition-colors cursor-pointer {}",
                    if show.get() == v { "bg-primary text-primary-foreground" } else { "bg-secondary text-muted-foreground hover:text-foreground" })
                on:click=move |_| { show.set(v); limit.set(PAGE) }>{label}</button>
        }
    };

    view! {
        <div class="grid gap-6">
            // Farbstreifen oben wie bei der Vorlage
            <div class="flex h-1.5 overflow-hidden rounded-full">
                {PALETTE.iter().map(|c| view! { <div class="flex-1" style=format!("background:{c}")></div> }).collect_view()}
            </div>
            <div class="text-center">
                <h1 class="font-serif text-2xl font-bold tracking-tight md:text-3xl">"Die Zeitleiste deines Tresors"</h1>
                <p class="mt-1 text-sm text-muted-foreground">
                    {move || {
                        let (created, changed, first) = stats.get();
                        let since = first.map(|(y, m, d)| format!(" · seit {} {y}", day_month(m, d))).unwrap_or_default();
                        format!("{created} Einträge angelegt · {changed} Passwortwechsel{since}")
                    }}
                </p>
            </div>
            <div class="flex flex-wrap items-center justify-center gap-2">
                {chip("Alles", Show::All)}
                {chip("Angelegt", Show::Created)}
                {chip("Passwort geändert", Show::Changed)}
                <button class="ml-1 flex items-center gap-1 rounded-full bg-secondary px-3 py-1 text-xs text-muted-foreground hover:text-foreground cursor-pointer"
                    on:click=move |_| newest_first.update(|n| *n = !*n)>
                    <Icon name="clock" class="size-3" />{move || if newest_first.get() { "Neueste zuerst" } else { "Älteste zuerst" }}
                </button>
            </div>

            {move || {
                let items = list.get();
                if items.is_empty() {
                    return view! { <p class="py-10 text-center text-sm text-muted-foreground">"Noch nichts auf der Zeitleiste."</p> }.into_any();
                }
                let total = items.len();
                let mut rows = vec![];
                let mut year = None;
                for (i, g) in items.into_iter().take(limit.get()).enumerate() {
                    if year != Some(g.year) {
                        year = Some(g.year);
                        rows.push(view! { <YearRow year=g.year.to_string() index=i /> }.into_any());
                    }
                    rows.push(view! { <EventRow g=g index=i /> }.into_any());
                }
                view! {
                    <div class="pb-4">
                        {rows}
                        // Linienende
                        <div class="grid grid-cols-[2.5rem_1fr] md:grid-cols-[1fr_3.5rem_1fr]">
                            <div class="relative h-6 md:col-start-2">
                                <div class="absolute inset-x-0 top-0 mx-auto h-full w-3 rounded-b-full" style=format!("background:{}", PALETTE[total % PALETTE.len()])></div>
                            </div>
                        </div>
                    </div>
                    {(total > limit.get()).then(|| view! {
                        <div class="text-center">
                            <button class="rounded-full bg-secondary px-4 py-1.5 text-sm hover:bg-accent cursor-pointer" on:click=move |_| limit.update(|l| *l += PAGE)>
                                {format!("Mehr anzeigen ({} weitere)", total - limit.get_untracked())}
                            </button>
                        </div>
                    })}
                }.into_any()
            }}
        </div>
    }
}

/// Jahreszahl als Marke auf der Linie.
#[component]
fn YearRow(year: String, index: usize) -> impl IntoView {
    let line = PALETTE[index % PALETTE.len()];
    let node = PALETTE[(index + 3) % PALETTE.len()];
    view! {
        <div class="grid grid-cols-[2.5rem_1fr] md:grid-cols-[1fr_3.5rem_1fr]">
            <div class="relative h-14 md:col-start-2">
                <div class="absolute inset-y-0 left-1/2 w-3 -translate-x-1/2" style=format!("background:{line}")></div>
                <div class="absolute top-1/2 left-0 z-10 -translate-y-1/2 whitespace-nowrap rounded-lg border-4 border-background px-3 py-0.5 font-serif text-lg font-bold text-white shadow md:left-1/2 md:-translate-x-1/2"
                    style=format!("background:{node}")>{year}</div>
            </div>
        </div>
    }
}

#[component]
fn EventRow(g: Group, index: usize) -> impl IntoView {
    let app = app();
    let line = PALETTE[index % PALETTE.len()];
    let node = PALETTE[(index + 3) % PALETTE.len()];
    let left = index % 2 == 0;
    let n = g.entries.len();
    let first_type = g.entries[0].cipher.cipher_type;
    let same_type = g.entries.iter().all(|e| e.cipher.cipher_type == first_type);
    let (label, icon) = match g.kind {
        Kind::Created => (
            match (n, if same_type { first_type } else { -1 }) {
                (1, cipher_type::CARD) => "Karte gespeichert".to_string(),
                (1, cipher_type::IDENTITY) => "Identität gespeichert".to_string(),
                (1, cipher_type::SECURE_NOTE) => "Notiz angelegt".to_string(),
                (1, _) => "Eintrag angelegt".to_string(),
                (n, _) => format!("{n} Einträge angelegt"),
            },
            if same_type { type_icon(first_type) } else { "vault" },
        ),
        Kind::PasswordChanged => (if n == 1 { "Passwort geändert".to_string() } else { format!("{n} Passwörter geändert") }, "key"),
    };
    let detail = if n == 1 { format!("{label} · {} Uhr", g.time) } else { label };
    let expanded = RwSignal::new(false);
    const SHOWN: usize = 6;
    let entries = StoredValue::new(g.entries);
    let open = move |key: String| {
        app.view.set(View::Vault);
        app.editing.set(None);
        app.selected.set(Some(key));
    };
    // Reihenfolge: Handy immer Linie | Text; ab md abwechselnd links/rechts
    let (text_order, icon_order, align, stub_side) = if left {
        ("order-2 md:order-1", "md:order-3 md:justify-start", "md:text-right md:items-end md:justify-end", "md:right-1/2")
    } else {
        ("order-2 md:order-3", "md:order-1 md:justify-end", "md:text-left md:items-start md:justify-start", "md:left-1/2")
    };
    view! {
        <div class="grid grid-cols-[2.5rem_1fr] md:grid-cols-[1fr_3.5rem_1fr]">
            <div class=format!("flex min-w-0 flex-col items-start py-3 pl-3 md:px-4 {text_order} {align}")>
                <p class="font-serif text-lg font-bold leading-tight">{day_month(g.month, g.day)}</p>
                <div class=format!("flex max-w-full flex-wrap gap-x-1.5 text-sm font-medium {align}")>
                    {move || {
                        let all = entries.get_value();
                        let take = if expanded.get() { all.len() } else { SHOWN };
                        let mut v: Vec<AnyView> = all.iter().take(take).enumerate().map(|(i, e)| {
                            let k = e.key();
                            let sep = (i + 1 < all.len().min(take)).then_some(",");
                            view! { <span class="max-w-full truncate"><button class="hover:underline cursor-pointer" on:click=move |_| open(k.clone())>{e.name()}</button>{sep}</span> }.into_any()
                        }).collect();
                        if all.len() > take {
                            v.push(view! { <button class="text-muted-foreground hover:text-foreground cursor-pointer" on:click=move |_| expanded.set(true)>{format!("+{} weitere", all.len() - take)}</button> }.into_any());
                        }
                        v
                    }}
                </div>
                <p class="text-xs text-muted-foreground">{detail}</p>
            </div>
            <div class="relative order-1 md:order-2">
                <div class="absolute inset-y-0 left-1/2 w-3 -translate-x-1/2" style=format!("background:{line}")></div>
                // Verbindung zur Textseite und Knoten
                <div class=format!("absolute top-1/2 hidden h-1 w-7 -translate-y-1/2 md:block {stub_side}") style=format!("background:{node}")></div>
                <div class="absolute top-1/2 left-1/2 z-10 size-[18px] -translate-x-1/2 -translate-y-1/2 rounded-[5px] border-2 border-background shadow"
                    style=format!("background:{node}")></div>
            </div>
            <div class=format!("hidden items-center px-6 text-muted-foreground md:flex {icon_order}")>
                <Icon name=icon class="size-9 stroke-[1.25]" />
            </div>
        </div>
    }
}
