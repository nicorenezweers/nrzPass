//! Tresor: Liste, Details, Bearbeiten.

use crate::env::{self, Platform};
use crate::state::{app, App, Entry, Filter, PRIMARY};
use crate::ui::icons::Icon;
use crate::ui::kit::*;
use leptos::prelude::*;
use leptos::task::spawn_local;
use nrzpass_core::api::{self, cipher_type, Cipher};
use serde_json::json;
use std::time::Duration;

pub fn type_icon(t: i64) -> &'static str {
    match t {
        cipher_type::LOGIN => "globe",
        cipher_type::CARD => "card",
        cipher_type::IDENTITY => "id",
        cipher_type::SECURE_NOTE => "note",
        _ => "key",
    }
}

pub fn type_name(t: i64) -> &'static str {
    match t {
        cipher_type::LOGIN => "Login",
        cipher_type::CARD => "Karte",
        cipher_type::IDENTITY => "Identität",
        cipher_type::SECURE_NOTE => "Notiz",
        cipher_type::SSH_KEY => "SSH-Schlüssel",
        _ => "Eintrag",
    }
}

/// Eintraege nach Filter und Suche.
pub fn visible_entries(app: App) -> Vec<Entry> {
    let filter = app.filter.get();
    let q = app.search.get().trim().to_lowercase();
    app.entries.with(|all| {
        all.iter()
            .filter(|e| match &filter {
                Filter::Trash => e.deleted(),
                _ => !e.deleted(),
            })
            .filter(|e| match &filter {
                Filter::All | Filter::Trash => true,
                Filter::Favorites => e.cipher.favorite,
                Filter::Type(t) => e.cipher.cipher_type == *t,
                Filter::Folder(acc, f) => &e.account == acc && e.cipher.folder_id == *f,
                Filter::Account(acc) => &e.account == acc,
            })
            .filter(|e| {
                if q.is_empty() {
                    return true;
                }
                // Notizen bleiben verschluesselt und werden daher nicht durchsucht
                let mut hay = format!("{} {}", e.name(), e.subtitle());
                for (u, _) in e.uris() {
                    hay.push(' ');
                    hay.push_str(&u);
                }
                hay.to_lowercase().contains(&q)
            })
            .cloned()
            .collect()
    })
}

/// Eintraege, die zur Seite im aktiven Tab passen (Erweiterung).
pub fn page_matches(app: App) -> Vec<Entry> {
    let Some((_, url)) = app.tab.get() else { return vec![] };
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return vec![];
    }
    app.entries.with(|all| {
        all.iter()
            .filter(|e| !e.deleted() && e.cipher.cipher_type == cipher_type::LOGIN)
            .filter(|e| e.uris().iter().any(|(u, m)| nrzpass_core::url::matches(u, &url, *m)))
            .cloned()
            .collect()
    })
}

fn current_totp(secret: &str) -> Option<(String, u64, u64)> {
    let t = nrzpass_core::totp::Totp::parse(secret)?;
    let now = env::now_secs();
    Some((t.code_at(now), t.remaining(now), t.period))
}

/// Felder im aktiven Tab ausfuellen (Erweiterung).
pub fn fill_entry(app: App, e: &Entry) {
    let Some((tab, url)) = app.tab.get_untracked() else { return };
    let matches = e.uris().iter().any(|(u, m)| nrzpass_core::url::matches(u, &url, *m));
    if !matches {
        let host = nrzpass_core::url::display_name(&url);
        let ok = env::window()
            .confirm_with_message(&format!("„{}“ ist nicht für {host} gespeichert. Trotzdem auf dieser Seite ausfüllen?", e.name()))
            .unwrap_or(false);
        if !ok {
            return;
        }
    }
    // Erst jetzt entschluesseln; der Klartext wird nach dem Senden verworfen und ueberschrieben
    let Some(plain) = app.reveal(e) else { return app.error("Eintrag nicht entschlüsselbar") };
    let l = plain.login.clone().unwrap_or_default();
    let totp = l.totp.as_deref().and_then(current_totp).map(|t| t.0);
    let msg = json!({ "type": "fill", "username": l.username, "password": l.password, "totp": totp, "url": url });
    let mut l = l;
    for v in [&mut l.password, &mut l.totp].into_iter().flatten() {
        zeroize::Zeroize::zeroize(v);
    }
    drop(plain);
    spawn_local(async move {
        match env::send_to_tab(tab, &msg).await {
            Ok(_) => {
                if let Some(code) = totp {
                    let _ = env::copy(&code, 30).await;
                }
                env::close_popup();
            }
            Err(_) => app.error("Auf dieser Seite kann nicht ausgefüllt werden"),
        }
    });
}

// ---------------------------------------------------------------------------------------------
// Liste
// ---------------------------------------------------------------------------------------------

#[component]
pub fn Avatar(name: String, kind: i64) -> impl IntoView {
    let letter = name.chars().find(|c| c.is_alphanumeric()).map(|c| c.to_uppercase().to_string()).unwrap_or_default();
    // Farbe aus dem Namen ableiten (ruhige Grautoene mit leichtem Farbstich)
    let hue = name.bytes().fold(0u32, |a, b| a.wrapping_mul(31).wrapping_add(b as u32)) % 360;
    let style = format!("background: oklch(0.32 0.03 {hue}); color: oklch(0.9 0.04 {hue})");
    view! {
        <div class="grid size-9 shrink-0 place-items-center rounded-lg text-sm font-semibold" style=style>
            {if letter.is_empty() { view! { <Icon name=type_icon(kind) /> }.into_any() } else { letter.into_any() }}
        </div>
    }
}

#[component]
pub fn EntryRow(entry: Entry) -> impl IntoView {
    let app = app();
    let key = entry.key();
    let key2 = key.clone();
    let selected = move || app.selected.get().as_deref() == Some(key2.as_str());
    let label = app.accounts.with_untracked(|a| a.iter().find(|x| x.id == entry.account && x.id != PRIMARY).map(|x| x.label.clone()));
    let login = entry.cipher.login.clone().unwrap_or_default();
    let reprompt = entry.cipher.reprompt == 1;
    let (user, pass) = (login.username.clone(), login.password.clone().filter(|_| !reprompt));
    let e2 = entry.clone();
    let popup = env::is_popup();
    view! {
        <div class=move || format!("group flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-left cursor-pointer transition-colors {}",
                if selected() { "bg-accent" } else { "hover:bg-accent/60" })
            role="button" tabindex="0"
            on:click={ let key = key.clone(); move |_| { app.editing.set(None); app.selected.set(Some(key.clone())) } }
            on:keydown={ let key = key.clone(); move |ev: web_sys::KeyboardEvent| if ev.key() == "Enter" { app.selected.set(Some(key.clone())) } }>
            <Avatar name=entry.name() kind=entry.cipher.cipher_type />
            <div class="min-w-0 flex-1">
                <div class="flex items-center gap-1.5">
                    <span class="truncate text-sm font-medium">{entry.name()}</span>
                    {entry.cipher.favorite.then(|| view! { <Icon name="star" class="size-3 text-warning fill-current" /> })}
                    {entry.broken.then(|| view! { <Icon name="alert" class="size-3 text-destructive" /> })}
                </div>
                <div class="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <span class="truncate">{entry.subtitle()}</span>
                    {label.map(|l| view! { <span class="shrink-0 rounded bg-secondary px-1 text-[10px]">{l}</span> })}
                </div>
            </div>
            <div class=if popup { "flex items-center gap-0.5" } else { "hidden md:flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity" }
                on:click=|ev| ev.stop_propagation()>
                {popup.then(|| (e2.cipher.cipher_type == cipher_type::LOGIN && !reprompt).then(|| {
                    let e = e2.clone();
                    view! { <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon title="Ausfüllen" on_click=Callback::new(move |_| fill_entry(app, &e))><Icon name="fill" /></Button> }
                }))}
                {user.filter(|u| !u.is_empty()).map(|u| view! {
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon title="Benutzername kopieren"
                        on_click=Callback::new(move |_| app.copy("Benutzername", u.clone()))><Icon name="user" /></Button>
                })}
                {pass.filter(|p| !p.is_empty()).map(|p| { let e = e2.clone(); view! {
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon title="Passwort kopieren"
                        on_click=Callback::new(move |_| app.copy_secret("Passwort", &e, &p))><Icon name="key" /></Button>
                }})}
            </div>
        </div>
    }
}

#[component]
pub fn EntryList() -> impl IntoView {
    let app = app();
    let entries = Memo::new(move |_| visible_entries(app));
    let matches = Memo::new(move |_| if env::platform() == Platform::Extension { page_matches(app) } else { vec![] });
    view! {
        <div class="flex flex-col gap-0.5 p-2">
            <Show when=move || !matches.get().is_empty() && app.search.get().is_empty()>
                <p class="px-2.5 pt-1 pb-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">"Für diese Seite"</p>
                <For each=move || matches.get() key=|e| e.key() children=|e| view! { <EntryRow entry=e /> } />
                <Separator class="my-2" />
            </Show>
            <Show when=move || !entries.get().is_empty() fallback=move || view! {
                <Empty icon=if app.filter.get() == Filter::Trash { "trash" } else { "vault" }
                    title=if !app.search.get().is_empty() { "Nichts gefunden" } else if app.filter.get() == Filter::Trash { "Papierkorb ist leer" } else { "Noch keine Einträge" }
                    text=if app.search.get().is_empty() { "Mit + legst du einen Eintrag an oder importierst unter Einstellungen deine Passwörter." } else { "" } />
            }>
                <For each=move || entries.get() key=|e| (e.key(), e.cipher.revision_date.clone(), e.cipher.deleted_date.clone(), e.cipher.favorite) children=|e| view! { <EntryRow entry=e /> } />
            </Show>
        </div>
    }
}

// ---------------------------------------------------------------------------------------------
// Details
// ---------------------------------------------------------------------------------------------

#[component]
/// Zeile mit Kopieren-Knopf. Mit `sealed` ist `value` noch verschluesselt und wird erst beim
/// Anzeigen (fuer 30 s) bzw. Kopieren entschluesselt.
fn CopyRow(
    #[prop(into)] label: String,
    value: String,
    #[prop(optional)] secret: bool,
    #[prop(optional)] mono: bool,
    #[prop(default = None)] sealed: Option<Entry>,
) -> impl IntoView {
    let app = app();
    let is_sealed = sealed.is_some();
    let plain = RwSignal::new(if is_sealed { None } else { Some(value.clone()) });
    let shown = RwSignal::new(!secret);
    // Klartext ueberschreiben und verwerfen (nur bei verschluesselten Werten)
    let wipe = move || {
        if is_sealed {
            plain.try_update(|p| {
                if let Some(x) = p.as_mut() {
                    zeroize::Zeroize::zeroize(x);
                }
                *p = None;
            });
        }
    };
    let (sealed2, enc) = (sealed.clone(), value.clone());
    let toggle = move |_| {
        if shown.get_untracked() {
            shown.set(false);
            wipe();
            return;
        }
        if let Some(e) = &sealed2 {
            match app.open(e, &enc) {
                Some(p) => plain.set(Some(p.to_string())),
                None => return app.error("Nicht entschlüsselbar"),
            }
            // Nach 30 s wieder verbergen und aus dem Speicher werfen
            spawn_local(async move {
                gloo_timers::future::TimeoutFuture::new(30_000).await;
                if shown.try_get_untracked() == Some(true) {
                    shown.set(false);
                    wipe();
                }
            });
        }
        shown.set(true);
    };
    on_cleanup(wipe);
    let l = label.clone();
    view! {
        <div class="group flex items-center gap-2 px-4 py-2.5">
            <div class="min-w-0 flex-1">
                <p class="text-[11px] text-muted-foreground">{label.clone()}</p>
                <div class="text-sm break-all">
                    {move || match (shown.get(), plain.get()) {
                        (true, Some(v)) => if secret { view! { <ColoredPassword value=v /> }.into_any() }
                            else { view! { <span class=if mono { "font-mono" } else { "" }>{v}</span> }.into_any() },
                        _ => view! { <span class="font-mono tracking-widest text-muted-foreground">"••••••••••"</span> }.into_any(),
                    }}
                </div>
            </div>
            {secret.then(|| view! {
                <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon title="Anzeigen" on_click=Callback::new(toggle)>
                    {move || view! { <Icon name=if shown.get() { "eye-off" } else { "eye" } /> }}
                </Button>
            })}
            <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon title=format!("{l} kopieren")
                on_click=Callback::new(move |_| match &sealed {
                    Some(e) => app.copy_secret(&l, e, &value),
                    None => app.copy(&l, value.clone()),
                })><Icon name="copy" /></Button>
        </div>
    }
}

#[component]
/// `secret` ist der verschluesselte TOTP-Schluessel; er wird nur fuer jede Code-Berechnung kurz
/// entschluesselt und sofort wieder ueberschrieben.
fn TotpRow(entry: Entry, secret: String) -> impl IntoView {
    let app = app();
    let code = move || app.open(&entry, &secret).and_then(|k| current_totp(&k));
    let state = RwSignal::new(code());
    if let Ok(h) = set_interval_with_handle(move || state.set(code()), Duration::from_millis(1000)) {
        on_cleanup(move || h.clear());
    }
    view! {
        {move || match state.get() {
            None => view! { <div class="px-4 py-2.5 text-xs text-destructive">"TOTP-Schlüssel ungültig"</div> }.into_any(),
            Some((code, rem, period)) => {
                let c2 = code.clone();
                let display = if code.len() == 6 { format!("{} {}", &code[..3], &code[3..]) } else { code.clone() };
                let dash = 2.0 * std::f64::consts::PI * 9.0;
                let offset = dash * (1.0 - rem as f64 / period as f64);
                view! {
                    <div class="flex items-center gap-2 px-4 py-2.5">
                        <div class="min-w-0 flex-1">
                            <p class="text-[11px] text-muted-foreground">"Einmalcode (TOTP)"</p>
                            <p class=format!("font-mono text-lg tracking-wider {}", if rem <= 5 { "text-destructive" } else { "" })>{display}</p>
                        </div>
                        <svg viewBox="0 0 24 24" class="size-6 -rotate-90">
                            <circle cx="12" cy="12" r="9" fill="none" stroke-width="3" class="ring-track" />
                            <circle cx="12" cy="12" r="9" fill="none" stroke-width="3" class="ring-value"
                                stroke-dasharray=dash.to_string() stroke-dashoffset=offset.to_string() />
                        </svg>
                        <span class="w-5 text-xs tabular-nums text-muted-foreground">{rem}</span>
                        <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon title="Code kopieren"
                            on_click=Callback::new(move |_| app.copy("Code", c2.clone()))><Icon name="copy" /></Button>
                    </div>
                }.into_any()
            }
        }}
    }
}

#[component]
fn Section(#[prop(into)] title: String, children: Children) -> impl IntoView {
    view! {
        <div class="grid gap-1.5">
            <p class="px-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">{title}</p>
            <div class="divide-y divide-border rounded-xl border border-border bg-card">{children()}</div>
        </div>
    }
}

/// Zeilen; geheime Werte (`true`) sind noch verschluesselt und werden erst bei Bedarf geoeffnet.
fn opt_rows(e: &Entry, rows: Vec<(&'static str, Option<String>, bool)>) -> impl IntoView {
    rows.into_iter()
        .filter_map(|(l, v, s)| {
            v.filter(|v| !v.is_empty()).map(|v| {
                let sealed = s.then(|| e.clone());
                view! { <CopyRow label=l value=v secret=s sealed=sealed /> }
            })
        })
        .collect_view()
}

#[component]
pub fn EntryDetail(key: String) -> impl IntoView {
    let app = app();
    let k = key.clone();
    let entry = Memo::new(move |_| app.entries.with(|e| e.iter().find(|x| x.key() == k).cloned()));
    let busy = RwSignal::new(false);
    let confirm_delete = RwSignal::new(false);
    // "Master-Passwort vor dem Anzeigen abfragen"
    let verified = RwSignal::new(false);
    let reprompt_pw = RwSignal::new(String::new());
    let check_reprompt = move || match app.verify_master(&reprompt_pw.get_untracked()) {
        Ok(_) => {
            reprompt_pw.set(String::new());
            verified.set(true);
        }
        Err(e) => app.error(e),
    };

    let act = move |what: &'static str| {
        let Some(e) = entry.get_untracked() else { return };
        let key = e.key();
        busy.set(true);
        spawn_local(async move {
            let r = match what {
                "trash" => app.delete_entry(&key, false).await.map(|_| "In den Papierkorb verschoben".to_string()),
                "delete" => app.delete_entry(&key, true).await.map(|_| "Endgültig gelöscht".to_string()),
                "restore" => app.restore_entry(&key).await.map(|_| "Wiederhergestellt".to_string()),
                "copy" => app.copy_to(&key, PRIMARY).await.map(|k| {
                    app.selected.set(Some(k));
                    "In nrzPass übernommen".to_string()
                }),
                "favorite" => {
                    let Some(plain) = app.reveal(&e) else { return app.error("Eintrag nicht entschlüsselbar") };
                    let mut c = plain.into_inner();
                    c.favorite = !c.favorite;
                    app.save_entry(&e.account, c).await.map(|_| String::new())
                }
                _ => Ok(String::new()),
            };
            busy.set(false);
            match r {
                Ok(m) if !m.is_empty() => app.toast(m),
                Ok(_) => {}
                Err(e) => app.error(e),
            }
        });
    };

    view! {
        {move || entry.get().map(|e| {
            let c = e.cipher.clone();
            let login = c.login.clone().unwrap_or_default();
            let deleted = e.deleted();
            let linked = e.account != PRIMARY;
            let acc_label = app.accounts.with_untracked(|a| a.iter().find(|x| x.id == e.account).map(|x| x.label.clone())).unwrap_or_default();
            let folder = c.folder_id.as_ref().and_then(|f| app.folders.with_untracked(|fs| fs.iter().find(|x| &x.folder.id == f && x.account == e.account).map(|x| x.folder.name.clone())));
            let uris = e.uris();
            // Je eine Kopie fuer die einzelnen Abschnitte (die Ansicht nimmt sie in Closures mit)
            let (e_login, e_fill, e_card, e_ident, e_notes, e_fields, e_hist) = (e.clone(), e.clone(), e.clone(), e.clone(), e.clone(), e.clone(), e.clone());
            view! {
                <div class="mx-auto grid w-full max-w-2xl gap-5 p-4 md:p-6">
                    <div class="flex items-start gap-3">
                        <Avatar name=e.name() kind=c.cipher_type />
                        <div class="min-w-0 flex-1">
                            <h2 class="truncate text-lg font-semibold leading-tight">{e.name()}</h2>
                            <div class="mt-1 flex flex-wrap items-center gap-1.5">
                                <Badge variant=BadgeVariant::Secondary>{type_name(c.cipher_type)}</Badge>
                                <Badge variant=BadgeVariant::Outline>{acc_label}</Badge>
                                {folder.map(|f| view! { <Badge variant=BadgeVariant::Outline><Icon name="folder" class="size-3" />{f}</Badge> })}
                                {c.organization_id.is_some().then(|| view! { <Badge variant=BadgeVariant::Outline>"Organisation"</Badge> })}
                                {deleted.then(|| view! { <Badge variant=BadgeVariant::Destructive>"Im Papierkorb"</Badge> })}
                            </div>
                        </div>
                        {(!deleted && c.edit && !e.broken).then(|| view! {
                            <div class="flex gap-1">
                                <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon title="Favorit" disabled=busy on_click=Callback::new(move |_| act("favorite"))>
                                    <Icon name="star" class=if c.favorite { "size-4 text-warning fill-current" } else { "size-4" } />
                                </Button>
                                <Button variant=ButtonVariant::Outline size=ButtonSize::Sm on_click=Callback::new({ let k = e.key(); move |_| app.editing.set(Some(Some(k.clone()))) })>
                                    <Icon name="pencil" />"Bearbeiten"
                                </Button>
                            </div>
                        })}
                    </div>

                    {e.broken.then(|| view! {
                        <p class="rounded-lg bg-destructive/10 p-3 text-sm text-destructive">"Dieser Eintrag konnte nicht entschlüsselt werden (fehlender Organisationsschlüssel oder beschädigte Daten)."</p>
                    })}

                    {(c.reprompt == 1 && !verified.get()).then(|| view! {
                        <Card class="grid gap-3 p-4">
                            <p class="flex items-center gap-2 text-sm"><Icon name="lock" />"Für diesen Eintrag ist das Master-Passwort nötig."</p>
                            <div class="flex gap-2">
                                <Input value=reprompt_pw r#type="password" autocomplete="current-password" autofocus=true on_enter=Callback::new(move |_| check_reprompt()) />
                                <Button on_click=Callback::new(move |_| check_reprompt())>"Anzeigen"</Button>
                            </div>
                        </Card>
                    })}
                    {(c.reprompt != 1 || verified.get()).then(|| view! {
                    {(c.cipher_type == cipher_type::LOGIN).then(|| {
                        let launch = uris.iter().find_map(|(u, _)| nrzpass_core::url::launch_url(u));
                        view! {
                            <Section title="Anmeldedaten">
                                {opt_rows(&e_login, vec![("Benutzername", login.username.clone(), false), ("Passwort", login.password.clone(), true)])}
                                {login.totp.clone().filter(|t| !t.is_empty()).map(|t| { let e = e_login.clone(); view! { <TotpRow entry=e secret=t /> } })}
                            </Section>
                            {(!uris.is_empty()).then(|| view! {
                                <Section title="Webseiten">
                                    {uris.iter().map(|(u, _)| {
                                        let (u1, u2) = (u.clone(), u.clone());
                                        let l = nrzpass_core::url::launch_url(u);
                                        view! {
                                            <div class="flex items-center gap-2 px-4 py-2.5">
                                                <span class="min-w-0 flex-1 truncate text-sm">{u1}</span>
                                                {l.map(|l| view! { <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon title="Öffnen" on_click=Callback::new(move |_| env::open_url(&l))><Icon name="external" /></Button> })}
                                                <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon title="Adresse kopieren" on_click=Callback::new(move |_| app.copy("Adresse", u2.clone()))><Icon name="copy" /></Button>
                                            </div>
                                        }
                                    }).collect_view()}
                                </Section>
                            })}
                            {(env::is_popup() && !deleted).then(|| { let e = e_fill.clone(); view! {
                                <Button class="w-full" on_click=Callback::new(move |_| fill_entry(app, &e))><Icon name="fill" />"Auf dieser Seite ausfüllen"</Button>
                            }})}
                            {(!env::is_popup()).then(|| launch.map(|l| view! {
                                <Button variant=ButtonVariant::Secondary class="w-full md:w-fit" on_click=Callback::new(move |_| env::open_url(&l))><Icon name="external" />"Webseite öffnen"</Button>
                            }))}
                        }
                    })}

                    {c.card.clone().map(|k| view! {
                        <Section title="Karte">
                            {opt_rows(&e_card, vec![
                                ("Karteninhaber", k.cardholder_name, false), ("Marke", k.brand, false), ("Nummer", k.number, true),
                                ("Ablauf", Some(format!("{}/{}", k.exp_month.unwrap_or_default(), k.exp_year.unwrap_or_default())).filter(|s| s != "/"), false),
                                ("Prüfnummer", k.code, true),
                            ])}
                        </Section>
                    })}

                    {c.identity.clone().map(|i| view! {
                        <Section title="Identität">
                            {opt_rows(&e_ident, vec![
                                ("Anrede", i.title, false), ("Vorname", i.first_name, false), ("Nachname", i.last_name, false),
                                ("Benutzername", i.username, false), ("Firma", i.company, false), ("E-Mail", i.email, false), ("Telefon", i.phone, false),
                                ("Adresse", Some([i.address1, i.address2, i.address3].into_iter().flatten().collect::<Vec<_>>().join(", ")), false),
                                ("PLZ / Ort", Some(format!("{} {}", i.postal_code.unwrap_or_default(), i.city.unwrap_or_default()).trim().to_string()), false),
                                ("Kanton / Land", Some(format!("{} {}", i.state.unwrap_or_default(), i.country.unwrap_or_default()).trim().to_string()), false),
                                ("AHV / SSN", i.ssn, true), ("Pass", i.passport_number, true), ("Führerschein", i.license_number, true),
                            ])}
                        </Section>
                    })}

                    {c.notes.clone().filter(|n| !n.is_empty()).and_then(|n| app.open(&e_notes, &n)).map(|n| {
                        // Notizen werden nur entschluesselt, solange der Eintrag offen ist
                        let n2 = n.clone();
                        let n = n.to_string();
                        view! {
                            <Section title="Notizen">
                                <div class="flex gap-2 px-4 py-3">
                                    <p class="flex-1 whitespace-pre-wrap break-words text-sm">{n}</p>
                                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon title="Notiz kopieren" on_click=Callback::new(move |_| app.copy("Notiz", n2.to_string()))><Icon name="copy" /></Button>
                                </div>
                            </Section>
                        }
                    })}

                    {c.fields.clone().filter(|f| !f.is_empty()).map(|fs| view! {
                        <Section title="Eigene Felder">
                            {fs.into_iter().map(|f| {
                                let name = f.name.unwrap_or_default();
                                match f.field_type {
                                    2 => view! { <div class="flex items-center justify-between px-4 py-2.5 text-sm"><span>{name}</span><span>{if f.value.as_deref() == Some("true") { "Ja" } else { "Nein" }}</span></div> }.into_any(),
                                    t => {
                                        let sealed = (t == nrzpass_core::vault::FIELD_HIDDEN).then(|| e_fields.clone());
                                        view! { <CopyRow label=name value=f.value.unwrap_or_default() secret={t == 1} sealed=sealed /> }.into_any()
                                    }
                                }
                            }).collect_view()}
                        </Section>
                    })}

                    {c.password_history.clone().filter(|h| !h.is_empty()).map(|h| view! {
                        <Section title="Frühere Passwörter">
                            {h.into_iter().map(|p| view! { <CopyRow label=format!("bis {}", env::format_date(&p.last_used_date)) value=p.password secret=true sealed=Some(e_hist.clone()) /> }).collect_view()}
                        </Section>
                    })}

                    })}

                    {(c.cipher_type == cipher_type::SSH_KEY).then(|| view! {
                        <p class="rounded-lg bg-secondary p-3 text-sm text-muted-foreground">"SSH-Schlüssel werden angezeigt, aber noch nicht bearbeitet."</p>
                    })}

                    <div class="flex flex-wrap gap-2">
                        {(linked && !deleted && !e.broken).then(|| view! {
                            <Button variant=ButtonVariant::Secondary disabled=busy on_click=Callback::new(move |_| act("copy"))><Icon name="download" />"In nrzPass übernehmen"</Button>
                        })}
                        {deleted.then(|| view! {
                            <Button variant=ButtonVariant::Secondary disabled=busy on_click=Callback::new(move |_| act("restore"))><Icon name="refresh" />"Wiederherstellen"</Button>
                        })}
                        {c.edit.then(|| view! {
                            <Button variant=ButtonVariant::Ghost class="text-destructive hover:text-destructive" disabled=busy
                                on_click=Callback::new(move |_| if deleted { confirm_delete.set(true) } else { act("trash") })>
                                <Icon name="trash" />{if deleted { "Endgültig löschen" } else { "Löschen" }}
                            </Button>
                        })}
                    </div>

                    <p class="text-[11px] text-muted-foreground">
                        {c.revision_date.clone().map(|d| format!("Geändert {}", env::format_date(&d)))}
                        {c.creation_date.clone().map(|d| format!(" · Erstellt {}", env::format_date(&d)))}
                    </p>

                    <Dialog open=confirm_delete title="Endgültig löschen?">
                        <p class="mb-4 text-sm text-muted-foreground">"Der Eintrag wird unwiderruflich gelöscht."</p>
                        <div class="flex justify-end gap-2">
                            <Button variant=ButtonVariant::Outline on_click=Callback::new(move |_| confirm_delete.set(false))>"Abbrechen"</Button>
                            <Button variant=ButtonVariant::Destructive on_click=Callback::new(move |_| { confirm_delete.set(false); act("delete") })>"Löschen"</Button>
                        </div>
                    </Dialog>
                </div>
            }
        })}
    }
}

// ---------------------------------------------------------------------------------------------
// Bearbeiten
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct UriRow {
    id: u32,
    uri: RwSignal<String>,
    match_type: RwSignal<String>,
}

#[derive(Clone, Copy)]
struct FieldRow {
    id: u32,
    name: RwSignal<String>,
    value: RwSignal<String>,
    kind: i64,
}

fn s(v: &Option<String>) -> RwSignal<String> {
    RwSignal::new(v.clone().unwrap_or_default())
}

fn o(v: RwSignal<String>) -> Option<String> {
    let t = v.get_untracked();
    if t.trim().is_empty() { None } else { Some(t) }
}

#[component]
pub fn EntryEditor(key: Option<String>) -> impl IntoView {
    let app = app();
    let existing = key.as_ref().and_then(|k| app.entry(k));
    let is_new = existing.is_none();
    // Zum Bearbeiten wird der Eintrag vollstaendig entschluesselt (nur solange der Editor offen ist)
    let base: Cipher = existing.as_ref().and_then(|e| app.reveal(e)).map(|r| r.into_inner()).unwrap_or_else(|| {
        let mut c = Cipher { cipher_type: cipher_type::LOGIN, edit: true, ..Default::default() };
        // Erweiterung: Adresse des aktiven Tabs vorschlagen
        if let Some((_, url)) = app.tab.get_untracked().filter(|(_, u)| u.starts_with("http")) {
            c.name = Some(nrzpass_core::url::display_name(&url));
            let origin = url.split('/').take(3).collect::<Vec<_>>().join("/");
            c.login = Some(api::CipherLogin { uris: Some(vec![api::LoginUri { uri: Some(origin), ..Default::default() }]), ..Default::default() });
        }
        if let Filter::Type(t) = app.filter.get_untracked() {
            c.cipher_type = t;
        }
        c
    });
    let account = RwSignal::new(existing.as_ref().map(|e| e.account.clone()).unwrap_or_else(|| match app.filter.get_untracked() {
        Filter::Account(a) | Filter::Folder(a, _) => a,
        _ => PRIMARY.to_string(),
    }));
    let kind = RwSignal::new(base.cipher_type.to_string());
    let name = s(&base.name);
    let notes = s(&base.notes);
    let folder = RwSignal::new(base.folder_id.clone().unwrap_or_default());
    let favorite = RwSignal::new(base.favorite);
    let reprompt = RwSignal::new(base.reprompt == 1);
    let login = base.login.clone().unwrap_or_default();
    let username = s(&login.username);
    let password = s(&login.password);
    let totp = s(&login.totp);
    let show_pw = RwSignal::new(is_new);
    let next_id = StoredValue::new(100u32);
    let uris = RwSignal::new(
        login
            .uris
            .clone()
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(i, u)| UriRow { id: i as u32, uri: s(&u.uri), match_type: RwSignal::new(u.match_type.map(|m| m.to_string()).unwrap_or_default()) })
            .collect::<Vec<_>>(),
    );
    let card = base.card.clone().unwrap_or_default();
    let (c_holder, c_brand, c_number, c_month, c_year, c_code) =
        (s(&card.cardholder_name), s(&card.brand), s(&card.number), s(&card.exp_month), s(&card.exp_year), s(&card.code));
    let id = base.identity.clone().unwrap_or_default();
    let (i_title, i_first, i_last, i_user, i_company, i_email, i_phone, i_addr1, i_addr2, i_zip, i_city, i_state, i_country, i_ssn, i_passport, i_license) = (
        s(&id.title), s(&id.first_name), s(&id.last_name), s(&id.username), s(&id.company), s(&id.email), s(&id.phone),
        s(&id.address1), s(&id.address2), s(&id.postal_code), s(&id.city), s(&id.state), s(&id.country), s(&id.ssn),
        s(&id.passport_number), s(&id.license_number),
    );
    let fields = RwSignal::new(
        base.fields
            .clone()
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(i, f)| FieldRow { id: i as u32, name: s(&f.name), value: s(&f.value), kind: f.field_type })
            .collect::<Vec<_>>(),
    );
    let busy = RwSignal::new(false);
    let base = StoredValue::new(base);

    let account_options = Signal::derive(move || app.accounts.with(|a| a.iter().map(|x| (x.id.clone(), x.label.clone())).collect()));
    let folder_options = Signal::derive(move || {
        let acc = account.get();
        let mut v = vec![(String::new(), "Kein Ordner".to_string())];
        v.extend(app.folders.with(|f| f.iter().filter(|x| x.account == acc).map(|x| (x.folder.id.clone(), x.folder.name.clone())).collect::<Vec<_>>()));
        v
    });
    let type_options = Signal::derive(|| {
        [cipher_type::LOGIN, cipher_type::CARD, cipher_type::IDENTITY, cipher_type::SECURE_NOTE]
            .iter()
            .map(|t| (t.to_string(), type_name(*t).to_string()))
            .collect()
    });
    let match_options = Signal::derive(|| {
        vec![
            (String::new(), "Standard (Domain)".to_string()),
            ("1".into(), "Host".into()),
            ("2".into(), "Beginnt mit".into()),
            ("3".into(), "Exakt".into()),
            ("5".into(), "Nie".into()),
        ]
    });

    let generate = move || {
        let st = app.settings.get_untracked();
        password.set(if st.use_passphrase {
            nrzpass_core::generator::passphrase(&st.passphrase)
        } else {
            nrzpass_core::generator::password(&st.generator)
        });
        show_pw.set(true);
    };

    let save = move || {
        if name.get_untracked().trim().is_empty() {
            app.error("Bitte einen Namen eingeben");
            return;
        }
        let mut c = base.get_value();
        let t: i64 = kind.get_untracked().parse().unwrap_or(1);
        c.cipher_type = t;
        c.name = o(name);
        c.notes = o(notes);
        c.favorite = favorite.get_untracked();
        c.reprompt = if reprompt.get_untracked() { 1 } else { 0 };
        c.folder_id = Some(folder.get_untracked()).filter(|f| !f.is_empty());
        c.login = None;
        c.card = None;
        c.identity = None;
        c.secure_note = None;
        match t {
            cipher_type::LOGIN => {
                let mut l = base.get_value().login.unwrap_or_default();
                l.username = o(username);
                l.totp = o(totp);
                let new_uris: Vec<api::LoginUri> = uris
                    .get_untracked()
                    .iter()
                    .filter_map(|u| {
                        let uri = o(u.uri)?;
                        let old = l.uris.as_ref().and_then(|v| v.iter().find(|x| x.uri.as_deref() == Some(uri.as_str())).cloned());
                        Some(api::LoginUri { uri: Some(uri), match_type: u.match_type.get_untracked().parse().ok(), extra: old.map(|o| o.extra).unwrap_or_default() })
                    })
                    .collect();
                l.uris = if new_uris.is_empty() { None } else { Some(new_uris) };
                c.login = Some(l);
                match o(password) {
                    Some(p) => nrzpass_core::vault::set_password(&mut c, &p, &env::now_iso()),
                    None => {
                        if let Some(l) = c.login.as_mut() {
                            l.password = None;
                        }
                    }
                }
            }
            cipher_type::CARD => {
                c.card = Some(api::CipherCard {
                    cardholder_name: o(c_holder),
                    brand: o(c_brand),
                    number: o(c_number).map(|n| n.replace(' ', "")),
                    exp_month: o(c_month),
                    exp_year: o(c_year),
                    code: o(c_code),
                })
            }
            cipher_type::IDENTITY => {
                c.identity = Some(api::CipherIdentity {
                    title: o(i_title), first_name: o(i_first), last_name: o(i_last), username: o(i_user), company: o(i_company),
                    email: o(i_email), phone: o(i_phone), address1: o(i_addr1), address2: o(i_addr2), postal_code: o(i_zip),
                    city: o(i_city), state: o(i_state), country: o(i_country), ssn: o(i_ssn), passport_number: o(i_passport),
                    license_number: o(i_license), ..Default::default()
                })
            }
            _ => c.secure_note = Some(api::SecureNote { note_type: 0 }),
        }
        let f: Vec<api::CipherField> = fields
            .get_untracked()
            .iter()
            .filter(|f| !f.name.get_untracked().trim().is_empty())
            .map(|f| api::CipherField { name: o(f.name), value: o(f.value), field_type: f.kind, linked_id: None })
            .collect();
        c.fields = if f.is_empty() { None } else { Some(f) };
        let acc = account.get_untracked();
        busy.set(true);
        spawn_local(async move {
            let r = app.save_entry(&acc, c).await;
            busy.set(false);
            match r {
                Ok(k) => {
                    app.editing.set(None);
                    app.selected.set(Some(k));
                    app.toast("Gespeichert");
                }
                Err(e) => app.error(e),
            }
        });
    };

    view! {
        <div class="mx-auto grid w-full max-w-2xl gap-5 p-4 md:p-6">
            <div class="sticky top-0 z-10 -mx-4 -mt-4 flex items-center justify-between gap-2 border-b border-border bg-background/95 px-4 py-2.5 backdrop-blur md:static md:m-0 md:border-0 md:bg-transparent md:p-0 md:backdrop-blur-none">
                <h2 class="truncate text-base font-semibold md:text-lg">{if is_new { "Neuer Eintrag" } else { "Eintrag bearbeiten" }}</h2>
                <div class="flex gap-2">
                    <Button variant=ButtonVariant::Ghost on_click=Callback::new(move |_| app.editing.set(None))>"Abbrechen"</Button>
                    <Button disabled=busy on_click=Callback::new(move |_| save())>
                        <Show when=move || busy.get() fallback=|| view! { <Icon name="check" /> }><Spinner /></Show>"Speichern"
                    </Button>
                </div>
            </div>

            <Card class="grid gap-4 p-4">
                <div class="grid gap-4 md:grid-cols-2">
                    {is_new.then(|| view! {
                        <Field label="Art"><Select value=kind options=type_options /></Field>
                    })}
                    <Show when=move || is_new && app.accounts.with(|a| a.len() > 1)>
                        <Field label="Tresor"><Select value=account options=account_options /></Field>
                    </Show>
                    <Field label="Name"><Input value=name placeholder="z. B. GitHub" autofocus=is_new /></Field>
                    <Field label="Ordner"><Select value=folder options=folder_options /></Field>
                </div>
                <div class="flex flex-wrap items-center gap-x-6 gap-y-3">
                    <label class="flex items-center gap-2 text-sm"><Switch checked=favorite label="Favorit" />"Favorit"</label>
                    <label class="flex items-center gap-2 text-sm"><Switch checked=reprompt label="Master-Passwort abfragen" />"Master-Passwort vor dem Anzeigen abfragen"</label>
                </div>
            </Card>

            <Show when=move || kind.get() == "1">
                <Card class="grid gap-4 p-4">
                    <Field label="Benutzername / E-Mail"><Input value=username autocomplete="off" /></Field>
                    <Field label="Passwort">
                        <div class="flex gap-2">
                            <Input value=password mono=true r#type=Signal::derive(move || if show_pw.get() { "text".to_string() } else { "password".to_string() }) />
                            <Button variant=ButtonVariant::Outline size=ButtonSize::Icon class="size-10 md:size-9 shrink-0" title="Anzeigen" on_click=Callback::new(move |_| show_pw.update(|s| *s = !*s))>
                                {move || view! { <Icon name=if show_pw.get() { "eye-off" } else { "eye" } /> }}
                            </Button>
                            <Button variant=ButtonVariant::Outline size=ButtonSize::Icon class="size-10 md:size-9 shrink-0" title="Starkes Passwort erzeugen" on_click=Callback::new(move |_| generate())>
                                <Icon name="wand" />
                            </Button>
                        </div>
                        <StrengthMeter password=password.into() />
                    </Field>
                    <Field label="Authenticator-Schlüssel (TOTP)" hint="Base32-Schlüssel oder otpauth://-Link – nrzPass erzeugt dann die Einmalcodes.">
                        <Input value=totp mono=true placeholder="JBSWY3DPEHPK3PXP" />
                    </Field>
                    <div class="grid gap-2">
                        <Label>"Webseiten"</Label>
                        <For each=move || uris.get() key=|u| u.id children=move |u| view! {
                            <div class="flex gap-2">
                                <Input value=u.uri placeholder="https://example.ch" />
                                <Select value=u.match_type options=match_options class="w-36 shrink-0" />
                                <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon class="size-10 md:size-9 shrink-0" title="Entfernen"
                                    on_click=Callback::new(move |_| uris.update(|v| v.retain(|x| x.id != u.id)))><Icon name="x" /></Button>
                            </div>
                        } />
                        <Button variant=ButtonVariant::Ghost size=ButtonSize::Sm on_click=Callback::new(move |_| {
                            let id = next_id.get_value(); next_id.set_value(id + 1);
                            uris.update(|v| v.push(UriRow { id, uri: RwSignal::new(String::new()), match_type: RwSignal::new(String::new()) }));
                        })><Icon name="plus" />"Webseite hinzufügen"</Button>
                    </div>
                </Card>
            </Show>

            <Show when=move || kind.get() == "3">
                <Card class="grid gap-4 p-4 md:grid-cols-2">
                    <Field label="Karteninhaber"><Input value=c_holder /></Field>
                    <Field label="Marke"><Input value=c_brand placeholder="Visa, Mastercard …" /></Field>
                    <Field label="Kartennummer"><Input value=c_number mono=true /></Field>
                    <div class="grid grid-cols-3 gap-2">
                        <Field label="Monat"><Input value=c_month placeholder="MM" /></Field>
                        <Field label="Jahr"><Input value=c_year placeholder="JJJJ" /></Field>
                        <Field label="CVC"><Input value=c_code r#type="password" /></Field>
                    </div>
                </Card>
            </Show>

            <Show when=move || kind.get() == "4">
                <Card class="grid gap-4 p-4 md:grid-cols-2">
                    <Field label="Anrede"><Input value=i_title /></Field>
                    <Field label="Benutzername"><Input value=i_user /></Field>
                    <Field label="Vorname"><Input value=i_first /></Field>
                    <Field label="Nachname"><Input value=i_last /></Field>
                    <Field label="E-Mail"><Input value=i_email /></Field>
                    <Field label="Telefon"><Input value=i_phone /></Field>
                    <Field label="Firma"><Input value=i_company /></Field>
                    <Field label="Adresse"><Input value=i_addr1 /></Field>
                    <Field label="Adresszusatz"><Input value=i_addr2 /></Field>
                    <div class="grid grid-cols-3 gap-2">
                        <Field label="PLZ"><Input value=i_zip /></Field>
                        <div class="col-span-2"><Field label="Ort"><Input value=i_city /></Field></div>
                    </div>
                    <Field label="Kanton / Bundesland"><Input value=i_state /></Field>
                    <Field label="Land"><Input value=i_country /></Field>
                    <Field label="AHV-Nr. / SSN"><Input value=i_ssn /></Field>
                    <Field label="Passnummer"><Input value=i_passport /></Field>
                    <Field label="Führerschein"><Input value=i_license /></Field>
                </Card>
            </Show>

            <Card class="grid gap-4 p-4">
                <Field label="Notizen"><Textarea value=notes rows=4 /></Field>
                <div class="grid gap-2">
                    <Label>"Eigene Felder"</Label>
                    <For each=move || fields.get() key=|f| f.id children=move |f| view! {
                        <div class="flex gap-2">
                            <Input value=f.name placeholder="Name" class="w-2/5" />
                            {if f.kind == 2 {
                                view! { <Select value=f.value options=Signal::derive(|| vec![("false".into(), "Nein".into()), ("true".into(), "Ja".into())]) /> }.into_any()
                            } else {
                                view! { <Input value=f.value placeholder="Wert" r#type=if f.kind == 1 { "password" } else { "text" } /> }.into_any()
                            }}
                            <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon class="size-10 md:size-9 shrink-0" title="Entfernen"
                                on_click=Callback::new(move |_| fields.update(|v| v.retain(|x| x.id != f.id)))><Icon name="x" /></Button>
                        </div>
                    } />
                    <div class="flex flex-wrap gap-1">
                        {[(0i64, "Text"), (1, "Versteckt"), (2, "Ja/Nein")].into_iter().map(|(k, l)| view! {
                            <Button variant=ButtonVariant::Ghost size=ButtonSize::Sm on_click=Callback::new(move |_| {
                                let id = next_id.get_value(); next_id.set_value(id + 1);
                                fields.update(|v| v.push(FieldRow { id, name: RwSignal::new(String::new()), value: RwSignal::new(if k == 2 { "false".into() } else { String::new() }), kind: k }));
                            })><Icon name="plus" />{l}</Button>
                        }).collect_view()}
                    </div>
                </div>
            </Card>
        </div>
    }
}
