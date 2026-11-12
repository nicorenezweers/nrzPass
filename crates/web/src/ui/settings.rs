//! Einstellungen, Kontosicherheit (2FA, Master-Passwort, Geraete, Protokoll), Import/Export, Downloads.

use crate::env::{self, Platform};
use crate::state::{app, PRIMARY};
use crate::ui::icons::Icon;
use crate::ui::kit::*;
use leptos::prelude::*;
use leptos::task::spawn_local;
use nrzpass_core::api;
use nrzpass_core::Kdf;
use serde_json::json;
use wasm_bindgen::JsCast;

#[component]
fn Row(#[prop(into)] title: String, #[prop(into, optional)] text: String, children: Children) -> impl IntoView {
    view! {
        <div class="flex flex-col gap-3 px-5 py-4 md:flex-row md:items-center md:justify-between">
            <div class="min-w-0"><p class="text-sm font-medium">{title}</p><p class="text-xs text-muted-foreground">{text}</p></div>
            <div class="flex shrink-0 flex-wrap items-center gap-2">{children()}</div>
        </div>
    }
}

#[component]
fn Group(#[prop(into)] title: String, children: Children) -> impl IntoView {
    view! {
        <section class="grid gap-2">
            <h2 class="px-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">{title}</h2>
            <Card class="divide-y divide-border">{children()}</Card>
        </section>
    }
}

fn qr_svg(text: &str) -> String {
    qrcode::QrCode::new(text.as_bytes())
        .map(|c| c.render::<qrcode::render::svg::Color>().min_dimensions(180, 180).dark_color(qrcode::render::svg::Color("#141414")).light_color(qrcode::render::svg::Color("#f5f5f5")).build())
        .unwrap_or_default()
}

#[component]
pub fn SettingsPage() -> impl IntoView {
    let app = app();
    let st = app.settings.get_untracked();
    let auto_lock = RwSignal::new(st.auto_lock_minutes.to_string());
    let clip = RwSignal::new(st.clipboard_clear_secs.to_string());
    let hidden = RwSignal::new(st.lock_when_hidden);
    Effect::new(move |_| {
        let (a, c, h) = (auto_lock.get(), clip.get(), hidden.get());
        app.settings.update(|s| {
            s.auto_lock_minutes = a.parse().unwrap_or(15);
            s.clipboard_clear_secs = c.parse().unwrap_or(30);
            s.lock_when_hidden = h;
        });
        app.save_settings();
    });
    let session = app.session.get_untracked();
    let kdf_label = session.as_ref().map(|s| s.kdf.label()).unwrap_or_default();

    view! {
        <div class="grid gap-6">
            <div>
                <h1 class="text-xl font-semibold">"Einstellungen"</h1>
                <p class="text-sm text-muted-foreground">{session.as_ref().map(|s| format!("{} · {}", s.email, s.server))}</p>
            </div>

            <Group title="Sperre">
                <Row title="Automatisch sperren" text="Nach so langer Inaktivität wird der Tresor gesperrt und alle Schlüssel aus dem Speicher gelöscht.">
                    <Select value=auto_lock class="w-52" options=Signal::derive(|| vec![
                        ("1".into(), "nach 1 Minute".into()), ("5".into(), "nach 5 Minuten".into()), ("15".into(), "nach 15 Minuten".into()),
                        ("30".into(), "nach 30 Minuten".into()), ("60".into(), "nach 1 Stunde".into()), ("240".into(), "nach 4 Stunden".into()), ("0".into(), "nie".into()),
                    ]) />
                </Row>
                <Row title="Sperren, wenn verborgen" text="Fenster oder Tab länger als 1 Minute im Hintergrund.">
                    <Switch checked=hidden label="Sperren, wenn verborgen" />
                </Row>
                <Row title="Zwischenablage leeren" text="Kopierte Passwörter werden automatisch entfernt.">
                    <Select value=clip class="w-52" options=Signal::derive(|| vec![
                        ("10".into(), "nach 10 Sekunden".into()), ("30".into(), "nach 30 Sekunden".into()), ("60".into(), "nach 1 Minute".into()),
                        ("120".into(), "nach 2 Minuten".into()), ("0".into(), "nie".into()),
                    ]) />
                </Row>
                <Row title="Sitzung">
                    <Button variant=ButtonVariant::Outline on_click=Callback::new(move |_| app.lock())><Icon name="lock" />"Jetzt sperren"</Button>
                    <Button variant=ButtonVariant::Ghost on_click=Callback::new(move |_| spawn_local(async move { app.logout().await }))><Icon name="logout" />"Abmelden"</Button>
                </Row>
            </Group>

            <Group title="Kontosicherheit">
                <TwoFactor />
                <ChangePassword kdf_label=kdf_label />
            </Group>

            <Devices />
            <Events />
            <ImportExport />
            <DangerZone />

            <p class="text-center text-xs text-muted-foreground">{format!("nrzPass {} · Rust · Leptos · Rust/UI · Turso", env!("CARGO_PKG_VERSION"))}</p>
        </div>
    }
}

#[component]
fn TwoFactor() -> impl IntoView {
    let app = app();
    let enabled = Signal::derive(move || app.accounts.with(|a| a.iter().find(|x| x.id == PRIMARY).map(|x| x.two_factor).unwrap_or(false)));
    let open = RwSignal::new(false);
    let disable_open = RwSignal::new(false);
    let pw = RwSignal::new(String::new());
    let key = RwSignal::new(Option::<String>::None);
    let code = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let hash = StoredValue::new(String::new());

    let start = move || {
        let h = match app.verify_master(&pw.get_untracked()) {
            Ok(h) => h,
            Err(e) => return app.error(e),
        };
        hash.set_value(h.clone());
        busy.set(true);
        spawn_local(async move {
            let r = app.call(PRIMARY, "POST", "/api/two-factor/get-authenticator", Some(json!({"masterPasswordHash": h}))).await;
            busy.set(false);
            match r {
                Ok(v) => key.set(v["key"].as_str().map(str::to_string)),
                Err(e) => app.error(e),
            }
        });
    };
    let confirm = move || {
        let Some(k) = key.get_untracked() else { return };
        busy.set(true);
        spawn_local(async move {
            let body = json!({"key": k, "token": code.get_untracked().replace(' ', ""), "masterPasswordHash": hash.get_value()});
            let r = app.call(PRIMARY, "PUT", "/api/two-factor/authenticator", Some(body)).await;
            busy.set(false);
            match r {
                Ok(_) => {
                    open.set(false);
                    key.set(None);
                    pw.set(String::new());
                    code.set(String::new());
                    app.toast("Zwei-Faktor ist aktiv");
                    let _ = app.sync_account(PRIMARY).await;
                }
                Err(e) => app.error(e),
            }
        });
    };
    let disable = move || {
        let h = match app.verify_master(&pw.get_untracked()) {
            Ok(h) => h,
            Err(e) => return app.error(e),
        };
        spawn_local(async move {
            match app.call(PRIMARY, "PUT", "/api/two-factor/disable", Some(json!({"masterPasswordHash": h, "type": 0}))).await {
                Ok(_) => {
                    disable_open.set(false);
                    pw.set(String::new());
                    app.toast("Zwei-Faktor deaktiviert");
                    let _ = app.sync_account(PRIMARY).await;
                }
                Err(e) => app.error(e),
            }
        });
    };

    view! {
        <Row title="Zwei-Faktor-Anmeldung (TOTP)" text="Zusätzlich zum Master-Passwort ein Code aus einer Authenticator-App bei jeder neuen Anmeldung.">
            {move || if enabled.get() {
                view! { <Badge variant=BadgeVariant::Success>"Aktiv"</Badge><Button variant=ButtonVariant::Ghost size=ButtonSize::Sm on_click=Callback::new(move |_| disable_open.set(true))>"Deaktivieren"</Button> }.into_any()
            } else {
                view! { <Button variant=ButtonVariant::Outline on_click=Callback::new(move |_| open.set(true))><Icon name="shield-check" />"Einrichten"</Button> }.into_any()
            }}
            <Dialog open=open title="Zwei-Faktor einrichten">
                <Show when=move || key.get().is_some() fallback=move || view! {
                    <div class="grid gap-4">
                        <Field label="Master-Passwort zur Bestätigung"><Input value=pw r#type="password" autofocus=true on_enter=Callback::new(move |_| start()) /></Field>
                        <Button disabled=busy on_click=Callback::new(move |_| start())>"Weiter"</Button>
                    </div>
                }>
                    {move || key.get().map(|k| {
                        let email = app.session.get_untracked().map(|s| s.email).unwrap_or_default();
                        let uri = format!("otpauth://totp/nrzPass:{}?secret={}&issuer=nrzPass", js_sys::encode_uri_component(&email), k);
                        let k2 = k.clone();
                        view! {
                            <div class="grid gap-4">
                                <p class="text-sm text-muted-foreground">"QR-Code mit der Authenticator-App scannen oder den Schlüssel eintippen."</p>
                                <div class="mx-auto overflow-hidden rounded-lg" inner_html=qr_svg(&uri)></div>
                                <button class="rounded-md bg-background p-2 text-center font-mono text-xs break-all cursor-pointer" title="Kopieren"
                                    on:click=move |_| app.copy("Schlüssel", k2.clone())>{k.clone()}</button>
                                <Field label="Code aus der App"><Input value=code mono=true autocomplete="one-time-code" on_enter=Callback::new(move |_| confirm()) /></Field>
                                <Button disabled=busy on_click=Callback::new(move |_| confirm())>"Aktivieren"</Button>
                            </div>
                        }
                    })}
                </Show>
            </Dialog>
            <Dialog open=disable_open title="Zwei-Faktor deaktivieren?">
                <div class="grid gap-4">
                    <p class="text-sm text-muted-foreground">"Dein Konto ist danach nur noch durch das Master-Passwort geschützt."</p>
                    <Field label="Master-Passwort"><Input value=pw r#type="password" autofocus=true /></Field>
                    <Button variant=ButtonVariant::Destructive on_click=Callback::new(move |_| disable())>"Deaktivieren"</Button>
                </div>
            </Dialog>
        </Row>
    }
}

#[component]
fn ChangePassword(kdf_label: String) -> impl IntoView {
    let app = app();
    let open = RwSignal::new(false);
    let current = RwSignal::new(String::new());
    let new = RwSignal::new(String::new());
    let new2 = RwSignal::new(String::new());
    let hint = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);
    let submit = move || {
        let (c, n) = (current.get_untracked(), new.get_untracked());
        if n.chars().count() < 12 {
            return error.set(Some("Mindestens 12 Zeichen".into()));
        }
        if n != new2.get_untracked() {
            return error.set(Some("Die neuen Passwörter stimmen nicht überein".into()));
        }
        if nrzpass_core::strength::estimate(&n).score < 3 {
            return error.set(Some("Bitte ein stärkeres Passwort wählen".into()));
        }
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(30).await;
            let r = app.change_password(&c, &n, &hint.get_untracked(), Kdf::DEFAULT).await;
            busy.set(false);
            match r {
                Ok(()) => {
                    open.set(false);
                    app.toast("Master-Passwort geändert – andere Geräte wurden abgemeldet");
                }
                Err(e) => error.set(Some(e)),
            }
        });
    };
    view! {
        <Row title="Master-Passwort" text=format!("Schlüsselableitung: {kdf_label}. Beim Ändern werden alle anderen Geräte abgemeldet.")>
            <Button variant=ButtonVariant::Outline on_click=Callback::new(move |_| open.set(true))><Icon name="key" />"Ändern"</Button>
            <Dialog open=open title="Master-Passwort ändern">
                <div class="grid gap-4">
                    <Field label="Aktuelles Master-Passwort"><Input value=current r#type="password" autocomplete="current-password" autofocus=true /></Field>
                    <Field label="Neues Master-Passwort"><Input value=new r#type="password" autocomplete="new-password" /></Field>
                    <StrengthMeter password=new.into() />
                    <Field label="Wiederholen"><Input value=new2 r#type="password" autocomplete="new-password" /></Field>
                    <Field label="Hinweis (optional)"><Input value=hint /></Field>
                    <p class="text-xs text-muted-foreground">"Neue Konten und Passwortwechsel nutzen Argon2id (64 MiB, 3 Durchläufe, 4 Threads)."</p>
                    <Show when=move || error.get().is_some()><p class="rounded-md bg-destructive/10 p-2.5 text-xs text-destructive">{move || error.get()}</p></Show>
                    <Button disabled=busy on_click=Callback::new(move |_| submit())><Show when=move || busy.get()><Spinner /></Show>"Ändern"</Button>
                </div>
            </Dialog>
        </Row>
    }
}

#[component]
fn Devices() -> impl IntoView {
    let app = app();
    let devices = RwSignal::new(Vec::<api::DeviceInfo>::new());
    let load = move || {
        spawn_local(async move {
            if let Ok(v) = app.call(PRIMARY, "GET", "/api/nrz/devices", None).await {
                devices.set(api::from_value_lenient(v).unwrap_or_default());
            }
        })
    };
    load();
    view! {
        <Group title="Angemeldete Geräte">
            <Show when=move || !devices.get().is_empty() fallback=|| view! { <p class="px-5 py-4 text-sm text-muted-foreground">"Keine Geräte gefunden."</p> }>
                <For each=move || devices.get() key=|d| d.id.clone() children=move |d| {
                    let id = d.id.clone();
                    let icon = match d.device_type { 0 | 1 => "smartphone", 2 | 3 | 4 | 19 | 20 => "puzzle", 6 | 7 | 8 => "monitor", _ => "globe" };
                    view! {
                        <div class="flex items-center gap-3 px-5 py-3">
                            <Icon name=icon class="size-4 text-muted-foreground" />
                            <div class="min-w-0 flex-1">
                                <p class="flex items-center gap-2 text-sm">{d.name.clone()}{d.current.then(|| view! { <Badge variant=BadgeVariant::Secondary>"Dieses Gerät"</Badge> })}</p>
                                <p class="text-xs text-muted-foreground">{format!("Zuletzt aktiv {}", env::format_date(&d.last_seen))}</p>
                            </div>
                            {(!d.current).then(|| view! {
                                <Button variant=ButtonVariant::Ghost size=ButtonSize::Sm on_click=Callback::new(move |_| {
                                    let id = id.clone();
                                    spawn_local(async move {
                                        match app.call(PRIMARY, "DELETE", &format!("/api/nrz/devices/{id}"), None).await {
                                            Ok(_) => { app.toast("Gerät abgemeldet"); load(); }
                                            Err(e) => app.error(e),
                                        }
                                    })
                                })>"Abmelden"</Button>
                            })}
                        </div>
                    }
                } />
            </Show>
        </Group>
    }
}

fn event_label(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "register" => ("Konto erstellt", "user"),
        "login" => ("Anmeldung", "unlock"),
        "login_failed" => ("Fehlgeschlagene Anmeldung", "alert"),
        "totp_failed" => ("Falscher Zwei-Faktor-Code", "alert"),
        "password_changed" => ("Master-Passwort geändert", "key"),
        "totp_enabled" => ("Zwei-Faktor aktiviert", "shield-check"),
        "totp_disabled" => ("Zwei-Faktor deaktiviert", "shield"),
        "device_revoked" => ("Gerät abgemeldet", "monitor"),
        "account_locked" => ("Konto vorübergehend gesperrt (zu viele Versuche)", "lock"),
        _ => ("Ereignis", "activity"),
    }
}

#[component]
fn Events() -> impl IntoView {
    let app = app();
    let events = RwSignal::new(Vec::<api::SecurityEvent>::new());
    let all = RwSignal::new(false);
    spawn_local(async move {
        if let Ok(v) = app.call(PRIMARY, "GET", "/api/nrz/events", None).await {
            events.set(api::from_value_lenient(v).unwrap_or_default());
        }
    });
    view! {
        <Group title="Sicherheitsprotokoll">
            <Show when=move || !events.get().is_empty() fallback=|| view! { <p class="px-5 py-4 text-sm text-muted-foreground">"Noch keine Ereignisse."</p> }>
                {move || events.get().into_iter().take(if all.get() { 200 } else { 8 }).map(|e| {
                    let (label, icon) = event_label(&e.kind);
                    let bad = e.kind.contains("failed") || e.kind == "account_locked" || e.kind == "totp_disabled";
                    view! {
                        <div class="flex items-center gap-3 px-5 py-2.5">
                            <Icon name=icon class=if bad { "size-4 text-destructive" } else { "size-4 text-muted-foreground" } />
                            <div class="min-w-0 flex-1">
                                <p class="text-sm">{label}</p>
                                <p class="truncate text-xs text-muted-foreground">{[Some(env::format_date(&e.date)), e.device.clone(), e.ip.clone()].into_iter().flatten().collect::<Vec<_>>().join(" · ")}</p>
                            </div>
                        </div>
                    }
                }).collect_view()}
                <Show when=move || !all.get() && 8 < events.get().len()>
                    <button class="w-full px-5 py-2.5 text-xs text-muted-foreground hover:text-foreground cursor-pointer" on:click=move |_| all.set(true)>"Alle anzeigen"</button>
                </Show>
            </Show>
        </Group>
    }
}

#[component]
fn ImportExport() -> impl IntoView {
    let app = app();
    let import_open = RwSignal::new(false);
    let export_open = RwSignal::new(false);
    let target = RwSignal::new(PRIMARY.to_string());
    let file_text = RwSignal::new(Option::<(String, String)>::None);
    let file_pw = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let master = RwSignal::new(String::new());
    let protect = RwSignal::new(true);
    let export_pw = RwSignal::new(String::new());
    let source = RwSignal::new(PRIMARY.to_string());
    let accounts = Signal::derive(move || app.accounts.with(|a| a.iter().map(|x| (x.id.clone(), x.label.clone())).collect()));

    let on_file = move |ev: leptos::ev::Event| {
        let input: web_sys::HtmlInputElement = ev.target().unwrap().unchecked_into();
        if let Some(f) = input.files().and_then(|l| l.get(0)) {
            let name = f.name();
            spawn_local(async move {
                match env::read_file(f).await {
                    Ok(t) => file_text.set(Some((name, t))),
                    Err(e) => app.error(e),
                }
            });
        }
    };
    let do_import = move || {
        let Some((_, text)) = file_text.get_untracked() else { return app.error("Bitte eine Datei wählen") };
        let pw = file_pw.get_untracked();
        busy.set(true);
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(30).await;
            let r = match nrzpass_core::vault::import(&text, if pw.is_empty() { None } else { Some(pw.as_str()) }) {
                Ok(imp) if imp.items.is_empty() => Err("Keine Einträge in der Datei gefunden".into()),
                Ok(imp) => app.import(&target.get_untracked(), imp).await,
                Err(e) => Err(e),
            };
            busy.set(false);
            match r {
                Ok(n) => {
                    import_open.set(false);
                    file_text.set(None);
                    file_pw.set(String::new());
                    app.toast(format!("{n} Einträge importiert"));
                }
                Err(e) => app.error(e),
            }
        });
    };
    let do_export = move || {
        if let Err(e) = app.verify_master(&master.get_untracked()) {
            return app.error(e);
        }
        let protected = protect.get_untracked();
        let epw = export_pw.get_untracked();
        if protected && epw.chars().count() < 8 {
            return app.error("Export-Passwort: mindestens 8 Zeichen");
        }
        busy.set(true);
        let src = source.get_untracked();
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(30).await;
            let items: Vec<_> = app.entries.with_untracked(|e| e.iter().filter(|x| x.account == src && !x.broken).map(|x| x.cipher.clone()).collect());
            let folders: Vec<_> = app.folders.with_untracked(|f| f.iter().filter(|x| x.account == src).map(|x| x.folder.clone()).collect());
            let json = nrzpass_core::vault::export_json(&items, &folders);
            let date = env::now_iso().chars().take(10).collect::<String>();
            let (name, content) = if protected {
                match nrzpass_core::vault::export_protected(&json, &epw, Kdf::DEFAULT) {
                    Ok(c) => (format!("nrzpass-export-{date}-geschuetzt.json"), c),
                    Err(e) => {
                        busy.set(false);
                        return app.error(e.to_string());
                    }
                }
            } else {
                (format!("nrzpass-export-{date}.json"), json)
            };
            let r = env::save_file(&name, &content).await;
            busy.set(false);
            match r {
                Ok(()) => {
                    export_open.set(false);
                    master.set(String::new());
                    export_pw.set(String::new());
                    app.toast(format!("{} Einträge exportiert", items.len()));
                }
                Err(e) => app.error(e),
            }
        });
    };

    view! {
        <Group title="Import & Export">
            <Row title="Importieren" text="Bitwarden/Vaultwarden-JSON (auch passwortgeschützt), Bitwarden-CSV, Chrome-, Firefox-, Safari- und Edge-CSV.">
                <Button variant=ButtonVariant::Outline on_click=Callback::new(move |_| import_open.set(true))><Icon name="upload" />"Importieren"</Button>
            </Row>
            <Row title="Exportieren" text="Standard: passwortgeschützt (AES-256 + Argon2id) – lässt sich in nrzPass, Bitwarden und Vaultwarden wieder einlesen.">
                <Button variant=ButtonVariant::Outline on_click=Callback::new(move |_| export_open.set(true))><Icon name="download" />"Exportieren"</Button>
            </Row>
            <Dialog open=import_open title="Passwörter importieren">
                <div class="grid gap-4">
                    <Show when=move || app.accounts.with(|a| a.len() > 1)><Field label="In Tresor"><Select value=target options=accounts /></Field></Show>
                    <Field label="Datei">
                        <input type="file" accept=".json,.csv,text/csv,application/json" on:change=on_file
                            class="block w-full text-sm text-muted-foreground file:mr-3 file:rounded-md file:border-0 file:bg-secondary file:px-3 file:py-1.5 file:text-sm file:text-foreground" />
                    </Field>
                    <Field label="Passwort der Datei (falls geschützt)"><Input value=file_pw r#type="password" /></Field>
                    <p class="text-xs text-muted-foreground">"Die Datei wird nur hier im Gerät gelesen und verschlüsselt hochgeladen. Lösche unverschlüsselte Exporte danach."</p>
                    <Button disabled=busy on_click=Callback::new(move |_| do_import())><Show when=move || busy.get()><Spinner /></Show>"Importieren"</Button>
                </div>
            </Dialog>
            <Dialog open=export_open title="Tresor exportieren">
                <div class="grid gap-4">
                    <Show when=move || app.accounts.with(|a| a.len() > 1)><Field label="Tresor"><Select value=source options=accounts /></Field></Show>
                    <label class="flex items-center justify-between gap-3 text-sm"><span>"Mit Passwort schützen (empfohlen)"</span><Switch checked=protect /></label>
                    <Show when=move || protect.get() fallback=|| view! {
                        <p class="flex gap-2 rounded-md bg-warning/10 p-2.5 text-xs text-warning"><Icon name="alert" class="size-3.5" />"Unverschlüsselt: jeder mit Zugriff auf die Datei sieht alle Passwörter."</p>
                    }>
                        <Field label="Export-Passwort"><Input value=export_pw r#type="password" autocomplete="new-password" /></Field>
                    </Show>
                    <Field label="Master-Passwort zur Bestätigung"><Input value=master r#type="password" autocomplete="current-password" /></Field>
                    <Button disabled=busy on_click=Callback::new(move |_| do_export())><Show when=move || busy.get()><Spinner /></Show>"Exportieren"</Button>
                </div>
            </Dialog>
        </Group>
    }
}

#[component]
fn DangerZone() -> impl IntoView {
    let app = app();
    let open = RwSignal::new(false);
    let pw = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let submit = move || {
        if confirm.get_untracked() != "LÖSCHEN" {
            return app.error("Bitte LÖSCHEN eintippen");
        }
        let h = match app.verify_master(&pw.get_untracked()) {
            Ok(h) => h,
            Err(e) => return app.error(e),
        };
        spawn_local(async move {
            match app.call(PRIMARY, "POST", "/api/accounts/delete", Some(json!({"masterPasswordHash": h}))).await {
                Ok(_) => {
                    open.set(false);
                    app.logout().await;
                    app.toast("Konto gelöscht");
                }
                Err(e) => app.error(e),
            }
        });
    };
    view! {
        <Group title="Gefahrenzone">
            <Row title="Konto löschen" text="Löscht dein nrzPass-Konto mit allen Einträgen endgültig vom Server.">
                <Button variant=ButtonVariant::Ghost class="text-destructive hover:text-destructive" on_click=Callback::new(move |_| open.set(true))><Icon name="trash" />"Konto löschen"</Button>
            </Row>
            <Dialog open=open title="Konto endgültig löschen?">
                <div class="grid gap-4">
                    <p class="text-sm text-muted-foreground">"Alle Einträge, Ordner und Verknüpfungen werden gelöscht. Das lässt sich nicht rückgängig machen."</p>
                    <Field label="Master-Passwort"><Input value=pw r#type="password" /></Field>
                    <Field label="Zur Bestätigung LÖSCHEN eintippen"><Input value=confirm /></Field>
                    <Button variant=ButtonVariant::Destructive on_click=Callback::new(move |_| submit())>"Endgültig löschen"</Button>
                </div>
            </Dialog>
        </Group>
    }
}

#[component]
pub fn DownloadsPage() -> impl IntoView {
    let files = RwSignal::new(Vec::<(String, u64)>::new());
    spawn_local(async move {
        let conn = crate::net::Conn { base: env::origin(), via: crate::net::Via::Direct, device_id: String::new() };
        if let Ok(r) = conn.raw("GET", "/api/nrz/downloads", None, None).await {
            if let Some(a) = r.json().as_array() {
                files.set(a.iter().filter_map(|f| Some((f["name"].as_str()?.to_string(), f["size"].as_u64().unwrap_or(0)))).collect());
            }
        }
    });
    let find = move |pat: &'static str| Signal::derive(move || files.get().into_iter().find(|(n, _)| n.to_lowercase().contains(pat)));
    let card = move |icon: &'static str, title: &'static str, text: &'static str, steps: &'static [&'static str], file: Signal<Option<(String, u64)>>| {
        view! {
            <Card class="grid gap-3 p-5">
                <div class="flex items-center gap-3">
                    <div class="grid size-10 place-items-center rounded-lg bg-secondary"><Icon name=icon class="size-5" /></div>
                    <div class="min-w-0 flex-1"><p class="text-sm font-medium">{title}</p><p class="text-xs text-muted-foreground">{text}</p></div>
                    {move || match file.get() {
                        Some((n, size)) => view! {
                            <a class="inline-flex h-9 items-center gap-2 rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground hover:bg-primary/90"
                                href=format!("/downloads/{n}") download=n.clone()><Icon name="download" />{format!("{:.1} MB", size as f64 / 1_048_576.0)}</a>
                        }.into_any(),
                        None => view! { <Badge variant=BadgeVariant::Outline>"nicht auf dem Server"</Badge> }.into_any(),
                    }}
                </div>
                <ol class="grid list-decimal gap-1 pl-5 text-xs text-muted-foreground">{steps.iter().map(|s| view! { <li>{*s}</li> }).collect_view()}</ol>
            </Card>
        }
    };
    let _ = Platform::Web;
    view! {
        <div class="grid gap-5">
            <div>
                <h1 class="text-xl font-semibold">"Apps & Erweiterung"</h1>
                <p class="text-sm text-muted-foreground">"nrzPass gibt es als Webseite, macOS-App und Browser-Erweiterung – alle mit derselben Ende-zu-Ende-Verschlüsselung."</p>
            </div>
            {card("apple", "macOS-App", "Tauri, für Apple Silicon und Intel", &[
                "DMG öffnen und nrzPass in „Programme“ ziehen.",
                "Beim ersten Start: Rechtsklick auf nrzPass → Öffnen (die App ist nicht von Apple notarisiert).",
                "Server-Adresse dieser Seite eintragen und anmelden.",
            ], find(".dmg"))}
            {card("puzzle", "Chrome, Edge, Brave, Arc", "Erkennt Login-Felder, füllt aus und schlägt starke Passwörter vor", &[
                "ZIP herunterladen und entpacken.",
                "chrome://extensions öffnen, oben rechts „Entwicklermodus“ einschalten.",
                "„Entpackte Erweiterung laden“ und den entpackten Ordner wählen.",
            ], find("chrome"))}
            {card("puzzle", "Firefox", "Gleiche Funktionen wie in Chrome", &[
                "ZIP herunterladen.",
                "about:debugging#/runtime/this-firefox öffnen → „Temporäres Add-on laden“ → ZIP wählen.",
                "Für dauerhafte Installation die Erweiterung über addons.mozilla.org signieren lassen.",
            ], find("firefox"))}
            <Card class="grid gap-2 p-5">
                <p class="flex items-center gap-2 text-sm font-medium"><Icon name="smartphone" />"iPhone & Android"</p>
                <p class="text-xs text-muted-foreground">"Diese Seite im Browser öffnen und „Zum Home-Bildschirm“ wählen – nrzPass läuft dann wie eine App. Bitwarden-Apps können sich ebenfalls mit diesem Server verbinden (eigener Server: diese Adresse)."</p>
            </Card>
        </div>
    }
}
