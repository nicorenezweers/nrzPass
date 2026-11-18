//! Anmelden, Registrieren und Entsperren.

use crate::env::{self, Platform};
use crate::state::app;
use crate::ui::icons::{Icon, Logo};
use crate::ui::kit::*;
use leptos::prelude::*;
use leptos::task::spawn_local;

#[component]
fn AuthFrame(children: Children) -> impl IntoView {
    if crate::env::is_popup() {
        // Popup: kompakt, scrollt innen (feste Popup-Hoehe)
        return view! {
            <div class="relative h-full w-full overflow-x-hidden overflow-y-auto">
                <div class="drift pointer-events-none absolute inset-0 overflow-hidden" aria-hidden="true"><span class="drift-a"></span></div>
                <div class="relative z-10 flex min-h-full flex-col justify-center gap-4 p-4">
                    <div class="flex items-center gap-3">
                        <Logo class="size-9" />
                        <div class="min-w-0">
                            <h1 class="text-base font-semibold leading-tight">"nrzPass"</h1>
                            <p class="text-[11px] text-muted-foreground">"Zero-Knowledge · Vaultwarden-kompatibel"</p>
                        </div>
                    </div>
                    {children()}
                </div>
            </div>
        }
        .into_any();
    }
    view! {
        <div class="relative flex min-h-dvh items-center justify-center overflow-hidden p-4 safe-top safe-bottom">
            <div class="drift absolute inset-0 -z-0" aria-hidden="true"><span class="drift-a"></span><span class="drift-b"></span></div>
            <div class="relative z-10 w-full max-w-sm">
                <div class="mb-6 flex flex-col items-center gap-3 text-center">
                    <Logo class="size-14" />
                    <div>
                        <h1 class="text-xl font-semibold tracking-tight">"nrzPass"</h1>
                        <p class="text-xs text-muted-foreground">"Zero-Knowledge · Vaultwarden-kompatibel · Rust"</p>
                    </div>
                </div>
                {children()}
            </div>
        </div>
    }
    .into_any()
}

#[component]
pub fn Setup() -> impl IntoView {
    let app = app();
    let register = RwSignal::new(false);
    let server = RwSignal::new(app.default_server());
    let email = RwSignal::new(app.session.get_untracked().map(|s| s.email).unwrap_or_default());
    let name = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let password2 = RwSignal::new(String::new());
    let hint = RwSignal::new(String::new());
    let totp = RwSignal::new(String::new());
    let need_totp = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);
    let show_pw = RwSignal::new(false);
    let signups = RwSignal::new(true);
    let show_server = env::platform() != Platform::Web;

    // Server-Infos (Registrierung offen?) – nur fuer nrzPass-Server
    let check_server = move || {
        let base = crate::net::normalize_server(&server.get_untracked());
        spawn_local(async move {
            let conn = crate::net::Conn { base, via: crate::net::default_via(), device_id: String::new() };
            if let Ok(r) = conn.raw("GET", "/api/nrz/info", None, None).await {
                if r.ok() {
                    let v = r.json();
                    signups.set(v["signupsAllowed"].as_bool().unwrap_or(false));
                    if !v["hasUsers"].as_bool().unwrap_or(true) {
                        register.set(true);
                    }
                }
            }
        });
    };
    if !server.get_untracked().is_empty() {
        check_server();
    }

    let submit = move || {
        if busy.get_untracked() {
            return;
        }
        error.set(None);
        let (srv, em, pw) = (server.get_untracked(), email.get_untracked(), password.get_untracked());
        if srv.trim().is_empty() || em.trim().is_empty() || pw.is_empty() {
            error.set(Some("Bitte alle Felder ausfüllen".into()));
            return;
        }
        if register.get_untracked() {
            if pw.chars().count() < 12 {
                error.set(Some("Das Master-Passwort braucht mindestens 12 Zeichen".into()));
                return;
            }
            if pw != password2.get_untracked() {
                error.set(Some("Die Passwörter stimmen nicht überein".into()));
                return;
            }
            if nrzpass_core::strength::estimate(&pw).score < 3 {
                error.set(Some("Bitte ein stärkeres Master-Passwort wählen (z. B. eine Passphrase aus 5 Woertern)".into()));
                return;
            }
        }
        busy.set(true);
        spawn_local(async move {
            // Kurz warten, damit der Ladezustand sichtbar wird, bevor Argon2id rechnet
            gloo_timers::future::TimeoutFuture::new(30).await;
            let res = if register.get_untracked() {
                app.register(&srv, &name.get_untracked(), &em, &pw, &hint.get_untracked()).await.map(|_| None)
            } else {
                let t = need_totp.get_untracked().then(|| (totp.get_untracked().replace(' ', ""), false));
                app.login(&srv, &em, &pw, t).await
            };
            busy.set(false);
            match res {
                Ok(Some(providers)) => {
                    if providers.iter().any(|p| p == "0") {
                        need_totp.set(true);
                    } else {
                        error.set(Some("Dieses Konto verlangt eine Zwei-Faktor-Methode, die nrzPass nicht kennt. Bitte eine Authenticator-App (TOTP) einrichten.".into()));
                    }
                }
                Ok(None) => {
                    password.set(String::new());
                    password2.set(String::new());
                }
                Err(e) => error.set(Some(e)),
            }
        });
    };

    view! {
        <AuthFrame>
            <Card>
                <CardHeader>
                    <CardTitle>{move || if need_totp.get() { "Zwei-Faktor-Code" } else if register.get() { "Konto erstellen" } else { "Anmelden" }}</CardTitle>
                    <CardDescription>{move || if need_totp.get() {
                        "Code aus deiner Authenticator-App eingeben."
                    } else if register.get() {
                        "Dein Master-Passwort verlässt nie dieses Gerät. Ohne es kann niemand – auch nicht der Server – deinen Tresor öffnen. Vergessen = Daten verloren."
                    } else {
                        "Mit deinem nrzPass-Konto. Ein Vaultwarden-Konto kannst du danach unter „Konten“ hinzufügen."
                    }}</CardDescription>
                </CardHeader>
                <CardContent class="grid gap-4">
                    <Show when=move || !need_totp.get() fallback=move || view! {
                        <Field label="Code">
                            <Input value=totp placeholder="123 456" autocomplete="one-time-code" autofocus=true mono=true
                                on_enter=Callback::new(move |_| submit()) />
                        </Field>
                    }>
                        {show_server.then(|| view! {
                            <Field label="Server" hint="Adresse deines nrzPass-Servers, z. B. http://umbrel.local:8490">
                                <div on:focusout=move |_| check_server()>
                                    <Input value=server placeholder="https://pass.example.ch" autocomplete="url" />
                                </div>
                            </Field>
                        })}
                        <Show when=move || register.get()>
                            <Field label="Name"><Input value=name placeholder="Dein Name" autocomplete="name" /></Field>
                        </Show>
                        <Field label="E-Mail">
                            <Input value=email r#type="email" placeholder="du@example.ch" autocomplete="username" autofocus=true />
                        </Field>
                        <Field label="Master-Passwort">
                            <div class="relative">
                                <Input value=password r#type=Signal::derive(move || if show_pw.get() { "text".to_string() } else { "password".to_string() })
                                    autocomplete=if register.get_untracked() { "new-password" } else { "current-password" } class="pr-10"
                                    on_enter=Callback::new(move |_| if !register.get_untracked() { submit() }) />
                                <button type="button" class="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1.5 text-muted-foreground hover:text-foreground cursor-pointer"
                                    aria-label="Passwort anzeigen" on:click=move |_| show_pw.update(|s| *s = !*s)>
                                    {move || view! { <Icon name=if show_pw.get() { "eye-off" } else { "eye" } /> }}
                                </button>
                            </div>
                        </Field>
                        <Show when=move || register.get()>
                            <StrengthMeter password=password.into() />
                            <Field label="Master-Passwort wiederholen">
                                <Input value=password2 r#type="password" autocomplete="new-password" />
                            </Field>
                            <Field label="Hinweis (optional)" hint="Wird unverschlüsselt gespeichert – nie das Passwort selbst!">
                                <Input value=hint placeholder="Erinnerung" />
                            </Field>
                        </Show>
                    </Show>
                    <Show when=move || error.get().is_some()>
                        <p class="flex items-start gap-2 rounded-md bg-destructive/10 p-2.5 text-xs text-destructive">
                            <Icon name="alert" class="mt-px size-3.5" />{move || error.get()}
                        </p>
                    </Show>
                    <Button class="w-full" size=ButtonSize::Lg disabled=busy on_click=Callback::new(move |_| submit())>
                        <Show when=move || busy.get()><Spinner /></Show>
                        {move || if busy.get() { "Schlüssel wird abgeleitet …" } else if need_totp.get() { "Bestätigen" } else if register.get() { "Konto erstellen" } else { "Anmelden" }}
                    </Button>
                    <Show when=move || !need_totp.get() && (signups.get() || register.get())>
                        <button class="text-xs text-muted-foreground hover:text-foreground cursor-pointer"
                            on:click=move |_| { error.set(None); register.update(|r| *r = !*r) }>
                            {move || if register.get() { "Schon ein Konto? Anmelden" } else { "Neues Konto erstellen" }}
                        </button>
                    </Show>
                </CardContent>
            </Card>
        </AuthFrame>
    }
}

#[component]
pub fn Lock() -> impl IntoView {
    let app = app();
    let password = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);
    let session = app.session.get_untracked();
    let email = session.as_ref().map(|s| s.email.clone()).unwrap_or_default();
    let server = session.as_ref().map(|s| s.server.clone()).unwrap_or_default();

    let submit = move || {
        if busy.get_untracked() || password.get_untracked().is_empty() {
            return;
        }
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(30).await;
            let pw = password.get_untracked();
            let r = app.unlock(&pw).await;
            busy.set(false);
            match r {
                Ok(()) => password.set(String::new()),
                Err(e) => {
                    error.set(Some(e));
                    password.set(String::new());
                }
            }
        });
    };

    view! {
        <AuthFrame>
            <Card>
                <CardHeader>
                    <CardTitle class="flex items-center gap-2"><Icon name="lock" />"Tresor gesperrt"</CardTitle>
                    <CardDescription>{email}<span class="block truncate text-[11px] opacity-70">{server}</span></CardDescription>
                </CardHeader>
                <CardContent class="grid gap-4">
                    <Field label="Master-Passwort">
                        <Input value=password r#type="password" autocomplete="current-password" autofocus=true
                            on_enter=Callback::new(move |_| submit()) />
                    </Field>
                    <Show when=move || error.get().is_some()>
                        <p class="rounded-md bg-destructive/10 p-2.5 text-xs text-destructive">{move || error.get()}</p>
                    </Show>
                    <Button class="w-full" size=ButtonSize::Lg disabled=busy on_click=Callback::new(move |_| submit())>
                        <Show when=move || busy.get() fallback=|| view! { <Icon name="unlock" /> }><Spinner /></Show>
                        "Entsperren"
                    </Button>
                    <button class="text-xs text-muted-foreground hover:text-foreground cursor-pointer"
                        on:click=move |_| spawn_local(async move { app.logout().await })>
                        "Abmelden / anderes Konto"
                    </button>
                </CardContent>
            </Card>
        </AuthFrame>
    }
}
