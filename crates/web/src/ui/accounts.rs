//! Verknuepfte Konten: Vaultwarden (oder jeder Bitwarden-kompatible Server) in nrzPass.

use crate::state::{app, AccountKind, Filter, View, PRIMARY};
use crate::ui::icons::Icon;
use crate::ui::kit::*;
use leptos::prelude::*;
use leptos::task::spawn_local;

#[component]
pub fn AccountsPage() -> impl IntoView {
    let app = app();
    let open = RwSignal::new(false);
    let label = RwSignal::new(String::from("Vaultwarden"));
    let server = RwSignal::new(String::new());
    let email = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let totp = RwSignal::new(String::new());
    let need_totp = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);
    let remove = RwSignal::new(Option::<(String, String)>::None);
    let remove_open = RwSignal::new(false);

    let submit = move || {
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(30).await;
            let t = need_totp.get_untracked().then(|| totp.get_untracked().replace(' ', ""));
            let r = app
                .add_linked(&label.get_untracked(), &server.get_untracked(), &email.get_untracked(), &password.get_untracked(), t)
                .await;
            busy.set(false);
            match r {
                Ok(Some(p)) => {
                    if p.iter().any(|x| x == "0") {
                        need_totp.set(true);
                    } else {
                        error.set(Some("Nur Authenticator-App (TOTP) wird als zweiter Faktor unterstützt.".into()));
                    }
                }
                Ok(None) => {
                    open.set(false);
                    password.set(String::new());
                    totp.set(String::new());
                    need_totp.set(false);
                    app.toast("Konto verknüpft");
                }
                Err(e) => error.set(Some(e)),
            }
        });
    };

    view! {
        <div class="grid gap-5">
            <div class="flex items-start justify-between gap-3">
                <div>
                    <h1 class="text-xl font-semibold">"Konten"</h1>
                    <p class="text-sm text-muted-foreground">"Füge dein Vaultwarden- oder Bitwarden-Konto hinzu: Einträge erscheinen direkt in nrzPass, lassen sich bearbeiten und mit einem Klick übernehmen."</p>
                </div>
                <Button on_click=Callback::new(move |_| { error.set(None); open.set(true) })><Icon name="plus" />"Hinzufügen"</Button>
            </div>

            <div class="grid gap-3">
                <For each=move || app.accounts.get() key=|a| (a.id.clone(), a.error.clone()) children=move |a| {
                    let id = a.id.clone();
                    let id2 = a.id.clone();
                    let label = a.label.clone();
                    let primary = a.id == PRIMARY;
                    let count = Signal::derive({ let id = id.clone(); move || app.entries.with(|e| e.iter().filter(|x| x.account == id && !x.deleted()).count()) });
                    let kind = match &a.kind { AccountKind::Primary => "nrzPass", AccountKind::Linked { .. } => "Vaultwarden / Bitwarden" };
                    view! {
                        <Card class="flex items-center gap-4 p-4">
                            <div class="grid size-10 place-items-center rounded-lg bg-secondary"><Icon name=if primary { "shield" } else { "link" } /></div>
                            <div class="min-w-0 flex-1">
                                <p class="flex items-center gap-2 text-sm font-medium">{a.label.clone()}<Badge variant=BadgeVariant::Outline>{kind}</Badge></p>
                                <p class="truncate text-xs text-muted-foreground">{format!("{} · {}", a.email, a.server)}</p>
                                {a.error.clone().map(|e| view! { <p class="mt-1 text-xs text-destructive">{e}</p> })}
                            </div>
                            <span class="text-xs tabular-nums text-muted-foreground">{move || format!("{} Einträge", count.get())}</span>
                            <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon title="Einträge anzeigen"
                                on_click=Callback::new(move |_| { app.filter.set(Filter::Account(id.clone())); app.view.set(View::Vault) })><Icon name="vault" /></Button>
                            {(!primary).then(|| view! {
                                <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon title="Verknüpfung entfernen"
                                    on_click=Callback::new(move |_| { remove.set(Some((id2.clone(), label.clone()))); remove_open.set(true) })><Icon name="trash" /></Button>
                            })}
                        </Card>
                    }
                } />
            </div>

            <Card class="p-5 text-sm text-muted-foreground">
                <p class="mb-2 flex items-center gap-2 font-medium text-foreground"><Icon name="shield-check" />"So bleibt es sicher"</p>
                <ul class="grid list-disc gap-1 pl-5 text-xs">
                    <li>"Dein Vaultwarden-Master-Passwort wird nur hier im Gerät verwendet und nie gespeichert."</li>
                    <li>"nrzPass speichert nur ein Sitzungs-Token und den Kontoschlüssel – verschlüsselt mit deinem nrzPass-Schlüssel. Der nrzPass-Server sieht davon nichts."</li>
                    <li>"Im Browser läuft die Verbindung über deinen nrzPass-Server (Vaultwarden erlaubt keine fremden Webseiten), Daten bleiben Ende-zu-Ende verschlüsselt."</li>
                    <li>"Umgekehrt geht es auch: Bitwarden-kompatible Apps sprechen dieselbe API wie nrzPass."</li>
                </ul>
            </Card>

            <Dialog open=open title="Vaultwarden-Konto hinzufügen">
                <div class="grid gap-4">
                    <Show when=move || !need_totp.get() fallback=move || view! {
                        <Field label="Zwei-Faktor-Code"><Input value=totp mono=true autofocus=true autocomplete="one-time-code" on_enter=Callback::new(move |_| submit()) /></Field>
                    }>
                        <Field label="Bezeichnung"><Input value=label /></Field>
                        <Field label="Server" hint="z. B. https://vault.example.ch oder http://umbrel.local:8089"><Input value=server placeholder="https://vault.example.ch" /></Field>
                        <Field label="E-Mail"><Input value=email r#type="email" /></Field>
                        <Field label="Master-Passwort (Vaultwarden)"><Input value=password r#type="password" on_enter=Callback::new(move |_| submit()) /></Field>
                    </Show>
                    <Show when=move || error.get().is_some()><p class="rounded-md bg-destructive/10 p-2.5 text-xs text-destructive">{move || error.get()}</p></Show>
                    <Button disabled=busy on_click=Callback::new(move |_| submit())>
                        <Show when=move || busy.get()><Spinner /></Show>{move || if need_totp.get() { "Bestätigen" } else { "Verbinden" }}
                    </Button>
                </div>
            </Dialog>

            <Dialog open=remove_open title="Verknüpfung entfernen?">
                <p class="mb-4 text-sm text-muted-foreground">{move || format!("„{}“ wird aus nrzPass entfernt. Die Daten auf dem Vaultwarden-Server bleiben unverändert.", remove.get().map(|r| r.1).unwrap_or_default())}</p>
                <div class="flex justify-end gap-2">
                    <Button variant=ButtonVariant::Outline on_click=Callback::new(move |_| remove_open.set(false))>"Abbrechen"</Button>
                    <Button variant=ButtonVariant::Destructive on_click=Callback::new(move |_| {
                        remove_open.set(false);
                        if let Some((id, _)) = remove.get_untracked() {
                            spawn_local(async move { match app.remove_linked(&id).await { Ok(()) => app.toast("Entfernt"), Err(e) => app.error(e) } });
                        }
                    })>"Entfernen"</Button>
                </div>
            </Dialog>
        </div>
    }
}
