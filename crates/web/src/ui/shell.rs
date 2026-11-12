//! Grundgeruest: Seitenleiste (Desktop), untere Navigation (Handy), Kopfzeile mit Suche.

use crate::env::{self, Platform};
use crate::state::{app, Filter, View, PRIMARY};
use crate::ui::icons::{Icon, Logo};
use crate::ui::kit::*;
use crate::ui::{accounts, generator, health, settings, vault};
use leptos::prelude::*;
use leptos::task::spawn_local;
use nrzpass_core::api::cipher_type;

#[component]
fn NavItem(#[prop(into)] icon: String, #[prop(into)] label: String, active: Signal<bool>, on_click: Callback<()>, #[prop(optional)] count: Option<Signal<usize>>) -> impl IntoView {
    view! {
        <button class=move || format!("flex w-full items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors cursor-pointer {}",
                if active.get() { "bg-accent text-foreground font-medium" } else { "text-muted-foreground hover:bg-accent/60 hover:text-foreground" })
            on:click=move |_| on_click.run(())>
            <Icon name=icon />
            <span class="flex-1 truncate text-left">{label}</span>
            {count.map(|c| view! { <span class="text-xs tabular-nums text-muted-foreground">{move || c.get()}</span> })}
        </button>
    }
}

#[component]
fn NavHeading(#[prop(into)] label: String, #[prop(optional)] action: Option<(String, Callback<()>)>) -> impl IntoView {
    view! {
        <div class="mt-4 mb-1 flex items-center justify-between px-2.5">
            <span class="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">{label}</span>
            {action.map(|(title, cb)| view! {
                <button class="rounded p-0.5 text-muted-foreground hover:text-foreground cursor-pointer" title=title.clone() aria-label=title on:click=move |_| cb.run(())>
                    <Icon name="plus" class="size-3.5" />
                </button>
            })}
        </div>
    }
}

/// Filter und Bereiche (Seitenleiste auf dem Desktop, Schublade auf dem Handy).
#[component]
fn Sidebar() -> impl IntoView {
    let app = app();
    let set_filter = move |f: Filter| {
        app.view.set(View::Vault);
        app.filter.set(f);
        app.selected.set(None);
        app.editing.set(None);
        app.nav_open.set(false);
    };
    let go = move |v: View| {
        app.view.set(v);
        app.nav_open.set(false);
    };
    let is = move |f: Filter| Signal::derive(move || app.view.get() == View::Vault && app.filter.get() == f);
    let count = move |f: Filter| {
        Signal::derive(move || {
            app.entries.with(|e| {
                e.iter()
                    .filter(|x| match &f {
                        Filter::Trash => x.deleted(),
                        Filter::All => !x.deleted(),
                        Filter::Favorites => !x.deleted() && x.cipher.favorite,
                        Filter::Type(t) => !x.deleted() && x.cipher.cipher_type == *t,
                        Filter::Account(a) => !x.deleted() && &x.account == a,
                        Filter::Folder(a, id) => !x.deleted() && &x.account == a && x.cipher.folder_id == *id,
                    })
                    .count()
            })
        })
    };
    let new_folder = RwSignal::new(false);
    let folder_name = RwSignal::new(String::new());
    let multi = Signal::derive(move || app.accounts.with(|a| a.len() > 1));

    view! {
        <nav class="flex h-full flex-col gap-0.5 overflow-y-auto p-3">
            <NavItem icon="vault" label="Alle Einträge" active=is(Filter::All) count=count(Filter::All) on_click=Callback::new(move |_| set_filter(Filter::All)) />
            <NavItem icon="star" label="Favoriten" active=is(Filter::Favorites) count=count(Filter::Favorites) on_click=Callback::new(move |_| set_filter(Filter::Favorites)) />
            <NavHeading label="Arten" />
            <NavItem icon="globe" label="Logins" active=is(Filter::Type(cipher_type::LOGIN)) count=count(Filter::Type(cipher_type::LOGIN)) on_click=Callback::new(move |_| set_filter(Filter::Type(cipher_type::LOGIN))) />
            <NavItem icon="card" label="Karten" active=is(Filter::Type(cipher_type::CARD)) count=count(Filter::Type(cipher_type::CARD)) on_click=Callback::new(move |_| set_filter(Filter::Type(cipher_type::CARD))) />
            <NavItem icon="id" label="Identitäten" active=is(Filter::Type(cipher_type::IDENTITY)) count=count(Filter::Type(cipher_type::IDENTITY)) on_click=Callback::new(move |_| set_filter(Filter::Type(cipher_type::IDENTITY))) />
            <NavItem icon="note" label="Notizen" active=is(Filter::Type(cipher_type::SECURE_NOTE)) count=count(Filter::Type(cipher_type::SECURE_NOTE)) on_click=Callback::new(move |_| set_filter(Filter::Type(cipher_type::SECURE_NOTE))) />

            <Show when=move || multi.get()>
                <NavHeading label="Tresore" />
                <For each=move || app.accounts.get() key=|a| (a.id.clone(), a.error.is_some()) children=move |a| {
                    let id = a.id.clone();
                    let f = Filter::Account(id.clone());
                    let err = a.error.is_some();
                    view! {
                        <NavItem icon=if a.id == PRIMARY { "shield" } else if err { "alert" } else { "link" } label=a.label.clone()
                            active=is(f.clone()) count=count(f.clone()) on_click=Callback::new(move |_| set_filter(Filter::Account(id.clone()))) />
                    }
                } />
            </Show>

            <NavHeading label="Ordner" action=("Ordner anlegen".to_string(), Callback::new(move |_| new_folder.set(true))) />
            <For each=move || app.folders.get() key=|f| (f.account.clone(), f.folder.id.clone(), f.folder.name.clone()) children=move |f| {
                let filt = Filter::Folder(f.account.clone(), Some(f.folder.id.clone()));
                let label = if f.account == PRIMARY { f.folder.name.clone() } else {
                    let acc = app.accounts.with_untracked(|a| a.iter().find(|x| x.id == f.account).map(|x| x.label.clone())).unwrap_or_default();
                    format!("{} · {}", f.folder.name, acc)
                };
                view! { <NavItem icon="folder" label=label active=is(filt.clone()) count=count(filt.clone()) on_click=Callback::new(move |_| set_filter(filt.clone())) /> }
            } />
            <NavItem icon="trash" label="Papierkorb" active=is(Filter::Trash) count=count(Filter::Trash) on_click=Callback::new(move |_| set_filter(Filter::Trash)) />

            <NavHeading label="Werkzeuge" />
            <NavItem icon="wand" label="Generator" active=Signal::derive(move || app.view.get() == View::Generator) on_click=Callback::new(move |_| go(View::Generator)) />
            <NavItem icon="activity" label="Sicherheitsbericht" active=Signal::derive(move || app.view.get() == View::Health) on_click=Callback::new(move |_| go(View::Health)) />
            <NavItem icon="link" label="Konten & Vaultwarden" active=Signal::derive(move || app.view.get() == View::Accounts) on_click=Callback::new(move |_| go(View::Accounts)) />
            <NavItem icon="settings" label="Einstellungen" active=Signal::derive(move || app.view.get() == View::Settings) on_click=Callback::new(move |_| go(View::Settings)) />
            {(env::platform() == Platform::Web).then(|| view! {
                <NavItem icon="download" label="Apps & Erweiterung" active=Signal::derive(move || app.view.get() == View::Downloads) on_click=Callback::new(move |_| go(View::Downloads)) />
            })}

            <Dialog open=new_folder title="Neuer Ordner">
                <div class="grid gap-4">
                    <Input value=folder_name placeholder="Name" autofocus=true />
                    <Button on_click=Callback::new(move |_| {
                        let n = folder_name.get_untracked();
                        if n.trim().is_empty() { return; }
                        new_folder.set(false);
                        folder_name.set(String::new());
                        spawn_local(async move {
                            match app.save_folder(PRIMARY, None, n.trim()).await {
                                Ok(()) => app.toast("Ordner angelegt"),
                                Err(e) => app.error(e),
                            }
                        });
                    })>"Anlegen"</Button>
                </div>
            </Dialog>
        </nav>
    }
}

#[component]
fn SearchBar() -> impl IntoView {
    let app = app();
    view! {
        <div class="relative flex-1">
            <Icon name="search" class="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <input class="h-10 md:h-9 w-full rounded-md border border-input bg-background/60 pl-8 pr-8 text-base md:text-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                type="search" placeholder="Tresor durchsuchen" autocomplete="off" spellcheck="false" id="vault-search"
                prop:value=move || app.search.get() on:input=move |ev| app.search.set(event_target_value(&ev)) />
            <Show when=move || !app.search.get().is_empty()>
                <button class="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground cursor-pointer" aria-label="Suche leeren"
                    on:click=move |_| app.search.set(String::new())><Icon name="x" /></button>
            </Show>
        </div>
    }
}

fn filter_title(f: &Filter) -> String {
    let app = app();
    match f {
        Filter::All => "Alle Einträge".into(),
        Filter::Favorites => "Favoriten".into(),
        Filter::Type(t) => vault::type_name(*t).to_string() + "s",
        Filter::Trash => "Papierkorb".into(),
        Filter::Account(a) => app.accounts.with(|x| x.iter().find(|y| &y.id == a).map(|y| y.label.clone())).unwrap_or_default(),
        Filter::Folder(a, id) => app
            .folders
            .with(|x| x.iter().find(|y| &y.account == a && Some(&y.folder.id) == id.as_ref()).map(|y| y.folder.name.clone()))
            .unwrap_or("Ordner".into()),
    }
}

/// Liste + Detail; auf dem Handy nacheinander.
#[component]
fn VaultView() -> impl IntoView {
    let app = app();
    let detail_open = Signal::derive(move || app.selected.get().is_some() || app.editing.get().is_some());
    let folder_open = RwSignal::new(false);
    let folder_name = RwSignal::new(String::new());
    let folder_action = move |delete: bool| {
        let Filter::Folder(acc, Some(id)) = app.filter.get_untracked() else { return };
        let name = folder_name.get_untracked();
        folder_open.set(false);
        spawn_local(async move {
            let r = if delete { app.delete_folder(&acc, &id).await } else { app.save_folder(&acc, Some(id), name.trim()).await };
            match r {
                Ok(()) => {
                    if delete { app.filter.set(Filter::All) }
                    app.toast(if delete { "Ordner gelöscht – Einträge bleiben erhalten" } else { "Ordner umbenannt" })
                }
                Err(e) => app.error(e),
            }
        });
    };
    view! {
        <div class="flex min-h-0 flex-1">
            <section class=move || format!("flex min-h-0 w-full flex-col border-border md:w-80 lg:w-96 md:shrink-0 md:border-r {}",
                    if detail_open.get() { "hidden md:flex" } else { "flex" })>
                <div class="flex items-center gap-2 p-3 pb-1">
                    <SearchBar />
                    <Button size=ButtonSize::Icon class="size-10 md:size-9 shrink-0" title="Neuer Eintrag"
                        on_click=Callback::new(move |_| { app.selected.set(None); app.editing.set(Some(None)) })><Icon name="plus" /></Button>
                </div>
                <div class="flex items-center justify-between px-4 pt-2 text-xs text-muted-foreground">
                    <span class="flex items-center gap-1.5">{move || filter_title(&app.filter.get())}
                        {move || matches!(app.filter.get(), Filter::Folder(_, Some(_))).then(|| view! {
                            <button class="rounded p-0.5 hover:text-foreground cursor-pointer" title="Ordner bearbeiten" aria-label="Ordner bearbeiten"
                                on:click=move |_| { folder_name.set(filter_title(&app.filter.get_untracked())); folder_open.set(true) }>
                                <Icon name="pencil" class="size-3" />
                            </button>
                        })}
                    </span>
                    <button class="flex items-center gap-1 hover:text-foreground cursor-pointer" title="Synchronisieren"
                        on:click=move |_| spawn_local(async move { app.sync_all().await })>
                        {move || view! { <Icon name="refresh" class=if app.syncing.get() { "size-3.5 animate-spin" } else { "size-3.5" } /> }}
                    </button>
                </div>
                <div class="min-h-0 flex-1 overflow-y-auto pb-nav"><vault::EntryList /></div>
                <Dialog open=folder_open title="Ordner bearbeiten">
                    <div class="grid gap-4">
                        <Input value=folder_name placeholder="Name" />
                        <div class="flex justify-between gap-2">
                            <Button variant=ButtonVariant::Ghost class="text-destructive hover:text-destructive" on_click=Callback::new(move |_| folder_action(true))><Icon name="trash" />"Löschen"</Button>
                            <Button on_click=Callback::new(move |_| folder_action(false))>"Umbenennen"</Button>
                        </div>
                    </div>
                </Dialog>
            </section>
            <section class=move || format!("min-h-0 flex-1 flex-col overflow-y-auto {}", if detail_open.get() { "flex" } else { "hidden md:flex" })>
                <div class="sticky top-0 z-10 flex items-center gap-2 border-b border-border bg-background/90 px-2 py-2 backdrop-blur md:hidden">
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Sm on_click=Callback::new(move |_| { app.editing.set(None); app.selected.set(None) })>
                        <Icon name="arrow-left" />"Zurück"
                    </Button>
                </div>
                <div class="pb-nav">
                    {move || match (app.editing.get(), app.selected.get()) {
                        (Some(k), _) => view! { <vault::EntryEditor key=k /> }.into_any(),
                        (None, Some(k)) => view! { <vault::EntryDetail key=k /> }.into_any(),
                        _ => view! {
                            <div class="hidden h-full md:flex"><div class="m-auto"><Empty icon="key" title="Kein Eintrag ausgewählt" text="Wähle links einen Eintrag oder lege mit + einen neuen an." /></div></div>
                        }.into_any(),
                    }}
                </div>
            </section>
        </div>
    }
}

#[component]
fn BottomNav() -> impl IntoView {
    let app = app();
    let item = move |icon: &'static str, label: &'static str, v: View| {
        let v2 = v.clone();
        view! {
            <button class=move || format!("flex flex-1 flex-col items-center gap-0.5 py-2 text-[11px] cursor-pointer {}",
                    if app.view.get() == v2 { "text-foreground" } else { "text-muted-foreground" })
                on:click=move |_| {
                    if app.view.get_untracked() == View::Vault && v == View::Vault { app.selected.set(None); app.editing.set(None); }
                    app.view.set(v.clone());
                }>
                <Icon name=icon class="size-5" />{label}
            </button>
        }
    };
    view! {
        <nav class="fixed inset-x-0 bottom-0 z-40 flex border-t border-border bg-sidebar/95 backdrop-blur safe-bottom md:hidden">
            {item("vault", "Tresor", View::Vault)}
            {item("wand", "Generator", View::Generator)}
            {item("activity", "Bericht", View::Health)}
            {item("settings", "Einstellungen", View::Settings)}
        </nav>
    }
}

#[component]
pub fn Shell() -> impl IntoView {
    let app = app();
    let popup = env::is_popup();
    let session = app.session;
    view! {
        <div class=if popup { "flex h-[580px] w-[380px] flex-col" } else { "flex h-dvh flex-col md:flex-row" }>
            // Seitenleiste (Desktop)
            {(!popup).then(|| view! {
                <aside class="hidden w-60 shrink-0 flex-col border-r border-border bg-sidebar md:flex">
                    <div class="flex items-center gap-2.5 px-4 pt-4 pb-1">
                        <Logo class="size-7" />
                        <div class="min-w-0">
                            <p class="text-sm font-semibold leading-tight">"nrzPass"</p>
                            <p class="truncate text-[11px] text-muted-foreground">{move || session.get().map(|s| s.email).unwrap_or_default()}</p>
                        </div>
                    </div>
                    <div class="min-h-0 flex-1"><Sidebar /></div>
                    <div class="border-t border-border p-3">
                        <UpdateBanner />
                        <Button variant=ButtonVariant::Ghost class="w-full justify-start" on_click=Callback::new(move |_| app.lock())><Icon name="lock" />"Sperren"</Button>
                    </div>
                </aside>
            })}

            // Kopfzeile (Handy / Popup)
            <header class=if popup { "flex items-center gap-2 border-b border-border px-3 py-2" } else { "flex items-center gap-2 border-b border-border px-3 py-2 safe-top md:hidden" }>
                <button class="rounded-md p-1.5 hover:bg-accent cursor-pointer" aria-label="Menü" on:click=move |_| app.nav_open.update(|o| *o = !*o)><Icon name="menu" class="size-5" /></button>
                <Logo class="size-6" />
                <span class="flex-1 text-sm font-semibold">"nrzPass"</span>
                {popup.then(|| view! {
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon title="Im Tab öffnen" on_click=Callback::new(|_| env::open_extension_tab())><Icon name="external" /></Button>
                })}
                <Show when=move || app.update.get().is_some()>
                    <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon class="relative text-success" title="Update verfügbar"
                        on_click=Callback::new(move |_| app.view.set(View::Settings))>
                        <Icon name="download" /><span class="absolute right-1 top-1 size-1.5 rounded-full bg-success"></span>
                    </Button>
                </Show>
                <Button variant=ButtonVariant::Ghost size=ButtonSize::Icon title="Sperren" on_click=Callback::new(move |_| app.lock())><Icon name="lock" /></Button>
            </header>

            // Schublade (Handy / Popup)
            <Show when=move || app.nav_open.get()>
                <div class=if popup { "fixed inset-0 z-50 bg-black/60 fade-in" } else { "fixed inset-0 z-50 bg-black/60 fade-in md:hidden" } on:click=move |_| app.nav_open.set(false)>
                    <div class="h-full w-72 max-w-[85vw] border-r border-border bg-sidebar safe-top sheet-in" on:click=|ev| ev.stop_propagation()>
                        <div class="flex items-center gap-2.5 px-4 pt-4">
                            <Logo class="size-7" />
                            <p class="truncate text-sm text-muted-foreground">{move || session.get().map(|s| s.email).unwrap_or_default()}</p>
                        </div>
                        <div class="h-[calc(100%-3.5rem)]"><Sidebar /></div>
                    </div>
                </div>
            </Show>

            <main class="flex min-h-0 min-w-0 flex-1 flex-col">
                {move || match app.view.get() {
                    View::Vault => view! { <VaultView /> }.into_any(),
                    View::Generator => view! { <Page><generator::GeneratorPage /></Page> }.into_any(),
                    View::Accounts => view! { <Page><accounts::AccountsPage /></Page> }.into_any(),
                    View::Settings => view! { <Page><settings::SettingsPage /></Page> }.into_any(),
                    View::Health => view! { <Page><health::HealthPage /></Page> }.into_any(),
                    View::Downloads => view! { <Page><settings::DownloadsPage /></Page> }.into_any(),
                }}
            </main>

            {(!popup).then(|| view! { <BottomNav /> })}
        </div>
    }
}

#[component]
fn Page(children: Children) -> impl IntoView {
    view! { <div class="min-h-0 flex-1 overflow-y-auto pb-nav"><div class="mx-auto w-full max-w-3xl p-4 md:p-8">{children()}</div></div> }
}

/// Meldungen unten rechts (Handy: ueber der Navigation).
#[component]
pub fn Toasts() -> impl IntoView {
    let app = app();
    view! {
        <div class="pointer-events-none fixed inset-x-0 bottom-20 z-[60] flex flex-col items-center gap-2 px-4 md:inset-x-auto md:right-4 md:bottom-4 md:items-end">
            <For each=move || app.toasts.get() key=|t| t.id children=|t| view! {
                <div class=format!("toast pointer-events-auto flex max-w-sm items-center gap-2 rounded-lg border px-3 py-2 text-sm shadow-lg {}",
                        if t.error { "border-destructive/40 bg-[#2a1515] text-red-200" } else { "border-border bg-popover" })>
                    <Icon name=if t.error { "alert" } else { "check" } class="size-4" />{t.text}
                </div>
            } />
        </div>
    }
}

/// Hinweis "Update verfuegbar" (fuehrt zu den Einstellungen).
#[component]
fn UpdateBanner() -> impl IntoView {
    let app = app();
    view! {
        <Show when=move || app.update.get().is_some()>
            <button class="mb-2 flex w-full items-center gap-2.5 rounded-md border border-success/30 bg-success/10 px-2.5 py-2 text-left text-sm text-success cursor-pointer hover:bg-success/15"
                on:click=move |_| app.view.set(View::Settings)>
                <Icon name="download" />
                <span class="flex-1">{move || format!("Update {} verfügbar", app.update.get().map(|u| u.version).unwrap_or_default())}</span>
            </button>
        </Show>
    }
}
