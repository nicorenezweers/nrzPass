//! Sicherheitsbericht: schwache, mehrfach verwendete und alte Passwoerter, fehlende 2FA.
//! Alles lokal berechnet – keine Daten verlassen das Geraet.

use crate::state::{app, Entry, View};
use crate::ui::icons::Icon;
use crate::ui::kit::*;
use crate::ui::vault::Avatar;
use leptos::prelude::*;
use nrzpass_core::api::cipher_type;
use std::collections::HashMap;

#[component]
fn Group(#[prop(into)] title: String, #[prop(into)] text: String, items: Vec<(Entry, String)>, variant: BadgeVariant) -> impl IntoView {
    let app = app();
    let n = items.len();
    let ok = n == 0;
    view! {
        <Card>
            <CardHeader class="flex-row items-center justify-between gap-2 space-y-0">
                <div><CardTitle class="text-sm">{title}</CardTitle><CardDescription class="text-xs">{text}</CardDescription></div>
                {if ok { view! { <Badge variant=BadgeVariant::Success><Icon name="check" class="size-3" />"OK"</Badge> }.into_any() }
                 else { view! { <Badge variant=variant>{n}</Badge> }.into_any() }}
            </CardHeader>
            {(!ok).then(|| view! {
                <div class="divide-y divide-border border-t border-border">
                    {items.into_iter().take(50).map(|(e, why)| {
                        let k = e.key();
                        view! {
                            <button class="flex w-full items-center gap-3 px-5 py-2.5 text-left hover:bg-accent/50 cursor-pointer"
                                on:click=move |_| { app.view.set(View::Vault); app.editing.set(None); app.selected.set(Some(k.clone())) }>
                                <Avatar name=e.name() kind=e.cipher.cipher_type />
                                <div class="min-w-0 flex-1"><p class="truncate text-sm">{e.name()}</p><p class="truncate text-xs text-muted-foreground">{e.subtitle()}</p></div>
                                <span class="shrink-0 text-xs text-muted-foreground">{why}</span>
                            </button>
                        }
                    }).collect_view()}
                </div>
            })}
        </Card>
    }
}

#[component]
pub fn HealthPage() -> impl IntoView {
    let app = app();
    let report = Memo::new(move |_| {
        let logins: Vec<Entry> = app.entries.with(|e| {
            e.iter().filter(|x| !x.deleted() && !x.broken && x.cipher.cipher_type == cipher_type::LOGIN).cloned().collect()
        });
        let pw = |e: &Entry| e.cipher.login.as_ref().and_then(|l| l.password.clone()).filter(|p| !p.is_empty());
        let mut weak = vec![];
        let mut counts: HashMap<String, usize> = HashMap::new();
        for e in &logins {
            if let Some(p) = pw(e) {
                *counts.entry(p.clone()).or_default() += 1;
                let s = nrzpass_core::strength::estimate(&p);
                if s.score <= 1 {
                    weak.push((e.clone(), s.label.to_string()));
                }
            }
        }
        let reused: Vec<(Entry, String)> = logins
            .iter()
            .filter_map(|e| pw(e).and_then(|p| counts.get(&p).copied()).filter(|n| *n > 1).map(|n| (e.clone(), format!("{n}× verwendet"))))
            .collect();
        let insecure: Vec<(Entry, String)> = logins
            .iter()
            .filter(|e| e.uris().iter().any(|(u, _)| u.starts_with("http://") && !u.contains("localhost") && !u.contains(".local")))
            .map(|e| (e.clone(), "http://".into()))
            .collect();
        let no_totp: Vec<(Entry, String)> = logins
            .iter()
            .filter(|e| e.cipher.login.as_ref().map(|l| l.totp.as_deref().unwrap_or("").is_empty()).unwrap_or(true))
            .filter(|e| {
                // Bekannte Dienste mit 2FA-Unterstuetzung
                const TFA: &[&str] = &["google.", "github.", "microsoft.", "apple.", "amazon.", "facebook.", "instagram.", "twitter.", "x.com", "dropbox.", "paypal.", "discord.", "gitlab.", "proton", "digitec.", "galaxus.", "postfinance.", "ubs.", "raiffeisen.", "binance.", "coinbase.", "steam", "twitch.", "slack.", "linkedin.", "reddit.", "cloudflare.", "hetzner.", "openai.", "anthropic."];
                e.uris().iter().any(|(u, _)| TFA.iter().any(|t| u.to_lowercase().contains(t)))
            })
            .map(|e| (e.clone(), "2FA möglich".into()))
            .collect();
        let total = logins.len();
        let issues = weak.len() + reused.len() + insecure.len();
        let score = if total == 0 { 100 } else { (100 * total.saturating_sub(issues.min(total)) / total) as u32 };
        (score, total, weak, reused, insecure, no_totp)
    });

    view! {
        <div class="grid gap-5">
            <div>
                <h1 class="text-xl font-semibold">"Sicherheitsbericht"</h1>
                <p class="text-sm text-muted-foreground">"Lokal berechnet – nichts verlässt dein Gerät."</p>
            </div>
            {move || {
                let (score, total, weak, reused, insecure, no_totp) = report.get();
                let two_factor = app.primary().map(|p| p.two_factor).unwrap_or(false);
                view! {
                    <Card class="flex items-center gap-5 p-5">
                        <div class=format!("grid size-16 place-items-center rounded-full border-4 text-lg font-semibold {}",
                            if score >= 90 { "border-success text-success" } else if score >= 60 { "border-warning text-warning" } else { "border-destructive text-destructive" })>{score}</div>
                        <div class="grid gap-1 text-sm">
                            <p class="font-medium">{format!("{total} Logins geprüft")}</p>
                            <p class="text-muted-foreground">{if two_factor { "Zwei-Faktor für nrzPass ist aktiv." } else { "Tipp: Aktiviere Zwei-Faktor für dein nrzPass-Konto (Einstellungen)." }}</p>
                        </div>
                    </Card>
                    <Group title="Schwache Passwörter" text="Leicht zu erraten – mit dem Generator ersetzen." items=weak variant=BadgeVariant::Destructive />
                    <Group title="Mehrfach verwendet" text="Ein Datenleck bei einem Dienst gefährdet alle anderen." items=reused variant=BadgeVariant::Destructive />
                    <Group title="Unverschlüsselte Webseiten" text="Anmeldung über http:// kann mitgelesen werden." items=insecure variant=BadgeVariant::Warning />
                    <Group title="Zwei-Faktor verfügbar" text="Diese Dienste unterstützen 2FA – Schlüssel in nrzPass speichern." items=no_totp variant=BadgeVariant::Secondary />
                }
            }}
        </div>
    }
}
