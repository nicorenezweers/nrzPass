//! Passwort- und Passphrasen-Generator.

use crate::state::app;
use crate::ui::icons::Icon;
use crate::ui::kit::*;
use leptos::prelude::*;
use nrzpass_core::generator;

#[component]
pub fn GeneratorPage() -> impl IntoView {
    let app = app();
    let st = app.settings.get_untracked();
    let phrase = RwSignal::new(st.use_passphrase);
    let length = RwSignal::new(st.generator.length);
    let upper = RwSignal::new(st.generator.upper);
    let lower = RwSignal::new(st.generator.lower);
    let digits = RwSignal::new(st.generator.digits);
    let symbols = RwSignal::new(st.generator.symbols);
    let ambiguous = RwSignal::new(st.generator.avoid_ambiguous);
    let words = RwSignal::new(st.passphrase.words);
    let separator = RwSignal::new(st.passphrase.separator.clone());
    let capitalize = RwSignal::new(st.passphrase.capitalize);
    let number = RwSignal::new(st.passphrase.number);
    let value = RwSignal::new(String::new());

    let regen = move || {
        let po = generator::PasswordOptions {
            length: length.get(),
            upper: upper.get(),
            lower: lower.get(),
            digits: digits.get(),
            symbols: symbols.get(),
            avoid_ambiguous: ambiguous.get(),
        };
        let pp = generator::PassphraseOptions { words: words.get(), separator: separator.get(), capitalize: capitalize.get(), number: number.get() };
        value.set(if phrase.get() { generator::passphrase(&pp) } else { generator::password(&po) });
        app.settings.update(|s| {
            s.generator = po;
            s.passphrase = pp;
            s.use_passphrase = phrase.get_untracked();
        });
        app.save_settings();
    };
    Effect::new(move |_| regen());

    let toggle = |label: &'static str, sig: RwSignal<bool>| {
        view! { <label class="flex items-center justify-between gap-3 py-2 text-sm"><span>{label}</span><Switch checked=sig label=label /></label> }
    };

    view! {
        <div class="grid gap-6">
            <div>
                <h1 class="text-xl font-semibold">"Generator"</h1>
                <p class="text-sm text-muted-foreground">"Kryptografisch sicherer Zufall direkt auf deinem Gerät."</p>
            </div>
            <Card class="p-5">
                <div class="min-h-14 rounded-lg bg-background p-4 text-lg leading-relaxed">
                    <ColoredPassword value=value />
                </div>
                <div class="mt-3"><StrengthMeter password=value.into() /></div>
                <div class="mt-4 flex gap-2">
                    <Button class="flex-1" on_click=Callback::new(move |_| app.copy("Passwort", value.get_untracked()))><Icon name="copy" />"Kopieren"</Button>
                    <Button variant=ButtonVariant::Outline on_click=Callback::new(move |_| regen())><Icon name="refresh" />"Neu"</Button>
                </div>
            </Card>
            <Card class="p-5">
                <div class="mb-4 grid grid-cols-2 gap-1 rounded-lg bg-secondary p-1">
                    {[(false, "Passwort"), (true, "Passphrase")].into_iter().map(|(v, l)| view! {
                        <button class=move || format!("rounded-md py-1.5 text-sm cursor-pointer {}", if phrase.get() == v { "bg-background font-medium" } else { "text-muted-foreground" })
                            on:click=move |_| phrase.set(v)>{l}</button>
                    }).collect_view()}
                </div>
                <Show when=move || !phrase.get() fallback=move || view! {
                    <div class="grid gap-1 divide-y divide-border">
                        <label class="grid gap-2 py-2 text-sm">
                            <span class="flex justify-between"><span>"Wörter"</span><span class="tabular-nums text-muted-foreground">{move || words.get()}</span></span>
                            <input type="range" min="3" max="12" class="accent-white" prop:value=move || words.get().to_string()
                                on:input=move |ev| words.set(event_target_value(&ev).parse().unwrap_or(5)) />
                        </label>
                        <label class="flex items-center justify-between gap-3 py-2 text-sm"><span>"Trennzeichen"</span>
                            <input class="h-8 w-16 rounded-md border border-input bg-transparent text-center font-mono" maxlength="3"
                                prop:value=move || separator.get() on:input=move |ev| separator.set(event_target_value(&ev)) />
                        </label>
                        {toggle("Großbuchstaben am Wortanfang", capitalize)}
                        {toggle("Zahl einfügen", number)}
                        <p class="pt-2 text-xs text-muted-foreground">"EFF-Wortliste (7776 Wörter, ca. 12,9 Bit pro Wort)."</p>
                    </div>
                }>
                    <div class="grid gap-1 divide-y divide-border">
                        <label class="grid gap-2 py-2 text-sm">
                            <span class="flex justify-between"><span>"Länge"</span><span class="tabular-nums text-muted-foreground">{move || length.get()}</span></span>
                            <input type="range" min="8" max="64" class="accent-white" prop:value=move || length.get().to_string()
                                on:input=move |ev| length.set(event_target_value(&ev).parse().unwrap_or(20)) />
                        </label>
                        {toggle("A–Z", upper)}
                        {toggle("a–z", lower)}
                        {toggle("0–9", digits)}
                        {toggle("!@#$%^&*", symbols)}
                        {toggle("Verwechselbare Zeichen vermeiden (Il1O0)", ambiguous)}
                    </div>
                </Show>
            </Card>
        </div>
    }
}
