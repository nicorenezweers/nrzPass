// nrzPass – Hintergrund-Dienst. Nur ein Lader: die Logik steckt in Rust (bg/nrzpass_bg_bg.wasm).
// Die Listener muessen synchron registriert werden, damit ein geweckter Service Worker keine
// Nachricht verpasst; sie warten auf das WASM und geben dann an Rust weiter.
import init, * as nrz from './bg/nrzpass_bg.js';

const api = globalThis.browser ?? globalThis.chrome;
const ready = init({ module_or_path: api.runtime.getURL('bg/nrzpass_bg_bg.wasm') }).then(() => nrz.bg_init());

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  ready.then(() => nrz.bg_message(msg, sender)).then(sendResponse, (e) => sendResponse({ error: String(e) }));
  return true;
});
api.alarms.onAlarm.addListener((alarm) => { ready.then(() => nrz.bg_alarm(alarm.name)); });
api.tabs.onActivated.addListener((info) => { ready.then(() => nrz.bg_tab(info.tabId)); });
api.tabs.onUpdated.addListener((id, info) => { if (info.status === 'complete') ready.then(() => nrz.bg_tab(id)); });
