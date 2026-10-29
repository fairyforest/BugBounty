# Pixabay Bug Bounty — Engagement Notes

**Standing preference (2026-10-26):** always respond to the user in English, regardless of their message language.

**Target:** `*.pixabay.com` (Bugcrowd program) · **Tester account id:** `58216674` (slug `u_lp7b4028ve-58216674`)
**Date started:** 2026-10-24 · **Last worked:** 2026-10-25 · **Status:** media IDOR + /api/docs closed; now auditing the **messaging** flow.

## >>> RESUME HERE (2026-10-26) <<<
Active thread: **messaging authz/IDOR**. Client route table extracted (see "Messaging route map" below). Next: run the safe scoped IDOR tests, starting with the message-id delete endpoint.
- **Immediate next action (go-ahead given 2026-10-26):** execute stored-XSS probe. Ready snippets in `snippets/xss_probe_console.js` — Step 1 (A on B's compose page): install fetch interceptor, swap outgoing `text` for `<svg onload="console.log('XSSPROBE-FIRED')">`, send via normal UI (fresh security_hash+turnstile ride along). Step 2 (B): read `/en/accounts/messages/conversations/58216674/` JSON, check payload survives verbatim. Step 3: hide probe msg via `status/{id}/?action=delete` in BOTH A and B sessions.
- **Top leads, ranked (re-reshuffled 2026-10-26 after call-shape extraction):**
  1. **Stored-XSS in DMs — CLIENT SINK CONFIRMED UNSANITIZED (2026-10-26).** `chunk-messages` @9946 renders message text via `dangerouslySetInnerHTML:{__html:o}` (o=message.text), NO DOMPurify/sanitize anywhere in bundles. Composer is `contentEditable` → sends its `innerHTML` as `text` (inline images = real `<img>` tags, hence HTML). **Only remaining gate = server-side sanitization of `text`.** PROBE READY 2026-10-26 (go-ahead given): payload `<svg onload="console.log('XSSPROBE-FIRED')">` via fetch-interceptor on A's compose send (`snippets/xss_probe_console.js`). VERDICT: B-side JSON `text` survives verbatim → stored XSS PROVEN (sink already confirmed unsanitized @9946); tags altered/stripped → gate holds. Cleanup = `status/{id}/?action=delete` in A AND B sessions.
  2. **Spam-report IDOR** — `POST status/{pk}/?action=delete&spam=1` on an arbitrary sequential message id you're not party to → false spam reports / auto-mod abuse. MEDIUM. Scoped test needs care (don't spam real msgs).
  3. ~~plain `status/{pk}/?action=delete`~~ — resolved LOW: per-user HIDE only ("others still see it"), IDOR = no-op.
  4. ~~`search` `target`~~ — CLOSED (enum conversation|message, self-scoped). ~~`bulk-action`~~ — LOW (other-user-id keyed, own-copy scoped).
- **SIDE-LEAD (park):** route table exposes many `/xmin/*` admin routes (`loginAsUser:/xmin/accounts/login_as/{username}/`, `deleteAccount`, `set_trusted`, `lock_all_uploads`, `taggingUserQaDashboard:/xmin/accounts/tagging?...`). Broken-access-control probe = potential priv-esc/ATO. Probe ONLY a read-only xmin route (tagging dashboard GET) first to avoid firing a real admin action.
- **Test accounts:** A = `58216674` (slug `u_lp7b4028ve-58216674`). B = `samthediver-58231454`.
- **Test artifacts left in place:** A has unsubmitted draft `10541613` (delete anytime). A↔B conversation exists w/ test messages `88350232`, `88350233`.
- **Browser/proxy state:** LibreWolf proxy currently **OFF** (turned off so upload UI JS worked); Burp intercept **off**. All live testing is done via **DevTools console `fetch()`** as the relevant account (Cloudflare blocks tool-originated traffic). Re-enable proxy only to passively capture a specific request.
- **CREDENTIAL (do not commit):** A's public API key was observed as `<58216674>-<secret>` on `/api/docs/`; secret NOT stored here. User may rotate it.

## Authorization
In-scope Bugcrowd program (`*.pixabay.com/`). Caveat carried throughout: **confirm program rules permit automated active scanning before any ZAP active scan.** So far only spider + passive + manual browsing (no attacks sent except the one non-destructive console probe below).

## Tooling / setup
- **OWASP ZAP 2.17.0** on `127.0.0.1:8080` (REST API + proxy share the port). Helper: `~/.claude/skills/zap/scripts/zap_api.sh`.
- ZAP root CA exported to `./zap_root_ca.cer` (imported into **LibreWolf**).
- **LibreWolf** proxies through ZAP; manual browsing captured + passively scanned. Context "Pixabay" scoped to `https?://([^/]+\.)?pixabay\.com/.*`, passive = in-scope only.
- **Cloudflare note:** site is behind Cloudflare. ZAP's spider and any ZAP-/curl-originated request get challenge/`403 "you have been blocked"` (TLS fingerprint). **Only real-browser traffic passes.** => test via **browser DevTools console `fetch()`** (same-origin, uses session cookies), NOT ZAP replay.
- Auth cookies seen: `sessionid`, `csrftoken`, `user_id`, `anonymous_user_id`. State-changing calls need header `x-csrftoken` = value of `csrftoken` cookie.

## Key authenticated endpoints
- `GET  /accounts/messages/conversations/` → JSON, paginated via `afterToken`. (list is self-scoped.)
- `POST /accounts/messages/compose/<recipient_user_id>/` — **send** (captured 2026-10-25). multipart FormData: `subject, text, submitted=1, timestamp, security_hash` (server-issued, 40-hex), `turnstile-response` (Cloudflare Turnstile, single-use per compose-page load). Recipient id is in the URL path = user-controlled. Open Qs: does `security_hash` bind to recipient? can it message users who blocked/disabled DMs? (turnstile limits blind replay → recipient-spam angle is low-value). B = `samthediver-58231454`, A = `58216674`.
- `GET  /accounts/messages/conversations/<other_user_id>/` — **thread read** (captured 2026-10-25). Returns `{messages:[{id,fromUserId,timestamp,text,lang,isHtml,isRead,attachments}], user:{...}}`. Addressed by *other participant's user id*, **paired with session user** → correctly scoped (changing id just selects which of YOUR convos). `?afterToken=<int message id>` pagination (400 on non-int). NOT IDOR via this path.
  - **Open IDOR angle:** message ids are **global + sequential** (88350231/232/233). Hunting for any endpoint that acts on a raw **message id** w/o participant check (mark-read/delete/report/attachment). Enumerating from JS bundle `chunk-8649.*.js`. Also test `afterToken` with a foreign message id for cross-convo leak.
  - Note: thread read returns `isHtml:true` + raw HTML (`<div>…</div>`) in `text` — check how it's rendered (stored-XSS-in-DM angle) once endpoint map is done.
- **Messaging endpoint map** (from JS bundle `chunk-8649`, 2026-10-25): `/accounts/messages/` + `compose/<uid>/`, `conversations/`, `conversations/<uid>/`, `conversations/bulk-action/` (IDOR candidate — bulk delete/mark-read by id list), `inbox/` (UI), `search/` (scope? leak?), `status/` (read-status / presence?). Next: read call shapes from JS, then safe scoped IDOR tests across A/B.
- **Messaging route table** (extracted 2026-10-26 from `chunk-client_startup.*.js` URL map + logic in `chunk-8649`; all prefixed `{langPrefix}` e.g. `/en`):
  - `conversationList` = `/accounts/messages/conversations/?afterToken={afterToken}` (self-scoped)
  - `conversationShow` = `/accounts/messages/conversations/{id}/?beforeToken=&afterToken=&focusMessageId=` — `{id}` = other participant's user id (paired → scoped)
  - `conversationBulkAction` = `POST /accounts/messages/conversations/bulk-action/`, JSON body `{ids:[<convId>], action:"read"|"unread"|…}` (confirmed in `markConversationAsUnread`: `bulkActionFetcher.post(url,{ids:[e],action:"unread"})`). Operates on **conversation ids** → low impact.
  - `conversationSearch` = `/accounts/messages/search/?query={query}&target={target}&afterToken={afterToken}` — **`target` param unprobed**.
  - `deleteMessage` = `POST /accounts/messages/status/{id}/?action=delete`, empty body `{}`, CSRF (`actionDataFetcher.post`). **Semantics = per-user HIDE** — modal text: "This will remove the message from your view. Other chat users will still be able to see it." → plain-delete IDOR = LOW impact (hiding a msg you can't see = no-op).
  - `messagesStatus` = `/accounts/messages/status/{pk}/` — `{pk}` = message id. **Spam variant:** `POST status/{pk}/?action=delete&spam=1` (`messageSpamFetcher.post`, @485605). ← IDOR test here = can you spam-report an arbitrary (sequential) message id you're not party to? MEDIUM abuse potential.
  - `reportMessage` = `/content-reports/?related_content_type={contentTypeId}&related_content_id={messageId}&content_url={contentUrl}` (low value).
  - `conversationSearch` call: `GET`, `target` ∈ {"conversation","message"} enum (result type, NOT user scope) → search self-scoped, `target` IDOR angle CLOSED.
  - `messageSend` = `/accounts/messages/compose/{userId}/`; `messageInbox` = `/accounts/messages/inbox/?conversation={conversationId}&message={messageId}` (UI).
- **`/xmin/*` ADMIN route surface** (same table — broken-access-control side-lead): `loginAsUser=/xmin/accounts/login_as/{username}/`, `deleteAccount=/xmin/accounts/{userId}/delete/`, `deleteSpammer=/xmin/accounts/{userId}/delete/?blacklist`, `toggleTrust=/xmin/accounts/{userId}/set_trusted/`, `lockAllMedia=/xmin/accounts/{userId}/lock_all_uploads/`, `taggingUserQaDashboard=/xmin/accounts/tagging?...` (read-only → safest first probe), plus many `/xmin/{project}/...` media-moderation routes. Probe read-only route for 200-vs-403 before anything state-changing.
- Upload chain:
  - `POST /accounts/media/fileuploader/` (multipart, field `file`) → `{success,id,photo.thumbnail,file_resolution}`. **Server rasterizes/re-encodes + min 3000px dimension check.**
  - `POST /accounts/media/save_unsubmitted/photo/<id>/` (JSON: title_field, description, tags_field, is_ai_generated, image_type, …)
  - `POST /accounts/media/submit/` (JSON: `{"media":[{"id":<id>,"type":"photo","isAiGenerated":false}]}`)
  - also: `/accounts/media/`, `/accounts/media/statistics/`, `/accounts/media/tags/suggest/`
- `GET  /autocomplete/?lang=en&search_term=user_id:<id>&media_type=...` — supports a `user_id:` operator (unprobed).
- `POST /accounts/notifications/` (polled; body/accepts unexamined).
- `GET  /api/docs/` (200), `/api/` (400) — public API docs, not yet read.
- `GET  /security-bootstrap/`, `/preflight/`, `/bootstrap/<sha256>.json` — app config blobs, not yet inspected.
- Uploads served from **separate origin `cdn.pixabay.com`** as processed JPGs.

## Findings status
1. **SVG/upload XSS — RULED OUT.** Uploads are rasterized/re-encoded and served from CDN sandbox origin.
2. **IDOR on media id (`save_unsubmitted`, `submit`) — CLOSED, NEGATIVE (2026-10-25).**
   - Two-account test done. Draft `10541613` created (unsubmitted) on account A via console `fileuploader`. From **account B's** session:
     - `POST /accounts/media/save_unsubmitted/photo/10541613/` → **404 (empty body)**. Owner-scoped lookup rejects foreign id.
     - `POST /accounts/media/submit/` `{media:[{id:10541613,type:"photo",...}]}` → **200** but body `{"errors":{"media_errors":[{"id":10541613,"errors":{"general":[{"message":"Media item not found"}]}}]}}`. Lookup scoped to B's user → not found. Not vulnerable.
   - Handler-shape note (not a vuln): `submit` reports not-found via `200` + per-item error object rather than a `404`.
   - Earlier nonexistent-id probe (`999999999` → 404) is consistent. Confirmed owner-scoped `get_object_or_404(Media, id, user=request.user)`.
3. Info-only: CSP `report-uri` on `/accounts/media/upload/` leaks Sentry DSN + release `release-20261021-61903ce902` (public DSN = informational, don't report standalone).
4. Security headers strong across app (XFO DENY, CSP frame-ancestors none, nosniff, HSTS, COOP, no-store).

## Next session TODO
- [x] ~~Finish IDOR test with a 2nd account (save_unsubmitted + submit)~~ — DONE 2026-10-25, NEGATIVE (see Findings #2).
- [x] ~~Read `/api/docs/`~~ — DONE 2026-10-25. It's the **public key-based REST search API** (`GET /api/?key=<uid>-<secret>&q=...`), HTML docs (not Swagger). Standard params only (`key,q,lang,image_type,page,per_page,...`); no user_id/private surface → **low value**. Key format = `<account_id>-<24hex secret>` (uid prefix is public → leaked keys are always attributable). `/api/?format=json` without key → 400 "Invalid or missing API key". Nothing to report.
- [ ] Probe `autocomplete` `user_id:` operator (enumeration/injection).
- [ ] Capture the **messaging send** flow (start a conversation → find recipient param → IDOR/param-tamper).
- [ ] Inspect `/security-bootstrap/`, `/preflight/`, `/bootstrap/*.json` responses for leaked config/flags.
- [ ] Try `save_unsubmitted` with `video`/`audio`/`3d` types (different code paths).

## Files here
- `endpoint_index.json` — slim method/path/status list (395 entries, no bodies).
- `chunk-media_upload.js` — upload JS bundle (client-side validation only; endpoints resolved via live capture).
- `zap_root_ca.cer` — ZAP CA for browser trust.
- `snippets/xss_probe_console.js` — ready-to-paste DevTools code for the stored-XSS probe (steps 1–3).
- Raw ZAP traffic persists in the running ZAP session (re-query via `zap_api.sh`) until a new session is started.
