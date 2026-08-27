# Module 04 — Deep Link Verification

> **Target vulnerability class:** Deep link parameter tampering, state corruption, open redirect, and authorization bypass
> **Risk profile:** **Medium-High** — low exploitation cost, frequently reaches authentication flows
> **CWE mapping:** CWE-939 (Improper Authorization in Handler for Custom URL Scheme), CWE-601 (URL Redirection to Untrusted Site), CWE-20 (Improper Input Validation), CWE-926 (Improper Export of Android Application Components), CWE-940 (Improper Verification of Source of a Communication Channel)
> **OWASP MASVS:** MASVS-PLATFORM-1, MASVS-PLATFORM-3, MASVS-AUTH-1

---

## 1. Root Cause

A deep link is an **unauthenticated remote procedure call from an unknown caller**. Anything can
originate one: a web page the user visits, an SMS, a QR code, a push notification, a malicious app
installed on the same device, an email link, an NFC tag.

Code generation models treat it as internal navigation. Asked to "open the order screen from a
link", the model writes the direct translation:

```js
// The link IS the request. The request is attacker-controlled.
Linking.addEventListener('url', ({ url }) => {
  const { path, queryParams } = Linking.parse(url);
  navigation.navigate(path, queryParams);      // arbitrary route + arbitrary params
});
```

Every value in `queryParams` is now attacker-supplied and reaches a screen that assumes its props
came from inside the app. The exploitable shapes follow immediately:

| Payload | Effect |
|---|---|
| `app://profile?userId=1042` | IDOR — renders another account if the screen trusts the prop |
| `app://reset-password?token=X&email=victim@x` | Password-reset flow driven with attacker parameters |
| `app://payment/confirm?amount=0&orderId=88` | State mutation triggered by navigation |
| `app://settings?isPremium=true` | Client-side entitlement flipped |
| `app://webview?url=https://evil.tld` | Attacker page rendered inside the trusted app chrome, inheriting its session |
| `app://auth/callback?returnTo=https://evil.tld` | Open redirect that carries the authorization code out |
| `app://admin` | Screen that was only ever hidden from the menu |

Two further facts make this worse than it looks:

**Custom schemes have no owner.** `app://` is claimed on a first-come basis on iOS and shared by
intent filter on Android. Any installed app can register the same scheme and receive links intended
for yours. This is why an OAuth authorization code delivered to a custom scheme without PKCE is
interceptable — it is the reason PKCE exists.

**Verified links are not validated inputs.** App Links (`assetlinks.json`) and Universal Links
(`apple-app-site-association`) prove the *domain* is yours. They prove nothing about who
constructed the URL — an attacker writes `https://yourapp.com/pay?amount=0` just as easily as
`app://pay?amount=0`, and the OS delivers it to your handler with full verification.

On desktop the same surface exists with a sharper edge. `app.setAsDefaultProtocolClient` makes
Windows deliver the URL as a **command-line argument**. A handler that reads `process.argv` without
validating it can be fed `--gpu-launcher="cmd /c calc"`, `--inspect`, or `--no-sandbox` by a web
page — parameter injection straight into the trusted main process, bypassing every renderer control
in [Module 02](02-desktop-process-isolation.md).

---

## 2. Non-Negotiable Rules

### R4.1 — Every incoming URL is untrusted input

Custom schemes, App Links, Universal Links, `NSUserActivity` continuation, Android intent extras,
push-notification payload URLs, QR-scanned URLs, and desktop protocol argv are **all** external
input from an unauthenticated source. There is no trusted variant.

Apply the same discipline you would apply to an unauthenticated HTTP endpoint: parse, validate,
authorize, then act.

### R4.2 — Use verified links for anything security-relevant

- Register App Links with `assetlinks.json` and `android:autoVerify="true"`; register Universal Links with a served `apple-app-site-association` and the correct associated-domains entitlement.
- Custom schemes may be retained for legacy support, but must never carry authentication material.
- **OAuth and OIDC:** PKCE is mandatory (`code_challenge_method=S256`). The `state` parameter is cryptographically random, bound to the session, verified on return, and single-use. Confidential-client secrets never live on the device — see [Module 03](03-binary-trust-and-gateways.md).
- Run the authorization request in `ASWebAuthenticationSession` (iOS) or Chrome Custom Tabs / `androidx.browser` (Android). **Never in an embedded WebView** — an embedded WebView lets the app read the user's credentials as they are typed, which is exactly why identity providers block it.

### R4.3 — Strict schema validation at the boundary, before anything else runs

One entry point handles every incoming URL. It parses, validates against an explicit schema, and
either produces a fully typed internal command or rejects.

```ts
import { z } from 'zod';

const Routes = {
  'order-detail': z.object({ orderId: z.string().uuid() }),
  'product':      z.object({ sku: z.string().regex(/^[A-Z0-9-]{4,24}$/) }),
  'campaign':     z.object({ id: z.enum(['spring', 'summer', 'winter']) }),
} as const;                                   // exhaustive allowlist — nothing else routes

export function resolveDeepLink(raw: string): InternalCommand | null {
  let url: URL;
  try { url = new URL(raw); } catch { return null; }

  if (url.protocol !== 'https:' || url.hostname !== 'links.example.com') return null;
  if (url.username || url.password) return null;              // reject user:pass@ tricks

  const key = url.pathname.split('/').filter(Boolean)[0];
  const schema = Object.prototype.hasOwnProperty.call(Routes, key)
    ? Routes[key as keyof typeof Routes] : undefined;
  if (!schema) return null;                                    // unknown route -> reject

  const parsed = schema.safeParse(Object.fromEntries(url.searchParams));
  if (!parsed.success) return null;                            // never partially apply

  return { route: key, params: parsed.data };                  // typed, closed set
}
```

Requirements this encodes, all mandatory:

- **Allowlist of routes.** A map, not string matching. No dynamic route construction from the path. No `navigate(path)` where `path` came from the URL.
- **Typed parameters.** Every parameter has a type, a format, and bounds. Identifiers are UUID or ULID, never sequential integers, never free strings.
- **Reject, do not repair.** A malformed link produces one generic outcome — open the home screen. Never coerce, never default a missing parameter, never partially apply a valid subset.
- **Fail closed on unknown routes.** New routes are added to the map deliberately.
- **No `hasOwnProperty` bypass.** Use `Object.prototype.hasOwnProperty.call` or a `Map` — a route named `constructor` or `__proto__` must not resolve.
- Perform this before any screen renders, any store is written, or any request fires.

### R4.4 — A link may navigate. A link may never authorize or mutate.

This is the rule that closes the entire vulnerability class.

**Prohibited absolutely:**

- Reading identity, role, entitlement, or permission from a URL parameter: `?isAdmin=`, `?role=`, `?isPremium=`, `?userId=`, `?tenantId=`, `?verified=1`
- Performing a write, purchase, transfer, deletion, subscription change, or setting change as a direct effect of link handling
- Establishing or elevating a session from a link parameter — no auto-login, no token in the URL, no "magic" bypass path
- Trusting a `token`, `signature`, or `hash` parameter without server-side verification, single-use enforcement, and short expiry

**Required instead:** the link resolves to a *destination and an intent*. The screen loads, fetches
its own data from the server using the **session identity**, and any state change requires an
explicit user action that is authorized server-side at execution time.

The correct handling of `app://pay?orderId=X` is: open the payment screen, fetch order `X` from the
server (which returns 404 if the session does not own it), display the server-supplied amount, and
wait for the user to press Pay. The amount never comes from the URL.

### R4.5 — Redirect destinations come from an allowlist, never from the URL

Open redirects in a native app leak authorization codes, session identifiers, and referrer data,
and lend your app's credibility to a phishing page.

- Resolve redirect targets through a **map of known destinations** keyed by a short identifier: `?to=support` resolves to a constant, not to a URL the client supplies.
- Where a URL genuinely must be accepted, parse with the `URL` constructor and compare `url.hostname` for **exact equality** against an allowlist. Never `startsWith`, never `includes`, never a regex on the raw string, never `endsWith('.example.com')` — `evil-example.com` and `example.com.evil.tld` both defeat those.
- Reject any protocol other than `https:`. Explicitly reject `javascript:`, `data:`, `file:`, `blob:`, `intent:`, `content:`, and `vbscript:`.
- Reject URLs containing credentials, and normalise punycode before comparison.
- Never load a URL-supplied address into a WebView. If an in-app browser is required, it renders only allowlisted hosts, with JavaScript bridges disabled for external content.

### R4.6 — Android component hygiene

- Declare `android:exported` explicitly on every activity, service, receiver, and provider. Exported is a deliberate decision, never an inherited default.
- Any activity reachable by intent filter treats **every** extra in `getIntent()` as untrusted — including `Parcelable` extras, which are a deserialization surface.
- **Never** forward an intent built from untrusted data (`Intent.parseUri`, an extra containing an `Intent`, a redirect target) into `startActivity` — this is implicit intent redirection (CWE-926) and it lets an external app launch your non-exported components.
- `PendingIntent` is created with `FLAG_IMMUTABLE` (or `FLAG_MUTABLE` only with a fully specified explicit component).
- The task and launch mode matter: `singleTask` with a permissive intent filter enables task-hijacking. Set `android:taskAffinity=""` on activities reachable from deep links, and prefer `singleTop` with explicit handling in `onNewIntent`.
- Deep-link handling belongs in `onNewIntent` **as well as** `onCreate` — a warm-start link that skips validation is the common regression.

### R4.7 — iOS handler hygiene

- Validate `NSUserActivity.webpageURL` host and path against the allowlist before use — do not assume the entitlement guarantees the shape of the URL.
- `application(_:open:options:)` receives a `sourceApplication` value that is advisory only. Do not use it as an authorization signal.
- Universal Links may arrive during cold start, warm start, and state restoration. Route all three through the same resolver.
- Never register a scheme that collides with a common vendor prefix; assume any custom scheme you register is also registered by someone else.

### R4.8 — Desktop protocol handlers: argv is hostile

On Windows and Linux, a registered protocol delivers the URL as a process argument. Treat the
argument vector as attacker-controlled input to the **main process**.

```js
const { app } = require('electron');

app.on('second-instance', (_event, argv) => {
  const candidate = argv.find(a => !a.startsWith('-') && a.startsWith('myapp://'));
  if (!candidate) return;
  const cmd = resolveDeepLink(candidate);        // R4.3 resolver, same allowlist
  if (cmd) routeInternally(cmd);                  // never loadURL(candidate)
});

app.on('open-url', (event, url) => {              // macOS
  event.preventDefault();
  const cmd = resolveDeepLink(url);
  if (cmd) routeInternally(cmd);
});
```

- Ignore every argument beginning with `-` or `--`. A web page that triggers your protocol can otherwise inject Chromium and Node switches — `--gpu-launcher`, `--inspect`, `--no-sandbox`, `--host-rules` — directly into a trusted process.
- Never pass a deep-link value into `loadURL`, `shell.openExternal`, `shell.openPath`, `execFile`, or any filesystem path without running it through the same resolver and allowlist.
- Deep links are delivered through `open-url` on macOS and through `second-instance` argv on Windows and Linux. Both paths need the identical validator; a validator on only one is a validator on neither.

### R4.9 — Prove the boundary with negative tests

Every deep-link route ships with tests asserting rejection, not just acceptance:

- Unknown route, unknown host, non-https scheme
- Missing parameter, wrong type, oversized value, injected `../`, null byte, unicode look-alike host
- Identifier belonging to another account — must return 404 from the server, not a rendered screen
- Every prohibited pattern from R4.4 — `?isAdmin=true`, `?amount=0`, `?token=`

---

## 3. Reference Architecture

```
  ANY ORIGIN: web page · SMS · QR · malicious app · email · push · argv
                          │
                          ▼  app://…  https://links.example.com/…  argv[1]
┌─────────────────────────────────────────────────────────────────────────────┐
│ SINGLE ENTRY RESOLVER — the only code that reads a URL                       │
│                                                                              │
│  1 URL parse (throw -> reject)         5 typed schema parse (zod/matcher)    │
│  2 protocol === https:                 6 reject on ANY failure — no repair   │
│  3 hostname exact-match allowlist      7 emit typed InternalCommand          │
│  4 route key in closed Route map                                             │
└─────────────────────────────┬────────────────────────────────────────────────┘
                              │  typed command only — no raw URL passes here
                              ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ NAVIGATION — destination only. No mutation. No authorization.                 │
│   screen mounts → fetches its own data with the SESSION identity              │
│   server returns 404 for resources the session does not own                   │
│   any state change requires an explicit user action, authorized server-side   │
└──────────────────────────────────────────────────────────────────────────────┘

   ✗ navigate(url.path, url.queryParams)      ✗ if (params.isAdmin) …
   ✗ loadURL(params.url)                      ✗ login(params.token)
   ✗ startActivity(Intent.parseUri(extra))    ✗ pay(params.amount)
```

---

## 4. Detection

**Static scan:**

```bash
semgrep --config skills/semgrep-rules.yml .
```

```bash
node scripts/audit-native.mjs .
```

**Fire hostile links at a running build — the authoritative test:**

```bash
adb shell am start -W -a android.intent.action.VIEW -d "myapp://settings?isPremium=true&userId=1" com.example.app
```

```bash
adb shell am start -W -a android.intent.action.VIEW -d "https://links.example.com/webview?url=https://example.org" com.example.app
```

```bash
xcrun simctl openurl booted "myapp://payment/confirm?amount=0&orderId=00000000-0000-0000-0000-000000000001"
```

```bash
adb shell am start -n com.example.app/.DeepLinkActivity -e redirect "https://example.org"
```

Each must produce a rejection or a screen that fetches its own data and shows the server-side
value. A screen that renders the URL-supplied value, or a redirect that leaves the allowlist, is a
finding.

**Enumerate the attack surface before testing it:**

```bash
apktool d -f app-release.apk -o apk_src && grep -A6 -E "<intent-filter|android:scheme|android:exported" apk_src/AndroidManifest.xml
```

```bash
grep -rEn "CFBundleURLSchemes|associated-domains|applinks:" ios/ 2>/dev/null
```

**Verify link ownership is actually configured:**

```bash
curl -s https://links.example.com/.well-known/assetlinks.json | head -40
```

```bash
curl -s https://links.example.com/.well-known/apple-app-site-association | head -40
```

**Desktop argv injection:**

```bash
grep -rEn "setAsDefaultProtocolClient|second-instance|open-url|process\.argv" --include=*.js --include=*.ts .
```

Every `process.argv` read in a protocol handler must filter arguments beginning with `-` before use.

---

## 5. Agent Constraints

Copy verbatim into the system prompt or rules file of any coding agent:

```text
DEEP LINK VERIFICATION — HARD CONSTRAINTS
1. Every incoming URL — custom scheme, App Link, Universal Link, intent extra, QR, push
   payload, desktop argv — is untrusted input from an unauthenticated caller.
2. ONE resolver handles all of them: URL parse -> https only -> exact hostname allowlist ->
   route key in a closed map -> typed schema parse -> typed command, or reject.
3. NEVER navigate(path, queryParams) with values taken from the URL. Routes come from an
   allowlist map; parameters are typed, bounded, and format-checked (uuid/enum/regex).
4. Reject, never repair. No coercion, no defaults, no partial application. One generic
   fallback destination.
5. A link may navigate. A link may NEVER authorize or mutate. No isAdmin/role/isPremium/
   userId/verified from a URL. No login, purchase, transfer, delete, or setting change as a
   direct effect of link handling.
6. Screens fetch their own data using the SESSION identity. The server returns 404 for
   resources the session does not own. Amounts and entitlements come from the server.
7. Redirects resolve through a destination map. If a URL must be accepted: URL parse,
   exact hostname equality, https only, reject javascript:/data:/file:/intent:/blob:,
   reject user:pass@. Never startsWith/includes/endsWith on a URL string.
8. Never load a URL-supplied address into a WebView.
9. OAuth: PKCE (S256) mandatory, state random + bound + single-use, ASWebAuthenticationSession
   or Custom Tabs — never an embedded WebView. No client secret on the device.
10. Android: android:exported explicit; validate every getIntent() extra; never forward a
    parsed/untrusted Intent into startActivity; PendingIntent FLAG_IMMUTABLE; handle links in
    onNewIntent as well as onCreate; taskAffinity="" on deep-link activities.
11. Desktop: filter every argv item starting with "-" before use. Validate open-url (macOS)
    and second-instance argv (Windows/Linux) through the SAME resolver. Never pass a link
    value to loadURL, shell.openExternal, shell.openPath, or execFile.
12. Ship negative tests: unknown route, wrong type, other-account id, ../ traversal,
    ?isAdmin=true, ?amount=0, external redirect host.
```

---

## 6. Worked Example

Side-by-side vulnerable vs. remediated deep-link handling for React Native, Flutter, and Electron:
**[examples/deep-link-remediation.md](../examples/deep-link-remediation.md)**

Related: [Module 02](02-desktop-process-isolation.md) — the desktop protocol handler runs in the
main process, so a validation failure here lands on the trusted side of the isolation boundary.
