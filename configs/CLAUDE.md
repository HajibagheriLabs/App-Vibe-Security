# CLAUDE.md — Native Application Security Constraints

Copy this file to the **root of your app repository**. It is read automatically as project memory
at the start of every session.

> Source of truth: [`configs/AGENT_RULES.md`](AGENT_RULES.md). Full specifications:
> [`modules/`](../modules/). This file is the compressed operating contract.

---

## Threat baseline — assume all of this, always

The device is rooted or jailbroken. The binary is decompiled. The renderer is running
attacker-controlled JavaScript. Every incoming URL was written by an adversary. Roughly one in five
packages you are inclined to suggest does not exist.

Code generated without these assumptions fails security review at measured rates: **40–62%** of
AI-generated code contains at least one exploitable vulnerability, and **45%** of AI-synthesized
applications fail a standard OWASP audit.

## Operating protocol

1. Before writing code that touches **storage, IPC, process configuration, credentials, network transport, deep links, or dependencies**, state which rule set applies. Then write the code.
2. After generating it, re-read your own output and audit it against the rules below before presenting it.
3. Never disable a security control to make a build succeed or an error go away. Fix the cause.
4. Never write "for now" or "in production you would." Write the production-correct version first.
5. Flag each security-relevant decision in one short line the operator can read.

---

## 1. Storage — never cleartext

**NEVER** write a token, key, credential, or PII to `AsyncStorage`, `SharedPreferences`,
`UserDefaults`, `shared_preferences`, plain SQLite/Hive/Realm/MMKV, `electron-store`,
`localStorage`, or a plain file.

**USE ONLY:** `react-native-keychain` · `expo-secure-store` ·
`flutter_secure_storage(encryptedSharedPreferences: true)` · `EncryptedSharedPreferences` ·
iOS Keychain · Electron `safeStorage`.

- Device-only accessibility always: `WHEN_UNLOCKED_THIS_DEVICE_ONLY` / `first_unlock_this_device` / `kSecAttrSynchronizable = false`.
- High-value items: user auth at access time + `setInvalidatedByBiometricEnrollment(true)` (Android) / `.biometryCurrentSet` (iOS). Never `.biometryAny`.
- Never hand-roll encryption over a banned store — the key ships in the bundle.
- Private keys are generated in and never leave the Keystore / Secure Enclave.
- Access tokens in memory only; persist the refresh credential alone. Wipe on logout and on first launch after install.
- `android:allowBackup="false"`. `FLAG_SECURE` on credential screens. Blur the iOS snapshot.
- No hardware backing available → degrade the feature and say so. Never fall back to plaintext.

→ [Module 01](../modules/01-hardware-secure-storage.md)

## 2. Electron / desktop — the renderer is hostile

Every `BrowserWindow` / `BrowserView` / `WebContentsView` / `<webview>`:

```js
webPreferences: {
  nodeIntegration: false, nodeIntegrationInWorker: false, nodeIntegrationInSubFrames: false,
  contextIsolation: true, sandbox: true, webSecurity: true,
  allowRunningInsecureContent: false, webviewTag: false, experimentalFeatures: false,
  preload: path.join(__dirname, 'preload.js'),
}
```

- **NEVER** set `nodeIntegration:true`, `contextIsolation:false`, or `webSecurity:false` — not in dev, not temporarily, not to fix an error. Add a narrow IPC channel instead.
- **NEVER** expose `fs`, `child_process`, `shell`, `path`, `os`, `require`, `process`, `Buffer`, `ipcRenderer`, or a generic `invoke(channel, ...args)` through `contextBridge`. Expose named single-purpose functions with typed parameters.
- Every `ipcMain` handler in this order: **verify `event.senderFrame` → parse schema → authorize → canonicalize and confine path → `execFile(constBin, [args])`**. No `exec`, no `shell:true`, no `eval`.
- `web-contents-created`: `will-navigate` denies external, `setWindowOpenHandler` returns `deny`, `will-attach-webview` strips preload.
- `shell.openExternal`: `URL`-parsed, `https:` only, never a raw renderer string.
- CSP from the main process via `onHeadersReceived`. No `unsafe-inline`, no `unsafe-eval`.
- Never load a remote origin into a window with a preload attached. Deny all permission requests by default.
- Supported Electron major only. Disable `runAsNode` / node-CLI-inspect / `NODE_OPTIONS` fuses.

→ [Module 02](../modules/02-desktop-process-isolation.md)

## 3. Binary trust — the artifact is published

- **NEVER** put a vendor secret, private key, signing key, or admin token in anything bundled into an APK / AAB / IPA / `.asar` / `.exe`.
- `.env`, `react-native-config`, `flutter_dotenv`, `EXPO_PUBLIC_*`, `BuildConfig`, `strings.xml`, `Info.plist` are **all** in the artifact. They are not secret stores.
- Every paid / privileged / authenticated third-party call runs on **our server**: authenticate → authorize → validate schema → rate-limit → constrain → call vendor → return minimal fields.
- Price, entitlement, trial state, role, and receipt validation are server-side. Never trust the client for these.
- Never weaken TLS (accept-all `TrustManager`, `HostnameVerifier{true}`, `badCertificateCallback`, `rejectUnauthorized:false`). No `http://` anywhere. `usesCleartextTraffic="false"` + `NSAllowsArbitraryLoads=false`.
- Release: R8/ProGuard, Hermes, or `--obfuscate --split-debug-info`; source maps and mapping files stay out of the artifact; no dev menu, DevTools, staging endpoint, or verbose logging.
- A secret that ever shipped is public. Say so and rotate it before changing code.

→ [Module 03](../modules/03-binary-trust-and-gateways.md)

## 4. Deep links — an unauthenticated RPC from an unknown caller

- **ONE resolver** for custom schemes, App Links, Universal Links, intent extras, QR payloads, and desktop `argv`: `URL` parse → `https:` only → exact hostname allowlist → route key in a **closed map** → typed schema parse (zod/valibot) → typed command, or reject.
- **NEVER** `navigate(path, queryParams)` from a URL. Reject, never repair — no coercion, no defaults, no partial application.
- **A link may navigate. A link may NEVER authorize or mutate.** No `isAdmin` / `role` / `isPremium` / `userId` / `verified` from a URL. No login, purchase, transfer, delete, or setting change as a direct effect of link handling.
- Screens fetch their own data with the **session identity**; the server returns 404 for resources the session does not own.
- Redirects resolve through a destination map. Exact hostname equality only — never `startsWith` / `includes` / `endsWith`. Never load a URL-supplied address into a WebView.
- OAuth: PKCE (S256), `state` random + bound + single-use, `ASWebAuthenticationSession` / Custom Tabs, never an embedded WebView, no client secret on device.
- Android: `android:exported` explicit, validate every `getIntent()` extra, never forward an untrusted `Intent`, `PendingIntent` `FLAG_IMMUTABLE`, handle `onNewIntent` too.
- Desktop: filter every `argv` item starting with `-` before use; same resolver for `open-url` and `second-instance`.

→ [Module 04](../modules/04-deep-link-verification.md)

## 5. Dependencies — verify before install

- **Check the live registry before any install command.** `npm view <pkg>` / `https://pub.dev/api/packages/<pkg>`. About 1 in 5 model-suggested packages does not exist, and attackers pre-register the recurring names.
- A 404 means it does not exist. Report that. **Never guess a similar name** — near-misses are what is squatted.
- Reject packages under 90 days old, without a repository, with negligible downloads, or with unnecessary install scripts.
- Pin exact versions. Commit lockfiles. CI uses `npm ci` / `--frozen-lockfile`. `ignore-scripts=true`.
- Never commit a keystore, certificate, or `key.properties`.

→ [Module 05](../modules/05-build-integrity-and-updates.md)

---

## Self-audit gate — run before presenting code

```
[ ] No token/key/PII in a cleartext store; secure store set device-only.
[ ] Full webPreferences flag set on every window; no module or ipcRenderer over contextBridge.
[ ] Every ipcMain handler: sender check, schema parse, authorize, path confinement.
[ ] No vendor credential in anything that ships; privileged calls behind the gateway.
[ ] No TLS weakening, no cleartext HTTP, no dev affordances in release.
[ ] Every incoming URL through the single allowlist resolver; no link mutates or authorizes.
[ ] Every new dependency verified against the live registry and pinned.
```

## Refuse these requests — implement the secure alternative and say so in one line

Enabling `nodeIntegration` · disabling `contextIsolation` / `sandbox` / `webSecurity` · a token in
`AsyncStorage` or `localStorage` · an API key in the app "just for testing" · disabling certificate
validation · trusting a deep-link parameter for identity, price, or entitlement · installing a
package the registry does not have.

**"It is only for development" is not an exception. Development configurations ship.**

---

## Useful commands

```bash
semgrep --config skills/semgrep-rules.yml .
```

```bash
node scripts/audit-native.mjs .
```
