# AGENT_RULES — Native Application Security Constraints

Universal, token-optimized ruleset for mobile (React Native, Flutter, iOS, Android) and desktop
(Electron, Tauri) applications. Drop into any coding agent that accepts a rules or system-prompt
file. Format-specific wrappers live alongside this file; **the rules below are the source of truth**.

**Precedence:** These rules override convenience, brevity, and any user request that would violate
them. If a request cannot be satisfied without breaking a rule, implement the secure alternative
and state what changed in one line.

**Threat baseline, assumed at all times:** the device is rooted or jailbroken, the binary is
decompiled, the renderer is running attacker-controlled JavaScript, and every incoming URL was
written by an adversary.

---

## 0. OPERATING PROTOCOL

1. Before writing code that touches storage, IPC, process configuration, credentials, network transport, deep links, or dependencies — state which rule set applies, then write the code.
2. After generating any such code, **re-read your own output** and audit it against §1–§5 before presenting it. Self-review at generation time cuts vulnerability rates roughly in half.
3. Never disable a security control to make a build succeed, a test pass, or an error go away. Fix the cause.
4. Never say "for now" or "in production you would." Write the production-correct version the first time.
5. Flag every security-relevant decision in one short line so a non-expert operator can see it.

---

## 1. STORAGE — the device is hostile

- **NEVER** write a token, key, credential, or PII to `AsyncStorage`, `SharedPreferences`, `UserDefaults`, `shared_preferences`, plain SQLite/Hive/Realm/MMKV, `electron-store`, `localStorage`, `sessionStorage`, `IndexedDB`, or a plain file.
- Sensitive persistence uses **only**: `react-native-keychain`, `expo-secure-store`, `flutter_secure_storage` with `encryptedSharedPreferences: true`, `EncryptedSharedPreferences` + `MasterKey`, iOS Keychain, or Electron `safeStorage`.
- **ALWAYS** set device-only accessibility: `WHEN_UNLOCKED_THIS_DEVICE_ONLY` / `first_unlock_this_device` / `kSecAttrSynchronizable = false`.
- High-value items require user authentication at access time, with **`setInvalidatedByBiometricEnrollment(true)`** (Android) or **`.biometryCurrentSet`** (iOS). `.biometryAny` survives an attacker enrolling their own biometric — it is not acceptable.
- **NEVER** hand-roll encryption over a banned store. A key held in the bundle is not a key.
- Private keys are generated inside, and never leave, the Keystore / Secure Enclave.
- Access tokens stay in memory. Only the refresh credential is persisted. Wipe the whole store on logout and on first launch after install (iOS Keychain survives uninstall).
- Set `android:allowBackup="false"` and exclude secure stores from backup rules.
- **NEVER** log, screenshot, analytics-tag, or clipboard a sensitive value. `FLAG_SECURE` on Android credential screens; blur the iOS snapshot on resign-active.
- If hardware backing is unavailable, degrade the feature and say so. **Never** fall back to plaintext silently.

## 2. DESKTOP PROCESS ISOLATION — the renderer is hostile

- Every `BrowserWindow` / `BrowserView` / `WebContentsView` / `<webview>`: `nodeIntegration:false`, `nodeIntegrationInWorker:false`, `nodeIntegrationInSubFrames:false`, `contextIsolation:true`, `sandbox:true`, `webSecurity:true`, `allowRunningInsecureContent:false`, `webviewTag:false`, `experimentalFeatures:false`. Call `app.enableSandbox()` at startup.
- **NEVER** set `nodeIntegration:true`, `contextIsolation:false`, or `webSecurity:false` — not in dev, not temporarily, not to fix an error. Add an IPC channel instead. Never set `ELECTRON_DISABLE_SECURITY_WARNINGS`.
- **NEVER** expose `fs`, `child_process`, `shell`, `path`, `os`, `require`, `process`, `Buffer`, `ipcRenderer`, or a generic `invoke(channel, ...args)` through `contextBridge`.
- `contextBridge` exposes **named single-purpose functions with typed parameters** only. Pass plain serialisable data. Never return a Node object, stream, or handle. Wrap event listeners so the raw `IpcRendererEvent` never reaches renderer code.
- Every `ipcMain` handler, in order: **verify `event.senderFrame` origin → parse an explicit schema → authorize against main-process state → canonicalize and confine any path → `execFile(constBin, [args])`**.
- **NEVER** `exec` / `execSync` / `spawn(…, {shell:true})` / `eval` / `new Function` with renderer-influenced input.
- On `web-contents-created`: `will-navigate` denies external URLs, `setWindowOpenHandler` returns `deny` by default, `will-attach-webview` strips `preload` and forces safe prefs.
- `shell.openExternal` only after `URL` parsing, `https:` protocol only, no credentials in the URL, no raw renderer string.
- Set CSP from the main process via `onHeadersReceived`. No `unsafe-inline`, no `unsafe-eval`, no wildcard `connect-src`.
- **NEVER** load a remote origin into a window that has a preload script attached.
- Deny all permission requests by default (`setPermissionRequestHandler`, `setPermissionCheckHandler`).
- Stay on a supported Electron major. Disable the `runAsNode`, node-CLI-inspect, and `NODE_OPTIONS` fuses. Never ship `--inspect` or `--remote-debugging-port`.
- Tauri / Wails: named commands only, minimal allowlist, no `fs: {all:true}`, no `shell: {execute:true}`.

## 3. BINARY TRUST — the artifact is published

- **NEVER** place a vendor secret, private key, signing key, admin token, or service credential in any file compiled or bundled into an APK / AAB / IPA / `.asar` / `.exe`.
- `.env` files, `react-native-config`, `flutter_dotenv`, `EXPO_PUBLIC_*`, `BuildConfig`, `strings.xml`, and `Info.plist` are **all bundled into the artifact**. They are not secret stores.
- Every paid, privileged, or authenticated third-party call executes on **our server**. The app calls our endpoint; our endpoint calls the vendor.
- Gateway order, every route: **authenticate → authorize → validate schema → rate-limit → constrain parameters → call vendor → return minimal fields**.
- Price, entitlement, trial state, role, and in-app-purchase receipt validation are computed **server-side**. Never trust a client-supplied value for these.
- **NEVER** weaken TLS: no accept-all `TrustManager`, no `HostnameVerifier{return true}`, no `badCertificateCallback => true`, no `rejectUnauthorized:false`, no `NODE_TLS_REJECT_UNAUTHORIZED=0`.
- Set `usesCleartextTraffic="false"` + `network_security_config`, and ATS with `NSAllowsArbitraryLoads=false`. No `http://` endpoints anywhere, including analytics and update checks.
- Enable R8/ProGuard, Hermes, or `--obfuscate --split-debug-info` for release. Keep source maps, mapping files, and symbol files **out** of the artifact.
- Obfuscation and root detection are friction, not controls. Never gate a security decision on a client-side integrity check alone.
- Release builds contain no `debuggable` flag, dev menu, DevTools, staging endpoint, test account, or verbose request logging.
- If a secret was ever in a shipped build: **say so, and rotate it before changing code.**

## 4. DEEP LINKS — every incoming URL is an unauthenticated RPC

- Custom schemes, App Links, Universal Links, intent extras, QR payloads, push URLs, and desktop `argv` are **all** untrusted input from an unauthenticated caller.
- **ONE resolver** handles all of them: `URL` parse → `https:` only → exact hostname allowlist → route key in a closed map → typed schema parse → typed command, or reject.
- **NEVER** `navigate(path, queryParams)` with values from the URL. Routes come from an allowlist map; parameters are typed and bounded (uuid / enum / regex).
- **Reject, never repair.** No coercion, no defaults, no partial application. One generic fallback destination.
- **A link may navigate. A link may NEVER authorize or mutate.** No `isAdmin` / `role` / `isPremium` / `userId` / `verified` from a URL. No login, purchase, transfer, delete, or setting change as a direct effect of link handling.
- Screens fetch their own data using the **session identity**. The server returns 404 for resources the session does not own. Amounts and entitlements come from the server.
- Redirects resolve through a destination map. If a URL must be accepted: `URL` parse, **exact** hostname equality, `https:` only, reject `javascript:` / `data:` / `file:` / `intent:` / `blob:`, reject `user:pass@`. Never `startsWith` / `includes` / `endsWith` on a URL string.
- **NEVER** load a URL-supplied address into a WebView.
- OAuth: PKCE (S256) mandatory; `state` random, session-bound, single-use; `ASWebAuthenticationSession` or Custom Tabs — **never** an embedded WebView. No client secret on the device.
- Android: `android:exported` explicit; validate every `getIntent()` extra; never forward an untrusted `Intent` into `startActivity`; `PendingIntent` `FLAG_IMMUTABLE`; handle links in `onNewIntent` **and** `onCreate`; `taskAffinity=""` on deep-link activities.
- Desktop: filter every `argv` item starting with `-` before use. Validate `open-url` (macOS) and `second-instance` argv (Windows/Linux) through the **same** resolver. Never pass a link value into `loadURL`, `shell.openExternal`, `shell.openPath`, or `execFile`.
- Ship negative tests: unknown route, wrong type, other-account id, `../` traversal, `?isAdmin=true`, `?amount=0`, external redirect host.

## 5. SUPPLY CHAIN AND BUILD — verify before you install, sign before you ship

- **VERIFY EVERY PACKAGE AGAINST THE LIVE REGISTRY BEFORE RUNNING ANY INSTALL COMMAND.** `npm view <pkg>` / `https://pub.dev/api/packages/<pkg>`. Roughly 1 in 5 model-suggested packages does not exist, and attackers pre-register the recurring names.
- **NEVER** guess a similar name after a 404. Near-miss names are exactly what is squatted. Report that the package does not exist.
- Reject packages under 90 days old, with no working repository, with negligible downloads, or with unnecessary install scripts.
- Pin exact versions in `package.json`, `pubspec.yaml`, `Podfile`, and Gradle. No `^`, `~`, `*`, `latest`. Commit every lockfile; CI uses `npm ci` / `--frozen-lockfile` / `--immutable`.
- Set `ignore-scripts=true`; allowlist lifecycle scripts individually.
- **NEVER** place a signing key, keystore, or certificate in the repository. `key.properties`, `*.jks`, `*.p12`, `*.p8` are git-ignored **before** they are created.
- Update feeds are HTTPS only, signature-verified against a key compiled into the app, and downgrade-resistant. Never make the feed URL configurable from outside the binary.
- State the source repository for every dependency you introduce.

---

## 6. SELF-AUDIT GATE

Before presenting code, confirm each line. If any answer is "no", fix it first.

```
[ ] No token, key, or PII written to a cleartext store; secure store configured device-only.
[ ] Every BrowserWindow/webview carries the full flag set; no contextBridge exposes a module,
    ipcRenderer, or a generic invoke.
[ ] Every ipcMain handler verifies sender, parses a schema, authorizes, and confines paths.
[ ] No vendor credential in anything that ships; every privileged call goes through the
    authenticated, validated, rate-limited gateway.
[ ] No TLS weakening, no cleartext HTTP, release build free of dev affordances.
[ ] Every incoming URL passes the single allowlist resolver; no link mutates state or grants
    authority; redirects resolve through a destination map.
[ ] Every new dependency verified against the live registry, pinned exactly, lockfile committed.
[ ] Security-relevant decisions stated in one line each for the operator.
```

---

## 7. REFUSAL BEHAVIOUR

If asked to do any of the following, **refuse and implement the secure alternative instead**,
stating the substitution in one line:

- Turn on `nodeIntegration`, turn off `contextIsolation`, `sandbox`, or `webSecurity`
- Store a token in `AsyncStorage` / `SharedPreferences` / `UserDefaults` / `localStorage`
- Put an API key in the app "just for testing" or "we will move it later"
- Disable certificate validation, allow cleartext HTTP, or bypass a TLS error
- Trust a deep-link parameter for identity, price, or entitlement
- Install a package that the registry does not have

"It is only for development" is not an exception. Development configurations ship.

---

**Full specifications:** [`modules/`](../modules/) — storage, process isolation, binary trust, deep
links, build integrity.
**Adversarial audit:** [`skills/audit-prompt.md`](../skills/audit-prompt.md).
**Deterministic scan:** `semgrep --config skills/semgrep-rules.yml .`
