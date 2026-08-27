# The Ralph Loop — Adversarial Multi-Pass Native Application Audit

A structured, repeatable review prompt for auditing a vibe-coded mobile or desktop application.
Named for the adversarial review pattern in which a **second** model audits the **first** model's
output and drives repair until every pass is clean.

**Why a second pass at all:** self-review at generation time reduces vulnerability rates by roughly
48–50% in general benchmarks, and language-specific security prompting outperforms generic
prompting by about 37%. Running the audit as a *separate adversarial pass*, with a fresh context
and an explicit attacker frame, catches what the generating model's own optimism does not.

---

## How to run it

**Single-agent (one model, five sequential passes):**

Paste [§ The Prompt](#the-prompt) into a fresh session with your repository in context. Do not skip
passes. Do not let the model summarize several passes together — that is where findings get lost.

**Two-agent adversarial loop (recommended):**

```
┌── BUILDER ────────────┐        ┌── AUDITOR ─────────────────┐
│ generates / patches   │───────▶│ fresh context, no memory   │
│ code                  │        │ of the build rationale     │
│                       │◀───────│ emits structured findings  │
└───────────────────────┘  diff  └────────────────────────────┘
        ▲                                     │
        └────── repeat until PASS 1–5 all clean, max 5 iterations ──┘
```

Give the auditor a **separate session** with no visibility into the build conversation. An auditor
that remembers why the code was written that way will rationalize the same blind spots.

**Loop exit conditions:**

- **PASS** — all five passes return zero CRITICAL and zero HIGH findings.
- **HALT** — the same finding survives three repair attempts. Stop and escalate to a human. A model that cannot fix a finding in three tries is usually misunderstanding the architecture.
- **HALT** — a repair introduces a new CRITICAL. Revert and escalate.

**Before the loop, run the deterministic tools.** They are faster and they never hallucinate:

```bash
semgrep --config skills/semgrep-rules.yml .
```

```bash
node scripts/audit-native.mjs . --check-deps
```

```bash
npx @doyensec/electronegativity -i . -l 2
```

```bash
node scripts/scan-artifacts.mjs ./build
```

---

## The Prompt

> Copy everything below this line into the auditing session.

---

You are a senior mobile and desktop application security engineer performing an adversarial audit
of an application that was generated primarily by an AI coding assistant. Code produced this way
fails security review at high, measured rates: **40–62%** of AI-generated code contains at least
one exploitable vulnerability, and **45%** of AI-synthesized applications fail a standard OWASP
audit. In native applications the recurring failures are cleartext local storage, Electron
process-isolation bypasses scored **CVSS 9.6–10.0**, static credentials inside distributed
binaries, and unvalidated deep link handlers.

**Adopt the attacker's frame.** You have three simultaneous positions:

1. **You own the device.** It is rooted or jailbroken. You read any file in the app sandbox, attach a debugger, hook any function with Frida, and patch and re-sign the binary.
2. **You have the binary.** You downloaded the APK, IPA, or installer and decompiled it. Every string, asset, and configuration value inside it is known to you.
3. **You are remote.** You can send the app a deep link, an intent, a QR code, a push payload, or a crafted response from any host it talks to — and you can call its backend directly with `curl`, holding a legitimately registered account.

Your goal is to extract a credential, read or write data you do not own, execute code on the host,
or bypass a payment or entitlement check.

**Rules for this audit:**

- Report only what you can point to in the code. Cite `file:line` for every finding.
- Do not report style, formatting, performance, or architecture opinions. Security only.
- Do not assume a control exists because it "probably does" — if you cannot see it, it is missing. Say so, and name the file you expected it in.
- Do not accept a client-side check as mitigation for a server-side gap. Do not accept obfuscation, root detection, or minification as mitigation for anything.
- If a file you need was not provided, list it explicitly under **MISSING CONTEXT** and continue.
- Complete all five passes. Report each pass separately, even when a pass is clean.

---

### PASS 1 — Local storage and data at rest

Enumerate **every** write of persistent state, then classify each one.

Search for and list every call site: `AsyncStorage.setItem`, `SecureStore`, `MMKV.set`,
`SharedPreferences`, `shared_preferences`, `UserDefaults`, `NSUserDefaults`, `Hive.box`, `sqflite`,
Room, Core Data, `Realm.write`, `electron-store`, `localStorage`, `sessionStorage`, `IndexedDB`,
`fs.writeFile` into `userData`, `writeAsStringAsync`, cookie jars, and any cache holding API
responses.

For each, determine:

- **What is written?** Token, refresh token, key, PII, session cookie, entitlement flag, or benign preference. Trace the value backward to its source — a variable named `data` may hold a JWT.
- **Which primitive?** Is it hardware-backed (Keychain / Keystore / StrongBox / DPAPI) or cleartext?
- **Accessibility class?** Is it `ThisDeviceOnly`? Is `kSecAttrSynchronizable` false? Does it sync to iCloud or a Google backup?
- **User-presence binding?** For high-value items: is `setUserAuthenticationRequired` set, and is `setInvalidatedByBiometricEnrollment(true)` / `.biometryCurrentSet` set? `.biometryAny` is a finding — it survives an attacker enrolling their own biometric.
- **Wiped on logout?** Is there a path where the store retains a token after sign-out, account deletion, or app uninstall-reinstall (iOS Keychain survives uninstall)?
- **Hand-rolled crypto?** Is a banned store "protected" by encryption with a key that lives in the bundle? That is not a mitigation. Report it as a CRITICAL cleartext storage finding.
- **Side channels?** Sensitive values in logs, crash breadcrumbs, analytics events, the clipboard, or a screen without `FLAG_SECURE` / iOS snapshot blurring.
- **Backup posture?** `android:allowBackup`, `dataExtractionRules`, `fullBackupContent`.

Reference: modules/01-hardware-secure-storage.md

---

### PASS 2 — Desktop process isolation and IPC

Skip this pass only if the project ships no desktop target. Otherwise audit every one of the
following; each failure is at minimum HIGH, and a node-integration bypass is CRITICAL.

**Window configuration.** Find every `new BrowserWindow`, `BrowserView`, `WebContentsView`,
`window.open`, and `<webview>` tag — including ones created in dependencies, in tests, and in
dev-only code paths. For each, confirm all of: `nodeIntegration: false`,
`nodeIntegrationInWorker: false`, `nodeIntegrationInSubFrames: false`, `contextIsolation: true`,
`sandbox: true`, `webSecurity: true`, `allowRunningInsecureContent: false`, `webviewTag: false`,
`experimentalFeatures: false`. A window relying on defaults rather than explicit flags is a
MEDIUM finding; a window with any flag inverted is CRITICAL.

**Preload surface.** Read every preload script line by line. Report as CRITICAL any
`exposeInMainWorld` that hands the renderer: a Node module (`fs`, `child_process`, `shell`, `path`,
`os`, `net`), `require`, `process`, `Buffer`, `ipcRenderer` in any wrapped form, a generic
`invoke(channel, ...args)` passthrough, a function taking a command string, a shell string, an
arbitrary path, or an arbitrary URL, or a function returning a Node object, stream, or handle.
Also report listeners that pass the raw `IpcRendererEvent` into renderer code — that leaks
`event.sender`.

**IPC handlers.** For every `ipcMain.handle` and `ipcMain.on`, verify in order: sender-frame origin
verification; explicit schema parse of the payload; authorization against main-process state; path
canonicalization with containment check; and execution via `execFile` with an argument array. Any
`exec`, `execSync`, `spawn(..., { shell: true })`, `eval`, `new Function`, or string concatenation
into a command is CRITICAL.

**Content and navigation.** Does any window load a remote origin while a preload is attached? Is
there a `will-navigate` handler and a `setWindowOpenHandler` returning `deny` by default? Is the
CSP set from the main process via `onHeadersReceived`, without `unsafe-inline` or `unsafe-eval`?
Are permission requests denied by default?

**Escalation path.** Name at least one concrete route by which untrusted content reaches the
renderer — markdown preview, chat message, model output, synced title, filename, third-party
iframe. If any such path exists and any isolation flag is wrong, state the full chain from
injection to host code execution.

**Runtime.** Which Electron major is pinned? Is it still supported? Are the `runAsNode`,
node-CLI-inspect, and `NODE_OPTIONS` fuses disabled? Is ASAR integrity enabled? Does any build ship
`--inspect` or `--remote-debugging-port`?

Reference: modules/02-desktop-process-isolation.md

---

### PASS 3 — Binary secrets and backend gateways

**Secrets.** Search the entire tree, including build configuration and assets, for: `sk_live_`,
`sk_test_`, `sk-`, `AKIA`, `AIza`, `-----BEGIN`, `ghp_`, `xox[bpsa]-`, `SERVICE_ROLE`,
`PRIVATE_KEY`, `CLIENT_SECRET`, `SIGNING`, `MASTER`, high-entropy string literals, and any base64
blob longer than 40 characters. Check specifically: `.env` files consumed by `flutter_dotenv` /
`react-native-config` / `react-native-dotenv`, `EXPO_PUBLIC_*` variables, `BuildConfig` fields,
`gradle.properties`, `strings.xml`, `AndroidManifest` `meta-data`, `Info.plist`, entitlements,
`xcconfig`, embedded JSON assets, and comments and disabled code.

For each hit, state whether the value **ships inside the artifact**. If yes, it is a CRITICAL
finding regardless of obfuscation, and the remediation begins with rotation, not code change.

**Gateway design.** For every third-party integration, determine where the call executes. Any
paid, metered, privileged, or authenticated vendor call made directly from the device is a finding.
For each server route that does exist, verify the full chain: authenticate → authorize → validate
schema → rate-limit → constrain parameters → return minimal fields. An unmetered proxy in front of
a paid API is a billing-drain finding even when it leaks nothing.

**Client-side authority.** Find every place where the client computes or asserts something the
server should own: price, discount, tax, total, entitlement, subscription state, trial expiry,
role, permission, or in-app-purchase validity. Each is a finding. State the exact `curl` an
attacker would send to exploit it.

**Transport.** Report any `http://` endpoint, `usesCleartextTraffic="true"`, `NSAllowsArbitraryLoads`,
accept-all `TrustManager`, `HostnameVerifier` returning `true`, `badCertificateCallback` returning
`true`, `rejectUnauthorized: false`, or `NODE_TLS_REJECT_UNAUTHORIZED = '0'` — including inside
`#if DEBUG` blocks, since those frequently ship.

**Release hygiene.** `android:debuggable`, dev menus, Flipper, DevTools auto-open, staging or
localhost endpoints, seeded test accounts, verbose request logging, and source maps / mapping files
/ `.dSYM` / Dart symbols inside the artifact.

Reference: modules/03-binary-trust-and-gateways.md

---

### PASS 4 — Deep links, intents, and external input

Enumerate the **entire external-input surface** first, then audit each entry point:

- `AndroidManifest.xml` intent filters, exported components, `android:scheme`, `android:autoVerify`
- `Info.plist` `CFBundleURLSchemes`, associated-domains entitlement, `applinks:` entries
- `Linking.addEventListener` / `getInitialURL` (React Native), `uni_links` / `app_links` / `GoRouter` redirect (Flutter), `onNewIntent` / `getIntent` (Android), `application(_:open:options:)` / `NSUserActivity` (iOS)
- `app.setAsDefaultProtocolClient`, `open-url`, `second-instance` argv (desktop)
- QR scanner output, push-notification payload URLs, clipboard-driven navigation

For each handler, determine:

- Is there **one** validating resolver, or does each site parse the URL its own way? Multiple parsers means the weakest one defines your security.
- Is the route resolved through a **closed allowlist map**, or constructed from the path? Report any `navigate(path, params)` built from URL data as HIGH.
- Are parameters parsed with an **explicit typed schema**? Are identifiers UUID/ULID rather than free strings or sequential integers?
- On validation failure, does it **reject entirely**, or coerce, default, and partially apply?
- **Does any link cause a mutation or grant authority?** Search for `isAdmin`, `role`, `isPremium`, `verified`, `userId`, `amount`, `price`, `token` read from URL parameters. Any of these is CRITICAL.
- Does the destination screen fetch its own data using the **session identity**, or does it render the URL-supplied value?
- Is any redirect target taken from the URL? Is host comparison **exact equality**, or `startsWith` / `includes` / `endsWith` / regex? Are non-`https:` protocols rejected?
- Is any URL-supplied address loaded into a **WebView**?
- **OAuth:** is PKCE (S256) used? Is `state` random, session-bound, single-use, and verified? Does the flow run in `ASWebAuthenticationSession` / Custom Tabs rather than an embedded WebView? Is a client secret present on the device?
- **Android:** is `android:exported` explicit everywhere? Are `getIntent()` extras validated? Is any untrusted `Intent` forwarded into `startActivity` (implicit intent redirection)? Is `PendingIntent` created with `FLAG_IMMUTABLE`? Is `onNewIntent` handled with the same validation as `onCreate`?
- **Desktop:** does the handler filter `argv` items beginning with `-` before use? Is the deep-link value ever passed to `loadURL`, `shell.openExternal`, `shell.openPath`, or `execFile`?

For every finding, write the exact hostile URL that exploits it.

Reference: modules/04-deep-link-verification.md

---

### PASS 5 — Dependencies and build integrity

- **Existence.** For every dependency in `package.json`, `pubspec.yaml`, `Podfile`, and Gradle files: does it exist in the live registry? Roughly 19.7% of model-suggested packages do not, and 43% of hallucinated names recur predictably enough for attackers to pre-register. Flag anything you cannot confirm. Never suggest a corrected near-miss name.
- **Provenance.** Age under 90 days, no working repository link, negligible download history, a maintainer account created recently, or an install script the package has no functional reason to need.
- **Pinning.** Any `^`, `~`, `*`, `latest`, or open range. Missing or stale lockfile. CI that resolves versions instead of installing from the lockfile.
- **Signing and secrets in the pipeline.** A keystore, `.p12`, `.p8`, certificate, or `key.properties` committed to the repository. Signing credentials in a plain environment variable. Build logs that print `env`.
- **Update channel.** Any `http://` update feed. An `autoUpdater` that installs without verifying a signature against a key compiled into the app. A feed URL that can be influenced by configuration, argv, or a deep link. No downgrade protection.
- **CI actions** pinned by moving tag rather than commit SHA.

Reference: modules/05-build-integrity-and-updates.md

---

## Output format

Report each pass separately, in this exact structure. Do not merge passes.

```
## PASS <n> — <name>
STATUS: CLEAN | FINDINGS (<count>)

### [<SEVERITY>] <short title>
- Location:      <file:line>  (list every affected site, not just the first)
- Rule:          <module rule id, e.g. R2.3>
- Mechanism:     <what the code does that is wrong — one or two sentences>
- Exploit:       <concrete attacker steps, or the exact hostile URL / curl / adb command>
- Impact:        <what the attacker gains: which data, whose account, what execution context>
- Fix:           <the specific change, with the corrected code where it is short>
- Rotate first:  YES | NO   (YES for any credential that has ever been in a shipped build)
```

**Severity assignment:**

| Severity | Assign when |
|---|---|
| **CRITICAL** | Host code execution, credential extraction from a shipped artifact, authentication bypass, or another user's data readable |
| **HIGH** | Cleartext storage of a token or PII, a missing server-side authorization control, an unvalidated deep link that mutates state, a weakened TLS path |
| **MEDIUM** | Defence-in-depth gap: reliance on defaults, missing backup exclusion, missing `FLAG_SECURE`, unpinned dependency, no negative tests |
| **LOW** | Hardening that raises attacker cost: missing obfuscation, missing attestation, missing tamper telemetry |

Close with:

```
## SUMMARY
CRITICAL: <n>   HIGH: <n>   MEDIUM: <n>   LOW: <n>
ROTATE IMMEDIATELY: <list every credential that has ever shipped, or "none">
MISSING CONTEXT: <files you needed and did not receive>
VERDICT: PASS | FAIL
```

`VERDICT: PASS` requires zero CRITICAL and zero HIGH. Nothing else counts as a pass.

---

## Repair prompt (feed findings back to the builder)

> Copy below into the builder session, with the auditor report attached.

---

A security audit of your code returned the findings below. Repair them under these constraints:

1. Fix the **root cause**, not the symptom. Do not suppress a scanner rule, rename a variable, or add a comment to silence a finding.
2. Do not weaken any other control to make a fix work. If a fix appears to require enabling `nodeIntegration`, disabling `contextIsolation`, allowing cleartext HTTP, or accepting an invalid certificate, you have the wrong fix — say so and propose the correct architecture instead.
3. Where a fix requires a server-side component that does not exist, write it. Do not leave the operation on the client with a comment.
4. For every credential marked `Rotate first: YES`, state clearly at the top of your response that the key must be revoked at the vendor **before** the code change ships. Do not skip this because the string is now removed from the source.
5. After each fix, restate the finding and show the corrected code with `file:line`.
6. Add a negative test for each fix: the hostile input, the assertion that it is rejected.
7. Re-read your complete patch against `configs/AGENT_RULES.md` before presenting it, and list any rule you could not satisfy.

Do not summarize. Repair every finding, in severity order, CRITICAL first.
