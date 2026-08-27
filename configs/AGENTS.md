# AGENTS.md — Native Application Security Contract

Place at your app repository root as `AGENTS.md`. Read automatically by agents that follow the
open AGENTS.md convention — Codex CLI, Amp, Jules, Hermes-style agents, and most custom CLI
harnesses. For tools that do not, point their system prompt at this file explicitly.

> Source of truth: [`configs/AGENT_RULES.md`](AGENT_RULES.md) · full specifications:
> [`modules/`](../modules/)

---

## Project security baseline

This repository builds a **native application** — code that ships as a file to a device the
operator does not control. Assume all of the following at all times:

- The device is rooted or jailbroken, and its filesystem is readable.
- The shipped binary is decompiled. Every string in it is public.
- The desktop renderer is executing attacker-controlled JavaScript.
- Every incoming URL — deep link, intent, QR payload, argv — was written by an adversary.
- Roughly one in five packages a model suggests does not exist in any registry.

## Working agreement

1. Before writing code that touches **storage, IPC, process configuration, credentials, network transport, deep links, or dependencies**: name the applicable rule, then write the code.
2. Re-read your own output and audit it against the rules below before presenting it.
3. Never disable a security control to make a build succeed or a test pass. Fix the cause.
4. Never write "for now" or "in production you would." Ship the production-correct version.
5. State each security-relevant decision in one line.

---

## Hard rules

### Storage
Never write a token, key, credential, or PII to `AsyncStorage`, `SharedPreferences`,
`UserDefaults`, `shared_preferences`, plain SQLite/Hive/Realm/MMKV, `electron-store`,
`localStorage`, or a plain file. Use `react-native-keychain`, `expo-secure-store`,
`flutter_secure_storage(encryptedSharedPreferences: true)`, `EncryptedSharedPreferences`, the iOS
Keychain, or Electron `safeStorage` — always device-only, with biometric invalidation on enrolment
change for high-value items. Access tokens live in memory; only the refresh credential persists.
Never hand-roll encryption over a banned store: the key ships in the bundle.
→ [Module 01](../modules/01-hardware-secure-storage.md)

### Desktop process isolation
Every window and webview carries `nodeIntegration:false`, `contextIsolation:true`, `sandbox:true`,
`webSecurity:true`. These are never relaxed — not in dev, not temporarily. `contextBridge` exposes
named single-purpose typed functions, never a module, never `ipcRenderer`, never a generic
`invoke`. Every `ipcMain` handler verifies the sender frame, parses a schema, authorizes, confines
paths, and uses `execFile` with an argument array. Navigation and window creation are denied by
default; CSP is set from the main process.
→ [Module 02](../modules/02-desktop-process-isolation.md)

### Binary trust
No vendor secret, private key, signing key, or admin token in any shipped artifact — and `.env`,
`react-native-config`, `flutter_dotenv`, `EXPO_PUBLIC_*`, `BuildConfig`, `strings.xml`, and
`Info.plist` are all part of the artifact. Privileged third-party calls run on our server behind an
authenticated, schema-validated, rate-limited gateway. Price, entitlement, role, and receipt
validation are server-side. TLS is never weakened; cleartext HTTP is never permitted.
→ [Module 03](../modules/03-binary-trust-and-gateways.md)

### Deep links
One resolver handles every incoming URL: parse, `https:` only, exact hostname allowlist, route key
in a closed map, typed schema parse, or reject. A link may navigate; it may never authorize or
mutate. Screens fetch their own data with the session identity. Redirects resolve through a
destination map. On desktop, drop every `argv` item beginning with `-` before use.
→ [Module 04](../modules/04-deep-link-verification.md)

### Dependencies and build
Verify every package against the live registry **before** running any install command. A 404 means
the package does not exist — report it, never guess a near-miss name. Pin exact versions, commit
lockfiles, `ignore-scripts=true`. Never commit a keystore or certificate. Update feeds are HTTPS
and signature-verified.
→ [Module 05](../modules/05-build-integrity-and-updates.md)

---

## Verification commands

Run these before declaring a task complete. Replace the build/test lines with this project's own.

```bash
semgrep --config skills/semgrep-rules.yml --error --severity ERROR .
```

```bash
node scripts/audit-native.mjs .
```

```bash
node scripts/scan-artifacts.mjs ./build
```

## Refusal behaviour

Refuse and implement the secure alternative — stating the substitution in one line — if asked to:
enable `nodeIntegration`; disable `contextIsolation`, `sandbox`, or `webSecurity`; store a token in
`AsyncStorage` or `localStorage`; embed an API key "just for testing"; disable certificate
validation; trust a deep-link parameter for identity, price, or entitlement; or install a package
the registry does not have.

**"It is only for development" is not an exception. Development configurations ship.**
