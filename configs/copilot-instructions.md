# GitHub Copilot — Native Application Security Instructions

Place this file at **`.github/copilot-instructions.md`** in your app repository. Copilot Chat and
Copilot coding agent read it automatically for every request in the repository.

> Source of truth: [`configs/AGENT_RULES.md`](AGENT_RULES.md) · full specifications:
> [`modules/`](../modules/)

---

## Context for every suggestion

This repository builds a **native application** (React Native, Flutter, iOS, Android, or Electron)
that ships as a file to a device the operator does not control. Apply these assumptions to every
completion and every chat answer:

- The device is rooted or jailbroken; its filesystem is readable.
- The binary is decompiled; every string in it is public.
- The desktop renderer may be executing attacker-controlled JavaScript.
- Every incoming deep link, intent, QR payload, and command-line argument is adversary-written.
- A package name that looks plausible may not exist — verify before suggesting an install.

## Storage

- Do **not** suggest `AsyncStorage`, `SharedPreferences`, `UserDefaults`, `shared_preferences`, plain SQLite/Hive/Realm/MMKV, `electron-store`, or `localStorage` for tokens, keys, credentials, or PII.
- Suggest `react-native-keychain`, `expo-secure-store`, `flutter_secure_storage` with `encryptedSharedPreferences: true`, `EncryptedSharedPreferences`, the iOS Keychain, or Electron `safeStorage`.
- Always include device-only accessibility (`WHEN_UNLOCKED_THIS_DEVICE_ONLY` / `first_unlock_this_device` / `kSecAttrSynchronizable = false`).
- For high-value items add user authentication at access time with `setInvalidatedByBiometricEnrollment(true)` (Android) or `.biometryCurrentSet` (iOS).
- Never suggest encrypting a value with a key held in the app to make a banned store acceptable.

## Electron and desktop

- Every `BrowserWindow`, `BrowserView`, `WebContentsView`, and `<webview>` gets `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, `webSecurity: true`, `webviewTag: false`.
- Never suggest enabling `nodeIntegration` or disabling `contextIsolation` / `webSecurity` to resolve a `require is not defined`, CORS, or `__dirname` error. Suggest a narrow IPC channel instead.
- `contextBridge.exposeInMainWorld` gets named single-purpose typed functions. Never `fs`, `child_process`, `shell`, `require`, `process`, `ipcRenderer`, or a generic `invoke(channel, ...args)`.
- Every `ipcMain.handle` suggestion includes: sender-frame verification, explicit schema parse, authorization, path canonicalization and confinement, and `execFile(constBin, [args])`.
- Include `will-navigate` denial, `setWindowOpenHandler` returning `deny`, and a main-process CSP.

## Credentials and network

- Never suggest placing an API key, secret, private key, or admin token in app source, `.env`, `BuildConfig`, `strings.xml`, `Info.plist`, or an `EXPO_PUBLIC_*` variable. All of these ship inside the artifact.
- Suggest a server-side gateway route instead: authenticate → authorize → validate schema → rate-limit → constrain parameters → call the vendor → return minimal fields.
- Never suggest an accept-all `TrustManager`, `HostnameVerifier` returning `true`, `badCertificateCallback => true`, `rejectUnauthorized: false`, or `NODE_TLS_REJECT_UNAUTHORIZED=0`, even to resolve a local development TLS error.
- Never suggest `http://` endpoints, `usesCleartextTraffic="true"`, or `NSAllowsArbitraryLoads`.

## Deep links

- Never suggest `navigate(path, queryParams)` built from a parsed URL.
- Suggest a single resolver: `URL` parse → `https:` only → exact hostname allowlist → route key in a closed map → typed schema parse (zod/valibot) → typed command, or reject.
- Never suggest reading identity, role, entitlement, price, or a session token from a URL parameter.
- Redirect destinations resolve through a map. Never `startsWith` / `includes` / `endsWith` on a URL string.
- On desktop, filter every `argv` item beginning with `-` before use.

## Dependencies

- Before suggesting an install command, confirm the package exists in the live registry.
- If a package cannot be confirmed, say so. Do **not** suggest a similar-looking name — attackers pre-register the near-misses that models produce.
- Suggest exact pinned versions and a committed lockfile.

## Review behaviour

When asked to review a diff or explain code in this repository, check it against the rules above
and report violations with `file:line`. Do not accept a client-side check as mitigation for a
missing server-side control.

**"It is only for development" is not an exception. Development configurations ship.**
