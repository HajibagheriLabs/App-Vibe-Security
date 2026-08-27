# Module 01 — Hardware-Backed Secure Storage

> **Target vulnerability class:** Cleartext local storage of credentials, tokens, and PII on the user's device
> **Empirical risk profile:** **High** — the dominant data-at-rest failure in AI-generated React Native, Flutter, and native mobile code
> **CWE mapping:** CWE-312 (Cleartext Storage of Sensitive Information), CWE-311 (Missing Encryption of Sensitive Data), CWE-522 (Insufficiently Protected Credentials), CWE-921 (Storage of Sensitive Data in a Mechanism Without Access Control)
> **OWASP MASVS:** MASVS-STORAGE-1, MASVS-STORAGE-2, MASVS-CRYPTO-2

---

## 1. Root Cause

Ask a code generation model to "keep the user logged in" and it will produce the shortest working
persistence call. In React Native that is `AsyncStorage.setItem`. In Flutter it is
`SharedPreferences.setString`. On native Android it is `getSharedPreferences(...).edit().putString(...)`.
On iOS it is `UserDefaults.standard.set(...)`. Every one of these writes a **plaintext file inside
the application sandbox**.

The model is not wrong about the API. It is wrong about the threat model. Three assumptions are
imported silently from the training corpus:

| Assumption the model makes | Why it is false on a shipped app |
|---|---|
| "The app sandbox is a security boundary." | It is an *isolation* boundary between apps on an intact OS. It does not survive root, jailbreak, an unlocked bootloader, a malicious backup extraction, or a forensic image. |
| "Only my app can read this file." | `adb backup`, `run-as` on a debuggable build, MDM backup channels, iTunes/Finder backups, and desktop sync tools all lift sandbox contents off the device. |
| "The token is short-lived so it does not matter." | Refresh tokens, device-binding secrets, and cached PII routinely persist for weeks. The stolen artifact is usually the *refresh* token, not the access token. |

The device belongs to the attacker. In a mobile threat model that is not a pessimistic framing —
it is the baseline, because a meaningful fraction of any install base is rooted, jailbroken,
emulated, or already compromised, and there is no reliable way to tell which fraction.

The desktop equivalent is identical in shape: an Electron app writing a token into
`app.getPath('userData')/config.json` through `electron-store`, `localStorage`, or a hand-rolled
JSON file. Any process running as that user reads it. Infostealer malware families enumerate
exactly these paths by default.

---

## 2. Non-Negotiable Rules

### R1.1 — Sensitivity classification is a required step, not a judgement call

The following values are **sensitive** and may never touch a cleartext store:

- Authentication material: access tokens, refresh tokens, ID tokens, session cookies, API keys, OAuth client secrets, magic-link codes
- Cryptographic material: private keys, symmetric keys, key-wrapping keys, seed phrases, recovery codes, HMAC secrets
- Personal data: name paired with contact data, government identifiers, date of birth, precise location history, health data, financial account data, message content
- Second-factor material: TOTP seeds, push-approval secrets, WebAuthn resident-key metadata
- Business-sensitive derived state: entitlement grants, licence keys, feature-unlock flags that gate paid functionality

Non-sensitive values — UI theme, language, onboarding-seen flag, last-opened tab, non-identifying
cache — may use ordinary storage. When classification is ambiguous, treat the value as sensitive.

### R1.2 — Banned primitives for sensitive values

These APIs write cleartext. They are **prohibited** for anything listed in R1.1:

| Platform | Prohibited for sensitive data |
|---|---|
| React Native | `@react-native-async-storage/async-storage`, legacy `AsyncStorage`, `react-native-mmkv` without an encryption key, `localStorage` / `sessionStorage` / `IndexedDB` inside a WebView, plain `react-native-fs` writes |
| Flutter | `shared_preferences`, `path_provider` + `File.writeAsString`, `hive` without `HiveAesCipher`, `sqflite` without SQLCipher, `get_storage` |
| Android native | `SharedPreferences` (including `MODE_PRIVATE`), `strings.xml`, manifest `meta-data`, unencrypted Room/SQLite, external storage of any kind |
| iOS native | `UserDefaults` / `NSUserDefaults`, `.plist` writes, `FileManager` writes without a Data Protection class, unencrypted Core Data |
| Electron / desktop | `electron-store` without hardware backing, renderer `localStorage`, `sessionStorage`, `IndexedDB`, hand-written JSON in `userData`, `keytar` (deprecated and unmaintained) |

`MODE_PRIVATE` is not encryption. The `encryptionKey` option in `electron-store` is obfuscation,
not encryption — the key ships inside the binary. Both fail the same way.

### R1.3 — Mandated hardware-backed primitives

Sensitive values are written **only** through a primitive that terminates in the platform hardware
security module (Secure Enclave, TEE, StrongBox, TPM, DPAPI-backed keychain):

| Runtime | Required API | Required configuration |
|---|---|---|
| React Native | `react-native-keychain` | `accessible: WHEN_UNLOCKED_THIS_DEVICE_ONLY`, `securityLevel: SECURE_HARDWARE`, `storage: AES_GCM` on Android |
| Expo | `expo-secure-store` | `keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY`, `requireAuthentication: true` for high-value items |
| Flutter | `flutter_secure_storage` | `AndroidOptions(encryptedSharedPreferences: true)`, `IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device)` |
| Android native | `androidx.security.crypto.EncryptedSharedPreferences` + `MasterKey`, or a raw `KeyStore` key | `AES256_GCM`, `setIsStrongBoxBacked(true)` where available, `setUserAuthenticationRequired(true)` for R1.5 items |
| iOS native | Keychain Services (`SecItemAdd`), or a Secure Enclave key via `kSecAttrTokenIDSecureEnclave` | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, `kSecAttrSynchronizable = false` |
| Electron | `safeStorage.encryptString` / `safeStorage.decryptString` (macOS Keychain, Windows DPAPI, Linux libsecret) | Guard with `safeStorage.isEncryptionAvailable()`; on failure **refuse to persist** rather than downgrading silently |

Two rules apply to every row: use the platform primitive **directly**, and never invent a
cryptographic wrapper around a banned primitive. A hand-rolled `AES.encrypt(token, 'my-secret')`
over `AsyncStorage` is not remediation — the passphrase is in the bundle, and
[Module 03](03-binary-trust-and-gateways.md) explains how it is extracted in under a minute.

### R1.4 — Key material never leaves the secure element

For signing, decryption, or device-binding keys: generate the key **inside** the Keystore or
Secure Enclave and perform the operation there. Never export a private key into application
memory, never serialise one to storage, never transmit one.

- Android: `KeyGenParameterSpec` with purposes limited to exactly what is used, `setRandomizedEncryptionRequired(true)`, and StrongBox requested where the device supports it.
- iOS: `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` and an explicit access control object.
- If the platform cannot provide hardware backing, the correct behaviour is to **degrade the feature** — not to fall back to software storage silently. Tell the user, or require re-authentication on every use.

### R1.5 — Biometric and passcode gating with enrolment invalidation

High-value items — payment credentials, private keys, recovery phrases, long-lived refresh tokens
on a shared device — require user presence at access time:

- Android: `setUserAuthenticationRequired(true)`, `setUserAuthenticationParameters(timeout, AUTH_BIOMETRIC_STRONG)`, and **`setInvalidatedByBiometricEnrollment(true)`**.
- iOS: `SecAccessControlCreateWithFlags` with `.biometryCurrentSet` — not `.biometryAny` — and `.devicePasscode` only where policy genuinely permits it.

The invalidation flag is the rule that actually matters. It destroys the key when a new
fingerprint or face is enrolled, which is precisely the step an attacker holding an unlocked
device performs. `.biometryAny` and the Android default survive that enrolment, and therefore
survive the attack.

Biometric prompts gate **key usage inside the secure element**. A biometric check whose only
effect is a boolean in JavaScript or Dart is decoration; it is bypassed by patching the bundle.

### R1.6 — Exclude sensitive stores from backup and cloud sync

- Android: `android:allowBackup="false"`, or a `dataExtractionRules` / `fullBackupContent` file that explicitly excludes the secure store. Set `android:hasFragileUserData="false"`.
- iOS: `kSecAttrAccessible...ThisDeviceOnly` on every Keychain item, `kSecAttrSynchronizable = false`, and `isExcludedFromBackup` on any sensitive file container.
- Electron: never write sensitive data into a directory synced by OneDrive, iCloud Drive, or Dropbox.

`ThisDeviceOnly` is what stops a token from being restored onto an attacker-controlled device from
a backup.

### R1.7 — Minimise what is stored at all

The most reliable protection for a value is that it was never written to disk.

1. Access tokens live **in memory only**, for the process lifetime.
2. Only the long-lived credential — refresh token or device secret — reaches the secure store.
3. Logout, account deletion, and detected tamper wipe **every** item. Iterate the store; do not delete keys one at a time from memory of what was written.
4. Keychain items survive app uninstall on iOS. Clear the Keychain on first launch after install, keyed off a flag in `UserDefaults`, or the next owner of the device inherits the session.
5. Any cache holding PII gets an explicit TTL and an eviction path.

### R1.8 — Close the side channels

- No sensitive value in `console.log`, `print`, `NSLog`, Logcat, crash-reporter breadcrumbs, or analytics events. Redact by allowlist, never by blocklist.
- Android: `FLAG_SECURE` on screens showing credentials, tokens, or recovery phrases. This also removes the screenshot from the recents thumbnail.
- iOS: blur or replace the window in `sceneWillResignActive`, before the OS writes the snapshot into `Library/Caches/Snapshots`.
- Clipboard: never auto-copy a secret. Where a copy is genuinely required, use an expiring pasteboard item and mark the field sensitive.
- Disable autofill and keyboard learning on secret fields (`textContentType`, `autoCorrect: false`, `importantForAutofill="no"`).

---

## 3. Reference Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│ DEVICE — assume rooted, jailbroken, imaged, or backed up by an attacker   │
│                                                                          │
│  ┌────────────────────────┐        ┌──────────────────────────────────┐  │
│  │ App process (memory)   │        │ App sandbox (files)  ✗ CLEARTEXT │  │
│  │                        │        │                                  │  │
│  │ • access token  ← RAM  │        │ • AsyncStorage / SharedPrefs     │  │
│  │ • decrypted PII        │        │ • UserDefaults / plist           │  │
│  │   (transient)          │        │ • unencrypted SQLite / Hive      │  │
│  └───────────┬────────────┘        │ • electron-store JSON            │  │
│              │                     │   ↳ readable by any root process │  │
│              │ read / write        │     and by every backup channel  │  │
│              ▼                     └──────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ SECURE STORE  ✓                                                    │  │
│  │ Keychain (Secure Enclave) · Keystore (TEE / StrongBox) · DPAPI     │  │
│  │                                                                    │  │
│  │ • refresh token, device secret                                     │  │
│  │ • key handles — the private key is never exported                  │  │
│  │ • unlock gated by biometryCurrentSet / invalidate-on-enrolment     │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │  STORAGE BOUNDARY
                                    │  Nothing sensitive crosses upward into
                                    │  a cleartext file. Ever.
```

---

## 4. Detection

**Static scan (this repository ruleset):**

```bash
semgrep --config skills/semgrep-rules.yml .
```

```bash
node scripts/audit-native.mjs .
```

**Prove it on a real device — this is the authoritative test.** Log in, background the app, then
read the sandbox:

```bash
adb shell run-as com.example.app cat /data/data/com.example.app/shared_prefs/*.xml
```

```bash
adb shell run-as com.example.app sqlite3 /data/data/com.example.app/databases/RKStorage "SELECT key, value FROM catalystLocalStorage;"
```

```bash
grep -rEn "eyJ[A-Za-z0-9_-]{10,}|refresh_token|Bearer |BEGIN [A-Z ]*PRIVATE KEY" "$HOME/AppData/Roaming/YourApp" "$HOME/Library/Application Support/YourApp" 2>/dev/null
```

Any JWT, refresh token, key, or personal record returned by these commands is a **P0**. Revoke the
exposed sessions before fixing the code — the data is already extractable from every device that
ran the vulnerable build.

**Backup extraction test.** If this produces readable application data, `allowBackup` is
misconfigured and R1.6 is violated:

```bash
adb backup -f out.ab com.example.app
```

---

## 5. Agent Constraints

Copy verbatim into the system prompt or rules file of any coding agent:

```text
SECURE STORAGE — HARD CONSTRAINTS
1. Never write a token, key, credential, or PII to AsyncStorage, SharedPreferences,
   UserDefaults, plain SQLite/Hive/Realm, electron-store, localStorage, or a plain file.
2. Sensitive persistence uses ONLY: react-native-keychain / expo-secure-store /
   flutter_secure_storage(encryptedSharedPreferences:true) / EncryptedSharedPreferences /
   iOS Keychain / Electron safeStorage.
3. Always set device-only accessibility: WHEN_UNLOCKED_THIS_DEVICE_ONLY /
   first_unlock_this_device / kSecAttrSynchronizable=false.
4. High-value items require user auth at access time, with
   setInvalidatedByBiometricEnrollment(true) on Android and .biometryCurrentSet on iOS.
5. Never hand-roll encryption over a banned store. A key held in the bundle is not a key.
6. Private keys are generated in, and never leave, the Keystore / Secure Enclave.
7. Access tokens stay in memory. Only the refresh credential is persisted.
8. Wipe the entire secure store on logout, and on first launch after install (iOS).
9. Set android:allowBackup="false" and exclude secure stores from backup rules.
10. Never log, screenshot, analytics-tag, or clipboard a sensitive value. FLAG_SECURE on
    Android credential screens; blur the iOS snapshot on resign-active.
11. If hardware backing is unavailable, degrade the feature and say so. Never fall back to
    plaintext silently.
```

---

## 6. Worked Example

Side-by-side vulnerable vs. remediated implementation for React Native and Flutter:
**[examples/mobile-storage-remediation.md](../examples/mobile-storage-remediation.md)**

Related: [Module 03 — Binary Trust and Gateways](03-binary-trust-and-gateways.md) explains why an
encryption key embedded in the app to "protect" cleartext storage provides no protection at all.
