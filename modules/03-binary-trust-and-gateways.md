# Module 03 — Binary Trust and Backend Gateways

> **Target vulnerability class:** Static credential harvesting from distributed binaries; privileged operations executed client-side
> **Risk profile:** **High** — the shipped artifact is attacker-readable by definition
> **CWE mapping:** CWE-798 (Use of Hard-coded Credentials), CWE-321 (Use of Hard-coded Cryptographic Key), CWE-656 (Reliance on Security Through Obscurity), CWE-319 (Cleartext Transmission of Sensitive Information), CWE-295 (Improper Certificate Validation)
> **OWASP MASVS:** MASVS-CODE-4, MASVS-NETWORK-1, MASVS-NETWORK-2, MASVS-RESILIENCE-1

---

## 1. Root Cause

A web application ships code to a browser that discards it on close. A mobile or desktop
application ships a **file** — an APK, an AAB, an IPA, a `.dmg`, an `.exe`, an `app.asar` — that
the user keeps, copies, and can open at leisure with free tools.

Code generation models do not distinguish between these delivery models. Asked to "call the
OpenAI API from my app" or "upload to S3", the model produces the same shape it produces for a
Node.js server: the key next to the call site. In a server that is correct. In a distributed
binary it publishes the key.

The extraction is not sophisticated:

| Artifact | Extraction | Time |
|---|---|---|
| React Native bundle | `unzip app.apk` then `strings assets/index.android.bundle` | seconds |
| Hermes bytecode | `hermes-dec` / `hbctool` — string table is intact by design | minutes |
| Flutter release | `strings libapp.so`, or Blutter for full Dart reconstruction | minutes |
| Android resources | `apktool d app.apk` — `strings.xml`, manifest `meta-data`, `BuildConfig` fields | seconds |
| iOS IPA | `unzip app.ipa` then `strings Payload/App.app/App` | seconds |
| Electron | `npx @electron/asar extract app.asar` — plain JavaScript | seconds |

Three compounding failures produce the exposure:

| Failure | What the model does | Result |
|---|---|---|
| **Delivery-model confusion** | Places a server-grade key in client code because the SDK example did | Key is in every installed copy |
| **`.env` illusion** | Uses `react-native-config`, `flutter_dotenv`, or `EXPO_PUBLIC_*` believing the value stays out of the binary | Bundler inlines the literal string at build time |
| **Obfuscation as a control** | Base64-encodes, string-splits, or XORs the key and considers it protected | Encoding is not encryption; the decode routine ships alongside it |

The second is the one that fools experienced developers. `flutter_dotenv` reads a `.env` file that
is bundled as an **asset** — `unzip` recovers it verbatim. `react-native-config` writes values into
`BuildConfig` and `Info.plist`. `EXPO_PUBLIC_` is a compile-time substitution by design. None of
these is a runtime secret store.

The same logic governs authorization. A client-side check — "only admins see this button", "the
price is calculated here", "the trial expires after 14 days" — is a rendering decision, not a
control. The attacker patches the binary, hooks the function with Frida, or simply calls your API
directly with `curl`.

---

## 2. Non-Negotiable Rules

### R3.1 — Zero static secrets in any shipped artifact

No credential may appear in an APK, AAB, IPA, `.app`, `.exe`, `.dmg`, `.asar`, or any bundle
served to a device. This includes, explicitly:

- JavaScript / Dart source and compiled bundles, including Hermes bytecode and split chunks
- `strings.xml`, `AndroidManifest.xml` `meta-data`, `BuildConfig`, `gradle.properties` consumed at build time
- `Info.plist`, entitlements, `xcconfig` values, embedded `.plist` assets
- Any `.env` file processed by `flutter_dotenv`, `react-native-config`, `react-native-dotenv`, or `EXPO_PUBLIC_*`
- Native libraries (`.so`, `.dylib`, `.framework`), asset files, JSON fixtures, embedded SQLite seeds
- Comments, test fixtures, disabled code paths, and commit history

**Prohibited without exception:** cloud provider access keys (AWS, GCP, Azure), database service
keys, payment secret keys (`sk_live_*`, `sk_test_*`), LLM provider keys, private signing keys,
push-notification server keys (FCM server key, APNs `.p8`), OAuth client secrets for confidential
clients, webhook signing secrets, admin API tokens.

**Permitted but only when the server enforces authorization independently:** OAuth *public* client
IDs, Firebase configuration values, Stripe publishable keys, Supabase anon keys, Sentry public
DSNs, Maps API keys that carry a platform + package-name restriction.

The distinction is not the name of the value. It is whether **the backend enforces the control**.
A Supabase anon key with no Row-Level Security behind it is a full-access key. A Firebase config
with permissive rules is a full-access key.

### R3.2 — Every privileged operation routes through an authenticated backend gateway

The client calls **your** endpoint. Your endpoint holds the vendor credential and calls the vendor.
The credential never crosses the network boundary toward the device.

Operations that must be server-side, without exception:

- Any call to a metered, paid, or privileged third-party API (LLMs, payments, SMS, email, geocoding, storage)
- Price calculation, discount application, currency conversion, tax computation
- Entitlement, subscription state, trial expiry, feature-flag gating that has commercial value
- Role and permission assignment
- Receipt validation for in-app purchases — validate with Apple/Google server-to-server, never on device
- Any write that other users can read

The gateway is not a pass-through. Every route, in order:

1. **Authenticate** the caller from a server-verified session or token. Never from a client-supplied identity claim.
2. **Authorize** the specific operation against server-side state.
3. **Validate** the request body against an explicit schema. Never forward client JSON verbatim to a vendor.
4. **Rate-limit** per identity, per device, and per IP. An unmetered proxy in front of a paid API is a billing-drain vulnerability even when it leaks nothing.
5. **Constrain** the operation. The client names *what*; the server decides *how much*, *which model*, *which bucket*, *which recipient*, *which price*.
6. **Return the minimum.** Never relay the raw vendor response — vendor errors routinely echo the submitted key.

### R3.3 — Bind the gateway to a real client, not to a shared secret

Since the app cannot hold a secret, it cannot prove its identity with one. An embedded "API key
for our own backend" is decoration — it is in every copy of the app.

Use platform attestation instead:

- **Android:** Play Integrity API — verify the token server-side, check `appRecognitionVerdict` and `deviceRecognitionVerdict`.
- **iOS:** App Attest (`DCAppAttestService`) for key attestation, DeviceCheck for device-level state.
- **Both:** Firebase App Check where the backend already sits in that ecosystem.
- **Desktop:** code signing plus a per-install credential issued at first run and stored per [Module 01](01-hardware-secure-storage.md).

Attestation raises the cost of automated abuse. It is **not** an authorization boundary — a
determined attacker on a rooted device can defeat it. Server-side authorization remains mandatory
regardless of attestation result.

### R3.4 — Obfuscation is friction, never a control

Obfuscation is **required** because it raises the cost of bulk automated scraping. It is
**never** counted as a mitigation for a secret that should not be present.

| Platform | Required build configuration |
|---|---|
| Android | R8/ProGuard with `minifyEnabled true`, `shrinkResources true`, a minimal `-keep` set, and `-printmapping`; upload the mapping file to the crash reporter, never ship it |
| React Native | Hermes enabled for release; source maps generated but **never bundled** — upload to the crash service and exclude from the artifact |
| Flutter | `flutter build --obfuscate --split-debug-info=<dir>`; archive the symbol directory outside the artifact |
| iOS | Strip debug symbols in release, `ENABLE_BITCODE` per current Apple guidance, no `DEBUG` conditionals shipping diagnostic paths |
| Electron | Package into `app.asar` with integrity validation; treat `asar` as a container, not encryption |

Anything achieved by string-splitting, Base64, ROT13, XOR with a constant, or a "hidden" native
`.so` is recoverable. If a value must be recoverable by the app at runtime without a server, it is
recoverable by an attacker. There is no exception to this.

### R3.5 — Transport is TLS-only, validated, and pinned where it matters

**No cleartext HTTP anywhere**, including analytics, image CDNs, update checks, and development
fallbacks:

- Android: `android:usesCleartextTraffic="false"` in the manifest **and** a `network_security_config.xml` with `cleartextTrafficPermitted="false"` for the base config. Do not add a debug-overrides block that ships to release.
- iOS: App Transport Security enabled; `NSAllowsArbitraryLoads` must be `false`, with no `NSExceptionAllowsInsecureHTTPLoads` entries for production hosts.
- Electron / desktop: reject `http://` endpoints in code; never set `rejectUnauthorized: false`; never assign `NODE_TLS_REJECT_UNAUTHORIZED = '0'`.

**Never weaken certificate validation.** A `TrustManager` that accepts all certificates, a
`HostnameVerifier` returning `true`, `URLSession` delegate code calling
`completionHandler(.useCredential, ...)` unconditionally, or a Flutter `badCertificateCallback`
returning `true` are all critical findings — they convert every network on the path into a
man-in-the-middle position. These appear in generated code as fixes for local development TLS
errors, and they ship.

**Pin where the data justifies it** (authentication, payments, health, messaging):

- Pin to the SPKI hash of an intermediate or leaf, with **at least one backup pin** for the next rotation.
- Ship a documented rotation plan and an expiry on the pin set. A pinned app with an expired pin and no backup is a self-inflicted outage.
- Android: `<pin-set>` in `network_security_config.xml`, or OkHttp `CertificatePinner`.
- iOS: `URLSession` delegate validating the SPKI hash, or the ATS pinning keys.
- Never implement pinning with a comparison that falls back to "accept" on parse failure.

### R3.6 — Release builds ship no development affordances

Every one of these is a finding in a production artifact:

- `android:debuggable="true"`, a debug keystore signature, or a debug `network_security_config`
- Flipper, the React Native dev menu, `__DEV__`-gated code that is not eliminated, remote JS debugging
- Electron DevTools opened automatically, `--inspect`, `--remote-debugging-port`, an unfused `runAsNode`
- Staging or localhost endpoints, test accounts, seeded credentials, feature flags that unlock paid functionality
- Verbose logging of requests, responses, headers, or tokens
- Source maps, `.dSYM` bundles, R8 mapping files, or Dart symbol files inside the artifact

### R3.7 — Anything ever shipped is public and must be rotated

A credential in a published build cannot be recalled. Old versions remain installed, mirrored on
APK aggregator sites, and cached in package archives indefinitely.

When a secret is found in an artifact:

1. **Rotate first.** Revoke the credential at the vendor. Do this before touching the code.
2. Audit vendor logs for use from unexpected sources during the exposure window.
3. Move the operation behind the gateway (R3.2).
4. Ship the fixed build, then force-upgrade clients if the exposure is severe.
5. Removing the string from `main` is cleanup, not remediation.

### R3.8 — Tamper and root detection is telemetry, not a boundary

Root/jailbreak detection, emulator detection, debugger detection, and integrity self-checks are
worth shipping — they raise cost and produce useful signal. They run **on the attacker machine**
and can always be defeated.

- Never gate a security decision on a client-side integrity result alone.
- Report the signal to the server and let the server decide (step up authentication, reduce limits, flag the session).
- Never crash silently or in a way that maps directly to one detection function — that is a single hook point.
- The server-side control must be correct with the client-side check entirely removed.

---

## 3. Reference Architecture

```
┌──────────────────────────────┐        ┌───────────────────────────────┐        ┌──────────────┐
│ DEVICE / DISTRIBUTED BINARY  │        │ YOUR GATEWAY (server)         │        │ VENDOR       │
│ APK · IPA · asar · exe       │        │                               │        │ LLM API      │
│                              │        │ 1 authenticate session        │        │ Stripe       │
│ • public client id           │───────▶│ 2 authorize operation         │───────▶│ S3 / storage │
│ • user session token         │  POST  │ 3 validate schema             │ secret │ SMS / email  │
│ • attestation token          │ /v1/x  │ 4 rate-limit id + device + ip │ held   │ push service │
│ • NO vendor credentials      │◀───────│ 5 constrain: model, amount,   │ server │              │
│ • NO signing keys            │ minimal│   bucket, recipient, price    │ side   │              │
│ • NO admin tokens            │ result │ 6 return minimum fields       │◀───────│              │
└──────────────────────────────┘        └───────────────────────────────┘        └──────────────┘
                               ▲
                               │  BINARY TRUST BOUNDARY
                               │  Everything to the left is published. Assume every byte
                               │  of it is read by an adversary the day you ship.
```

---

## 4. Detection

**Scan the built artifact — this is the authoritative test.** Source-level scanning misses values
injected at build time:

```bash
node scripts/scan-artifacts.mjs ./build/app-release.apk
```

```bash
semgrep --config skills/semgrep-rules.yml .
```

**Android:**

```bash
unzip -o app-release.apk -d apk_out && strings -n 8 apk_out/assets/index.android.bundle | grep -aEn "sk_live_|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|-----BEGIN"
```

```bash
apktool d -f app-release.apk -o apktool_out && grep -rEn "api[_-]?key|secret|token|password" apktool_out/res/values/strings.xml apktool_out/AndroidManifest.xml
```

**iOS:**

```bash
unzip -o app.ipa -d ipa_out && strings -n 8 ipa_out/Payload/*.app/* 2>/dev/null | grep -aE "sk_live_|AKIA[0-9A-Z]{16}|-----BEGIN|Bearer "
```

**Flutter:**

```bash
strings -n 8 apk_out/lib/arm64-v8a/libapp.so | grep -aE "sk_live_|AKIA[0-9A-Z]{16}|https?://[a-z0-9.-]*(staging|internal|localhost)"
```

**Electron:**

```bash
npx @electron/asar extract app.asar /tmp/unpacked && npx gitleaks detect --no-git --source /tmp/unpacked
```

**Network posture:**

```bash
grep -rEn "usesCleartextTraffic=\"true\"|NSAllowsArbitraryLoads|rejectUnauthorized: *false|NODE_TLS_REJECT_UNAUTHORIZED" . --include=*.xml --include=*.plist --include=*.js --include=*.ts
```

```bash
grep -rEn "checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|HostnameVerifier|badCertificateCallback|ALLOW_ALL_HOSTNAME" . --include=*.java --include=*.kt --include=*.dart --include=*.swift
```

Any hit from these commands is a **P0**. Rotate the credential before the code change.

**Dynamic proof of gateway design.** Take the session token from a normal, legitimate account and
replay every request with `curl`, changing identifiers, prices, quantities, and role fields. If any
request that the UI would not allow succeeds, the control was client-side.

---

## 5. Agent Constraints

Copy verbatim into the system prompt or rules file of any coding agent:

```text
BINARY TRUST — HARD CONSTRAINTS
1. NEVER place a vendor secret, private key, signing key, admin token, or service credential
   in any file that is compiled or bundled into an APK/AAB/IPA/asar/exe.
2. .env files, react-native-config, flutter_dotenv, EXPO_PUBLIC_*, BuildConfig, strings.xml,
   and Info.plist are ALL bundled into the artifact. They are not secret stores.
3. Every paid, privileged, or authenticated third-party call executes on OUR server. The app
   calls our endpoint; our endpoint calls the vendor.
4. Gateway order, every route: authenticate -> authorize -> validate schema -> rate-limit ->
   constrain parameters -> call vendor -> return minimal fields.
5. Price, entitlement, trial state, role, and receipt validation are computed server-side.
   Never trust a value the client sends for these.
6. NEVER weaken TLS: no accept-all TrustManager, no HostnameVerifier{return true}, no
   badCertificateCallback=>true, no rejectUnauthorized:false, no NODE_TLS_REJECT_UNAUTHORIZED=0.
7. Set usesCleartextTraffic=false + network_security_config, and ATS with
   NSAllowsArbitraryLoads=false. No http:// endpoints, including analytics and updates.
8. Enable R8/ProGuard, Hermes, or --obfuscate --split-debug-info for release. Keep source
   maps, mapping files, and symbol files OUT of the artifact.
9. Obfuscation and root detection are friction, not controls. Never gate a security decision
   on a client-side integrity check alone.
10. Release builds contain no debuggable flag, dev menu, DevTools, staging endpoint, test
    account, or verbose request logging.
11. If a secret was ever in a shipped build: say so, and rotate it before changing code.
```

---

## 6. Worked Example

The gateway pattern is shown end to end alongside the storage fix in
**[examples/mobile-storage-remediation.md](../examples/mobile-storage-remediation.md)**.

Related: [Module 01](01-hardware-secure-storage.md) covers the credential once it reaches the
device. [Module 05](05-build-integrity-and-updates.md) covers signing, notarization, and the
update channel that delivers the artifact.
