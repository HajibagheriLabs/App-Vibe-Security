# Worked Example — Mobile Credential Storage: Vulnerable vs. Remediated

**Modules:** [01 — Hardware-Backed Secure Storage](../modules/01-hardware-secure-storage.md) ·
[03 — Binary Trust and Gateways](../modules/03-binary-trust-and-gateways.md)
**Scenario:** A React Native and Flutter application that keeps the user signed in and calls a
third-party API. The user asked the assistant to "remember the login so users do not have to sign
in every time" and to "call the AI API to summarize notes."

---

## Part 1 — The vulnerable implementation (React Native)

### `auth.ts` — vulnerable

```ts
// ✗ VULNERABLE
import AsyncStorage from '@react-native-async-storage/async-storage';

const API_KEY = 'sk-proj-EXAMPLE-NOT-A-REAL-KEY-000000000000';   // ✗ ships in the bundle

export async function login(email: string, password: string) {
  const res = await fetch('https://api.example.com/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  const { accessToken, refreshToken, user } = await res.json();

  await AsyncStorage.setItem('authToken', accessToken);        // ✗ cleartext
  await AsyncStorage.setItem('refreshToken', refreshToken);    // ✗ cleartext, long-lived
  await AsyncStorage.setItem('user', JSON.stringify(user));    // ✗ cleartext PII
  console.log('Logged in with token', accessToken);            // ✗ token in Logcat
  return user;
}

export async function summarize(text: string) {
  return fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: `Bearer ${API_KEY}` },            // ✗ key leaves the device
    body: JSON.stringify({ model: 'gpt-4', messages: [{ role: 'user', content: text }] }),
  });
}

export async function logout() {
  await AsyncStorage.removeItem('authToken');                  // ✗ refreshToken and user remain
}
```

### `AndroidManifest.xml` — vulnerable

```xml
<!-- ✗ VULNERABLE -->
<application
    android:allowBackup="true"                       
    android:usesCleartextTraffic="true"              
    android:debuggable="true">                       
```

### Exploitation

Every step below uses free, standard tooling and takes under five minutes.

**1. Read the tokens off the device.** AsyncStorage is a SQLite table on Android:

```bash
adb shell run-as com.example.app \
  sqlite3 /data/data/com.example.app/databases/RKStorage \
  "SELECT key, value FROM catalystLocalStorage;"
```

```
authToken|eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
refreshToken|rt_9f2c4a1b8e...
user|{"id":"u_8842","email":"victim@example.com","phone":"+1555...","plan":"pro"}
```

The refresh token is the prize — it outlives the access token by weeks.

**2. Lift it without root**, because `allowBackup="true"`:

```bash
adb backup -f out.ab com.example.app
```

**3. Extract the API key from the bundle**, because it is a string literal:

```bash
unzip -o app-release.apk -d out && strings out/assets/index.android.bundle | grep -o 'sk-proj-[A-Za-z0-9-]*'
```

```
sk-proj-EXAMPLE-NOT-A-REAL-KEY-000000000000
```

The attacker now bills their own workload to the developer's account, at the developer's rate
limits, with no way to attribute it to a specific user.

**4. Read the token out of the logs** — `console.log` reaches Logcat in release builds:

```bash
adb logcat | grep -i "logged in with token"
```

---

## Part 2 — The remediated implementation (React Native)

### `secureStore.ts` — the only module that touches persistence

```ts
// ✓ REMEDIATED
import * as Keychain from 'react-native-keychain';

const SERVICE = 'com.example.app.auth';

// Hardware-backed, device-only, wiped as a unit.
export const secureStore = {
  async setRefreshToken(token: string) {
    const ok = await Keychain.setGenericPassword('refresh', token, {
      service: SERVICE,
      accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,  // ✓ never restored elsewhere
      securityLevel: Keychain.SECURITY_LEVEL.SECURE_HARDWARE,          // ✓ TEE / StrongBox
      storage: Keychain.STORAGE_TYPE.AES_GCM,                          // ✓ authenticated encryption
    });
    if (!ok) throw new Error('E_NO_SECURE_STORAGE');   // ✓ never fall back to plaintext
  },

  async getRefreshToken(): Promise<string | null> {
    const creds = await Keychain.getGenericPassword({ service: SERVICE });
    return creds ? creds.password : null;
  },

  async wipe() {
    await Keychain.resetGenericPassword({ service: SERVICE });         // ✓ whole store
  },
};

// High-value items — payment credentials, recovery phrases — additionally require
// user presence, with the key destroyed if a new biometric is enrolled.
export async function setHighValueSecret(key: string, value: string) {
  await Keychain.setGenericPassword(key, value, {
    service: `${SERVICE}.hv`,
    accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,       // ✓ NOT BIOMETRY_ANY
    securityLevel: Keychain.SECURITY_LEVEL.SECURE_HARDWARE,
  });
}
```

### `auth.ts` — remediated

```ts
// ✓ REMEDIATED
import { secureStore } from './secureStore';

// Access token lives in memory for the process lifetime. It is never written to disk.
let accessToken: string | null = null;
export const getAccessToken = () => accessToken;

export async function login(email: string, password: string) {
  const res = await fetch('https://api.example.com/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw new Error('E_LOGIN');
  const { accessToken: at, refreshToken } = await res.json();

  accessToken = at;                                  // ✓ memory only
  await secureStore.setRefreshToken(refreshToken);   // ✓ hardware-backed, device-only
  // ✓ No PII cached. The profile is fetched from the server with the session identity.
  // ✓ No token logged, ever.
  return fetchProfile();
}

export async function logout() {
  accessToken = null;
  await secureStore.wipe();                          // ✓ everything, not one key
  await fetch('https://api.example.com/logout', { method: 'POST' });   // ✓ revoke server-side
}

// iOS Keychain items survive app uninstall. Clear on first launch after a fresh install,
// or the next owner of the device inherits the session.
export async function clearStaleKeychainOnFirstRun() {
  const seen = await AsyncStorage.getItem('installMarker');   // non-sensitive flag: fine here
  if (!seen) {
    await secureStore.wipe();
    await AsyncStorage.setItem('installMarker', '1');
  }
}

// ✓ No vendor key on the device. The app calls OUR endpoint; our endpoint calls the vendor.
export async function summarize(noteId: string) {
  const res = await fetch('https://api.example.com/v1/notes/summarize', {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ noteId }),                // ✓ an id, not the model, not the prompt
  });
  if (!res.ok) throw new Error('E_SUMMARIZE');
  return res.json();
}
```

### The gateway that replaces the embedded key — server side

```ts
// ✓ REMEDIATED — server. The vendor key exists only here.
export async function POST(req: Request) {
  // 1. authenticate — from the verified session, never from the request body
  const session = await requireSession(req);

  // 2. validate schema
  const { noteId } = SummarizeSchema.parse(await req.json());

  // 3. authorize — ownership predicate in the query, not a post-fetch check
  const note = await db.note.findFirst({ where: { id: noteId, ownerId: session.userId } });
  if (!note) return json({ error: 'not_found' }, 404);   // 404, not 403 — no enumeration

  // 4. rate-limit per identity and per device
  await rateLimit(`summarize:${session.userId}`, { max: 20, window: '1h' });

  // 5. constrain — the server chooses the model, the length, and the prompt shape
  const out = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    max_tokens: 400,
    messages: [{ role: 'system', content: SYSTEM_PROMPT }, { role: 'user', content: note.body }],
  });

  // 6. return the minimum — never relay the raw vendor response
  return json({ summary: out.choices[0].message.content });
}
```

### `AndroidManifest.xml` — remediated

```xml
<!-- ✓ REMEDIATED -->
<application
    android:allowBackup="false"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/network_security_config">
```

```xml
<!-- res/xml/network_security_config.xml — ✓ base config, not a debug override -->
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors><certificates src="system" /></trust-anchors>
  </base-config>
</network-security-config>
```

Add `FLAG_SECURE` to any screen showing credentials or recovery material:

```kotlin
window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
```

---

## Part 3 — The same fix in Flutter

### Vulnerable

```dart
// ✗ VULNERABLE
final prefs = await SharedPreferences.getInstance();
await prefs.setString('authToken', token);         // ✗ cleartext XML / plist
await prefs.setString('refreshToken', refresh);    // ✗ cleartext, long-lived
await prefs.setBool('isPremium', true);            // ✗ entitlement decided on the client

final apiKey = dotenv.env['OPENAI_KEY'];           // ✗ .env is bundled as an ASSET
```

`flutter_dotenv` bundles the `.env` file as an asset. `unzip -p app.apk assets/.env` recovers it
verbatim.

### Remediated

```dart
// ✓ REMEDIATED
const _storage = FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences: true),                   // ✓ Keystore-backed
  iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device), // ✓ device-only
);

String? _accessToken;                              // ✓ memory only

Future<void> login(String email, String password) async {
  final res = await _http.post(Uri.parse('https://api.example.com/login'),
      body: jsonEncode({'email': email, 'password': password}));
  if (res.statusCode != 200) throw Exception('E_LOGIN');
  final body = jsonDecode(res.body);

  _accessToken = body['accessToken'];                                  // ✓ not persisted
  await _storage.write(key: 'refreshToken', value: body['refreshToken']);  // ✓ hardware-backed
}

Future<void> logout() async {
  _accessToken = null;
  await _storage.deleteAll();                      // ✓ the whole store
}

// ✓ Entitlement comes from the server on every session, never from local state.
Future<bool> hasPremium() async {
  final res = await _authedGet('/v1/me/entitlements');
  return (jsonDecode(res.body)['premium'] as bool?) ?? false;
}
```

Release build, with obfuscation and symbols kept out of the artifact:

```bash
flutter build apk --release --obfuscate --split-debug-info=build/symbols
```

---

## Part 4 — What changed, and why each change matters

| # | Vulnerable | Remediated | What it stops |
|---|---|---|---|
| 1 | `AsyncStorage` / `SharedPreferences` for tokens | Keychain / Keystore via the platform plugin | `adb run-as`, backup extraction, forensic imaging |
| 2 | Access token persisted | Access token in memory only | Nothing durable to steal from disk |
| 3 | Default accessibility | `WHEN_UNLOCKED_THIS_DEVICE_ONLY` / `first_unlock_this_device` | Restore onto an attacker device from a backup |
| 4 | `BIOMETRY_ANY` for high-value items | `BIOMETRY_CURRENT_SET` | Attacker enrolling their own biometric on an unlocked device |
| 5 | PII cached locally | Fetched per session with the session identity | Profile, email, and phone readable from the sandbox |
| 6 | `removeItem('authToken')` on logout | `wipe()` of the whole store + server revoke | Orphaned refresh token surviving sign-out |
| 7 | Keychain persists after uninstall | Cleared on first run after install | Next device owner inheriting the session |
| 8 | Vendor key in the bundle | Server gateway holds the key | `strings` on the bundle; billing abuse; quota theft |
| 9 | Client picks model and prompt | Server constrains both | Prompt and model substitution, cost inflation |
| 10 | `isPremium` stored locally | Entitlement read from the server | Patching the binary to unlock paid features |
| 11 | `console.log(token)` | No secret logged | Token recovery from Logcat |
| 12 | `allowBackup="true"` | `false` + extraction rules | One-command sandbox exfiltration |
| 13 | `usesCleartextTraffic="true"` | `false` + network security config | Interception on any hostile network |
| 14 | `debuggable="true"` | Removed | `run-as` on a non-rooted device |
| 15 | No obfuscation | R8 / Hermes / Dart obfuscation, symbols excluded | Bulk automated scraping of the artifact |

Rows 1–7 protect data at rest. Rows 8–10 remove the reason the credential was on the device at all
— that one is architectural, and it is the change that actually matters.

---

## Part 5 — Verify the fix

```bash
semgrep --config skills/semgrep-rules.yml .
```

```bash
node scripts/audit-native.mjs .
```

```bash
node scripts/scan-artifacts.mjs ./android/app/build/outputs/apk/release/app-release.apk
```

**Prove it on a device.** Log in, background the app, then read the sandbox — the commands that
worked in Part 1 must now return nothing:

```bash
adb shell run-as com.example.app sqlite3 /data/data/com.example.app/databases/RKStorage "SELECT key, value FROM catalystLocalStorage;"
```

```bash
unzip -p app-release.apk assets/index.android.bundle | strings | grep -E "sk-|sk_live_|AKIA[0-9A-Z]{16}"
```

**If any secret was ever in a shipped build: rotate it at the vendor first.** Removing the string
from `main` is cleanup, not remediation — every previously installed copy still contains it.

**Negative tests to ship with the change:**

```ts
test('no token reaches AsyncStorage', async () => {
  await login('a@b.c', 'pw');
  const all = await AsyncStorage.multiGet(await AsyncStorage.getAllKeys());
  const dump = JSON.stringify(all);
  expect(dump).not.toMatch(/eyJ[A-Za-z0-9_-]{10,}/);   // no JWT
  expect(dump).not.toMatch(/refresh/i);
});

test('logout clears the entire secure store', async () => {
  await login('a@b.c', 'pw');
  await logout();
  expect(await secureStore.getRefreshToken()).toBeNull();
  expect(getAccessToken()).toBeNull();
});

test('secure storage failure throws rather than degrading', async () => {
  mockKeychainUnavailable();
  await expect(secureStore.setRefreshToken('x')).rejects.toThrow('E_NO_SECURE_STORAGE');
});

test('summarize rejects a note owned by another user', async () => {
  const res = await callGateway(userA, { noteId: userBNoteId });
  expect(res.status).toBe(404);
});
```
