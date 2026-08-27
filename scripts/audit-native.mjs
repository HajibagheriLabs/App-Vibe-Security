#!/usr/bin/env node
/**
 * audit-native.mjs — deterministic security audit for native applications.
 *
 * Covers the ground Semgrep cannot reach without a language pack: Android manifests,
 * iOS property lists, Gradle and build configuration, Electron packaging, and live
 * registry verification of declared dependencies.
 *
 *   node scripts/audit-native.mjs [path] [options]
 *
 * Options:
 *   --check-deps     Verify every declared dependency exists in its live registry
 *                    (npm, pub.dev). Requires network access.
 *   --exclude <p>    Skip paths containing this substring (repeatable, or comma-separated).
 *                    Use for directories of deliberately vulnerable test fixtures.
 *   --json           Emit findings as JSON.
 *   --quiet          Suppress the passing-checks section.
 *   --no-color       Disable ANSI colour.
 *
 * Exit codes:  0 = no ERROR findings   1 = one or more ERROR findings   2 = usage error
 *
 * Zero dependencies. Node 18+.
 * Reference: modules/ — rule identifiers in each finding map to the module rules.
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, basename, extname, sep } from 'node:path';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'build', 'dist', 'out', 'release',
  'Pods', 'DerivedData', '.gradle', '.dart_tool', '.expo', '.next', 'vendor',
  '__pycache__', '.venv', 'coverage', '.idea', '.vscode', 'Carthage',
]);

const CODE_EXT = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.dart', '.java', '.kt', '.kts', '.swift', '.m', '.mm',
]);

const CONFIG_EXT = new Set(['.xml', '.plist', '.gradle', '.json', '.yml', '.yaml', '.properties', '.entitlements']);

// Detector definitions necessarily contain the patterns they detect.
const SELF_SKIP = new Set(['semgrep-rules.yml', 'audit-native.mjs', 'scan-artifacts.mjs']);

const MAX_FILE_BYTES = 2 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Rules — each entry: id, rule (module reference), severity, test, message
// `where` selects which files the check runs against.
// ---------------------------------------------------------------------------

const SENSITIVE_KEY = String.raw`(token|jwt|auth|secret|password|passwd|credential|session|refresh|api[_-]?key|apikey|private[_-]?key|access[_-]?key|bearer|pin|otp|totp|seed|mnemonic|passphrase|ssn|cvv|card[_-]?number)`;

/** @type {Array<{id:string,rule:string,severity:'ERROR'|'WARNING',where:(f:string)=>boolean,re:RegExp,title:string,fix:string,rotate?:boolean}>} */
const RULES = [
  // ===================== MODULE 01 — SECURE STORAGE ========================
  {
    id: 'AVS-101', rule: 'M01/R1.2', severity: 'ERROR', where: isCode,
    re: new RegExp(String.raw`AsyncStorage\s*\.\s*(setItem|mergeItem)\s*\(\s*['"\`][^'"\`]*` + SENSITIVE_KEY, 'i'),
    title: 'Sensitive value written to AsyncStorage (cleartext)',
    fix: 'Use react-native-keychain or expo-secure-store with WHEN_UNLOCKED_THIS_DEVICE_ONLY.',
  },
  {
    id: 'AVS-102', rule: 'M01/R1.2', severity: 'ERROR', where: isCode,
    re: new RegExp(String.raw`(localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*['"\`][^'"\`]*` + SENSITIVE_KEY, 'i'),
    title: 'Sensitive value written to localStorage / sessionStorage',
    fix: 'Use Electron safeStorage or the platform keychain; keep access tokens in memory.',
  },
  {
    id: 'AVS-103', rule: 'M01/R1.2', severity: 'ERROR', where: isCode,
    re: new RegExp(String.raw`(setString|setBool|setInt|putString)\s*\(\s*['"\`][^'"\`]*` + SENSITIVE_KEY, 'i'),
    title: 'Sensitive value written to SharedPreferences / shared_preferences (cleartext)',
    fix: 'Use EncryptedSharedPreferences, or flutter_secure_storage with encryptedSharedPreferences: true.',
  },
  {
    id: 'AVS-104', rule: 'M01/R1.2', severity: 'ERROR', where: isCode,
    re: new RegExp(String.raw`UserDefaults[^\n]{0,60}forKey\s*:\s*['"\`][^'"\`]*` + SENSITIVE_KEY, 'i'),
    title: 'Sensitive value written to UserDefaults (cleartext plist, included in backups)',
    fix: 'Use Keychain Services with kSecAttrAccessibleWhenUnlockedThisDeviceOnly.',
  },
  {
    id: 'AVS-105', rule: 'M01/R1.5', severity: 'WARNING', where: isCode,
    re: /(BIOMETRY_ANY|\.biometryAny|setInvalidatedByBiometricEnrollment\s*\(\s*false\s*\))/,
    title: 'Biometric key survives enrolment of a new biometric',
    fix: 'Use .biometryCurrentSet (iOS) / setInvalidatedByBiometricEnrollment(true) (Android).',
  },
  {
    id: 'AVS-106', rule: 'M01/R1.6', severity: 'WARNING', where: (f) => basename(f) === 'AndroidManifest.xml',
    re: /android:allowBackup\s*=\s*"true"/,
    title: 'android:allowBackup="true" — sandbox is extractable via adb backup',
    fix: 'Set allowBackup="false", or supply dataExtractionRules excluding credential stores.',
  },
  {
    id: 'AVS-107', rule: 'M01/R1.8', severity: 'WARNING', where: isCode,
    re: new RegExp(String.raw`(console\.log|print|NSLog|Log\.[dviwe])\s*\([^)\n]{0,80}` + SENSITIVE_KEY, 'i'),
    title: 'Possible sensitive value written to a log sink',
    fix: 'Redact by allowlist. Logcat and crash breadcrumbs are readable off-device.',
  },

  // ================ MODULE 02 — DESKTOP PROCESS ISOLATION =================
  {
    id: 'AVS-201', rule: 'M02/R2.1', severity: 'ERROR', where: isCode,
    re: /nodeIntegration(InWorker|InSubFrames)?\s*:\s*true/,
    title: 'nodeIntegration enabled — renderer injection becomes host code execution',
    fix: 'Set nodeIntegration: false and add a narrow, parameter-validated IPC channel.',
  },
  {
    id: 'AVS-202', rule: 'M02/R2.1', severity: 'ERROR', where: isCode,
    re: /contextIsolation\s*:\s*false/,
    title: 'contextIsolation disabled — preload and page share one JavaScript context',
    fix: 'Set contextIsolation: true. It is the default from Electron 12.',
  },
  {
    id: 'AVS-203', rule: 'M02/R2.1', severity: 'ERROR', where: isCode,
    re: /(webSecurity\s*:\s*false|allowRunningInsecureContent\s*:\s*true|experimentalFeatures\s*:\s*true)/,
    title: 'Same-origin policy or insecure-content protection disabled',
    fix: 'Restore webSecurity: true. Fix CORS at the server or proxy through the main process.',
  },
  {
    id: 'AVS-204', rule: 'M02/R2.1', severity: 'WARNING', where: isCode,
    re: /sandbox\s*:\s*false/,
    title: 'Renderer sandbox disabled',
    fix: 'Set sandbox: true and call app.enableSandbox() before app.whenReady().',
  },
  {
    id: 'AVS-205', rule: 'M02/R2.3', severity: 'ERROR', where: isCode,
    re: /exposeInMainWorld[\s\S]{0,400}?\b(child_process|require\s*\(|[^.\w]fs\s*[,:}]|\bexecSync\b|\bexec\b\s*[,:]|shell\s*[,:}]|ipcRenderer\s*[,:}])/,
    title: 'contextBridge exposes a Node module or raw capability to the renderer',
    fix: 'Expose named single-purpose functions with typed parameters. Decide privilege in main.',
  },
  {
    id: 'AVS-206', rule: 'M02/R2.3', severity: 'ERROR', where: isCode,
    re: /\(\s*channel\s*,\s*\.\.\.\s*\w+\s*\)\s*=>\s*ipcRenderer\.(invoke|send)/,
    title: 'Generic ipcRenderer passthrough exposed — the entire IPC surface is reachable',
    fix: 'One bridge function per business operation, with a fixed channel name.',
  },
  {
    id: 'AVS-207', rule: 'M02/R2.4', severity: 'ERROR', where: isCode,
    re: /ipcMain\s*\.\s*(handle|on)\s*\([\s\S]{0,600}?\b(exec|execSync)\s*\(|ipcMain\s*\.\s*(handle|on)\s*\([\s\S]{0,600}?shell\s*:\s*true/,
    title: 'Shell execution reachable from an IPC handler',
    fix: 'Use execFile(constantBinary, [args]). Never build a command string from IPC data.',
  },
  {
    id: 'AVS-208', rule: 'M02/R2.5', severity: 'ERROR', where: isCode,
    re: /setWindowOpenHandler\s*\([\s\S]{0,200}?action\s*:\s*['"]allow['"]/,
    title: 'setWindowOpenHandler returns allow — child window inherits opener permissions',
    fix: "Return { action: 'deny' } and route external links through a validated openExternal.",
  },
  {
    id: 'AVS-209', rule: 'M02/R2.9', severity: 'WARNING', where: isCode,
    re: /(runAsNode\s*[:=]\s*true|enableNodeCliInspectArguments\s*[:=]\s*true|enableNodeOptionsEnvironmentVariable\s*[:=]\s*true|onlyLoadAppFromAsar\s*[:=]\s*false)/,
    title: 'Electron fuse left in an unsafe state',
    fix: 'Disable runAsNode, node CLI inspect arguments, and the NODE_OPTIONS fuse.',
  },
  {
    id: 'AVS-210', rule: 'M02/R2.9', severity: 'ERROR', where: isCode,
    re: /(--remote-debugging-port|--inspect(-brk)?[=\s'"]|ELECTRON_DISABLE_SECURITY_WARNINGS)/,
    title: 'Debug channel enabled or security warnings suppressed',
    fix: 'Remove the switch. A debugging port is a full code-execution channel.',
  },
  {
    id: 'AVS-211', rule: 'M02/R2.11', severity: 'ERROR', where: (f) => basename(f).includes('tauri.conf'),
    re: /"(all|execute|sidecar)"\s*:\s*true/,
    title: 'Tauri allowlist grants blanket filesystem or shell capability',
    fix: 'Expose named commands; scope filesystem access to one directory.',
  },

  // ============ MODULE 03 — BINARY TRUST AND BACKEND GATEWAYS =============
  {
    id: 'AVS-301', rule: 'M03/R3.1', severity: 'ERROR', where: (f) => isCode(f) || isConfig(f), rotate: true,
    re: /(sk_live_[0-9a-zA-Z]{16,}|sk_test_[0-9a-zA-Z]{16,}|rk_live_[0-9a-zA-Z]{16,}|sk-[A-Za-z0-9_-]{32,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)/,
    title: 'Vendor credential literal present — it ships inside the artifact',
    fix: 'Move the call behind an authenticated server gateway. ROTATE THE KEY NOW.',
  },
  {
    id: 'AVS-302', rule: 'M03/R3.1', severity: 'WARNING', where: (f) => isCode(f) || isConfig(f),
    re: /(?:api[_-]?key|apikey|secret|secret[_-]?key|private[_-]?key|access[_-]?token|client[_-]?secret|master[_-]?key|signing[_-]?key)\s*[:=]\s*["'][A-Za-z0-9_\-/+=]{20,}["']/i,
    title: 'Constant named like a secret assigned a long literal',
    fix: 'Every string in a distributed artifact is public. Move it server-side, or rename it if it is genuinely public.',
  },
  {
    id: 'AVS-303', rule: 'M03/R3.1', severity: 'ERROR', where: isCode,
    re: /(process\.env|import\.meta\.env)\.(EXPO_PUBLIC_|REACT_APP_|NEXT_PUBLIC_|VITE_|PUBLIC_)\w*(SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|CREDENTIAL|ACCESS_TOKEN|CLIENT_SECRET|SIGNING|MASTER|ADMIN|API_SECRET)/,
    title: 'Secret behind a public build-time environment prefix',
    fix: 'Public prefixes are inlined as literals into the shipped bundle. Move it server-side and rotate.',
  },
  {
    id: 'AVS-304', rule: 'M03/R3.5', severity: 'ERROR', where: isCode,
    re: /(rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0|strictSSL\s*:\s*false|badCertificateCallback\s*=[^;\n]{0,60}=>\s*true|ALLOW_ALL_HOSTNAME_VERIFIER)/,
    title: 'TLS certificate validation disabled',
    fix: 'Restore validation. Install a development CA on the test device instead.',
  },
  {
    id: 'AVS-305', rule: 'M03/R3.5', severity: 'ERROR', where: isCode,
    re: /(checkServerTrusted\s*\([^)]*\)\s*(throws\s+CertificateException\s*)?\{\s*\}|HostnameVerifier\s*\{\s*_?\s*,?\s*_?\s*->\s*true\s*\}|verify\s*\([^)]*\)\s*(:\s*Boolean\s*)?\{\s*return\s+true\s*;?\s*\})/,
    title: 'TrustManager or HostnameVerifier accepts every certificate',
    fix: 'Use the platform trust store; pin with network_security_config or CertificatePinner.',
  },
  {
    id: 'AVS-306', rule: 'M03/R3.5', severity: 'ERROR',
    where: (f) => ['AndroidManifest.xml', 'network_security_config.xml'].includes(basename(f)),
    re: /(android:usesCleartextTraffic\s*=\s*"true"|cleartextTrafficPermitted\s*=\s*"true")/,
    title: 'Cleartext HTTP permitted by Android configuration',
    fix: 'Set usesCleartextTraffic="false" and cleartextTrafficPermitted="false" in the base config.',
  },
  {
    id: 'AVS-307', rule: 'M03/R3.5', severity: 'ERROR', where: (f) => extname(f) === '.plist',
    re: /<key>NSAllowsArbitraryLoads(InWebContent|ForMedia)?<\/key>\s*<true\s*\/>/,
    title: 'App Transport Security disabled (NSAllowsArbitraryLoads)',
    fix: 'Remove the exception, or scope it to one legacy host with NSExceptionDomains.',
  },
  {
    id: 'AVS-308', rule: 'M03/R3.6', severity: 'ERROR', where: (f) => basename(f) === 'AndroidManifest.xml',
    re: /android:debuggable\s*=\s*"true"/,
    title: 'android:debuggable="true" — any user can read the private data directory',
    fix: 'Remove the attribute. Debug builds set it automatically.',
  },
  {
    id: 'AVS-309', rule: 'M03/R3.5', severity: 'WARNING', where: isCode,
    re: /["'`]http:\/\/(?!localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0|\[::1\])[a-zA-Z0-9]/,
    title: 'Cleartext http:// endpoint',
    fix: 'Use https. Analytics and update checks count.',
  },
  {
    id: 'AVS-310', rule: 'M03/R3.1', severity: 'WARNING', where: isCode,
    re: /(flutter_dotenv|dotenv\.load\s*\(|react-native-config|react-native-dotenv)/,
    title: 'Client-side dotenv loader — the .env file is bundled into the artifact',
    fix: 'Non-sensitive configuration only. Secrets belong behind the server gateway.',
  },

  // =================== MODULE 04 — DEEP LINK VERIFICATION =================
  {
    id: 'AVS-401', rule: 'M04/R4.4', severity: 'ERROR', where: isCode,
    re: /(queryParams|searchParams|queryParameters|route\.params|getQueryParameter\()[\s\S]{0,40}?\b(isAdmin|is_admin|isPremium|is_premium|isPro|entitlement|role|verified|amount|price|total|access_token|authToken)\b/,
    title: 'Identity, entitlement, price, or token read from URL parameters',
    fix: 'A link may navigate; it may never authorize or mutate. Fetch the value from the server.',
  },
  {
    id: 'AVS-402', rule: 'M04/R4.3', severity: 'ERROR', where: isCode,
    re: /(navigation|Navigator|router)\s*\.\s*(navigate|push|replace|pushNamed)\s*\(\s*(path|url\.path|parsed\.path|uri\.path|\w*[Pp]ath)\s*,/,
    title: 'Deep link path routed straight into navigation',
    fix: 'Resolve through a closed route map with a typed schema per route.',
  },
  {
    id: 'AVS-403', rule: 'M04/R4.5', severity: 'ERROR', where: isCode,
    re: /\b\w*(?:url|uri|host|origin|redirect|returnTo|callback|next)\w*\s*\.\s*(startsWith|endsWith|includes|contains|hasPrefix|hasSuffix)\s*\(/i,
    title: 'URL or host validated with a substring test',
    fix: 'Parse with the URL API and compare hostname for exact equality against an allowlist.',
  },
  {
    id: 'AVS-404', rule: 'M04/R4.6', severity: 'ERROR', where: isCode,
    re: /(Intent\.parseUri\s*\(|\(Intent\)\s*\w+\.getParcelableExtra\s*\(|getParcelableExtra\s*\([^)]*\)\s*as\s*Intent)/,
    title: 'Untrusted Intent parsed or forwarded (implicit intent redirection)',
    fix: 'Switch on a validated identifier and build the Intent explicitly.',
  },
  {
    id: 'AVS-405', rule: 'M04/R4.8', severity: 'ERROR', where: isCode,
    re: /(second-instance|open-url)[\s\S]{0,300}?(loadURL|openExternal|openPath|execFile)\s*\(\s*(argv|\w*[Uu]rl\b)/,
    title: 'Protocol-handler argv passed to a privileged sink without filtering',
    fix: 'Drop every argv item beginning with "-", then run the value through the URL resolver.',
  },
  {
    id: 'AVS-406', rule: 'M04/R4.2', severity: 'WARNING', where: isCode,
    re: /(WebView|WKWebView|InAppWebView)[^\n]{0,120}(oauth|authorize|\/login|signin|sign-in)/i,
    title: 'Authentication flow rendered in an embedded WebView',
    fix: 'Use ASWebAuthenticationSession (iOS) or Chrome Custom Tabs (Android).',
  },
  {
    id: 'AVS-407', rule: 'M04/R4.6', severity: 'WARNING', where: isCode,
    re: /PendingIntent\.(getActivity|getService|getBroadcast)\s*\((?![\s\S]{0,200}FLAG_IMMUTABLE)/,
    title: 'PendingIntent created without FLAG_IMMUTABLE',
    fix: 'Use FLAG_IMMUTABLE, or FLAG_MUTABLE with a fully specified explicit component.',
  },

  // ============ MODULE 05 — SUPPLY CHAIN AND BUILD INTEGRITY ==============
  {
    id: 'AVS-501', rule: 'M05/R5.5', severity: 'ERROR', where: (f) => isCode(f) || isConfig(f),
    re: /(setFeedURL\s*\(\s*["'`]?http:\/\/|url\s*:\s*["'`]http:\/\/[^"'`]*(update|release|latest|appcast))/i,
    title: 'Auto-update feed over cleartext HTTP',
    fix: 'HTTPS plus signature verification against a key compiled into the application.',
  },
  {
    id: 'AVS-502', rule: 'M05/R5.4', severity: 'ERROR', where: (f) => isConfig(f), rotate: true,
    re: /(storePassword|keyPassword)\s*[=:]\s*["']?[^\s"'#]{3,}/i,
    title: 'Signing password present in a build configuration file',
    fix: 'Move signing material to the CI secret store or an HSM. Revoke and reissue.',
  },
];

// ---------------------------------------------------------------------------
// Structural checks (presence / absence, not a single regex)
// ---------------------------------------------------------------------------

/** @param {{files:string[], root:string, read:(f:string)=>string}} ctx */
function structuralChecks(ctx) {
  const out = [];
  const { files, root, read } = ctx;
  const rel = (f) => relative(root, f).split(sep).join('/');

  const manifests = files.filter((f) => basename(f) === 'AndroidManifest.xml');
  const hasElectron = files.some((f) => /electron/i.test(read(f)) && isCode(f));
  const gradleFiles = files.filter((f) => extname(f) === '.gradle' || basename(f) === 'build.gradle.kts');

  // -- Android: exported components without an explicit attribute ------------
  for (const m of manifests) {
    const src = read(m);
    if (/<intent-filter/.test(src) && !/android:exported\s*=/.test(src)) {
      out.push(mk('AVS-411', 'M04/R4.6', 'WARNING', rel(m), 0,
        'Component declares an intent-filter without an explicit android:exported',
        'Set android:exported explicitly on every activity, service, receiver, and provider.'));
    }
    if (/android:scheme\s*=\s*"(?!https?")/.test(src) && !/android:autoVerify\s*=\s*"true"/.test(src)) {
      out.push(mk('AVS-412', 'M04/R4.2', 'WARNING', rel(m), 0,
        'Custom URI scheme registered with no verified App Link alongside it',
        'Any installed app can claim a custom scheme. Use App Links with autoVerify for anything security-relevant.'));
    }
    if (!/android:networkSecurityConfig\s*=/.test(src) && !/android:usesCleartextTraffic\s*=\s*"false"/.test(src)) {
      out.push(mk('AVS-413', 'M03/R3.5', 'WARNING', rel(m), 0,
        'No network security configuration and no explicit cleartext denial',
        'Add android:networkSecurityConfig with cleartextTrafficPermitted="false" in the base config.'));
    }
  }

  // -- Android: release build without R8 -----------------------------------
  for (const g of gradleFiles) {
    const src = read(g);
    if (/release\s*\{/.test(src) && /minifyEnabled\s+false/.test(src)) {
      out.push(mk('AVS-321', 'M03/R3.4', 'WARNING', rel(g), 0,
        'Release build has minifyEnabled false — no R8 shrinking or obfuscation',
        'Set minifyEnabled true and shrinkResources true; keep the mapping file out of the artifact.'));
    }
  }

  // -- Electron: required hardening that must exist somewhere ---------------
  if (hasElectron) {
    const all = files.filter(isCode).map(read).join('\n');
    const need = [
      ['setWindowOpenHandler', 'AVS-221', 'M02/R2.5', 'No setWindowOpenHandler found — child windows inherit opener permissions',
        "Add contents.setWindowOpenHandler(() => ({ action: 'deny' })) on web-contents-created."],
      ['will-navigate', 'AVS-222', 'M02/R2.5', 'No will-navigate handler found — the renderer can navigate anywhere',
        'Add a will-navigate handler that preventDefaults any non-internal URL.'],
      ['onHeadersReceived', 'AVS-223', 'M02/R2.7', 'No main-process Content-Security-Policy found',
        'Set the CSP via session.defaultSession.webRequest.onHeadersReceived. A meta tag is rewritable.'],
      ['setPermissionRequestHandler', 'AVS-224', 'M02/R2.8', 'No permission request handler — device permissions are granted by default',
        'Deny by default with setPermissionRequestHandler and setPermissionCheckHandler.'],
      ['enableSandbox', 'AVS-225', 'M02/R2.1', 'app.enableSandbox() not called — a window added later can omit the sandbox',
        'Call app.enableSandbox() before app.whenReady().'],
    ];
    for (const [needle, id, rule, title, fix] of need) {
      if (!all.includes(needle)) out.push(mk(id, rule, 'WARNING', '(project)', 0, title, fix));
    }
  }

  // -- Lockfiles present ----------------------------------------------------
  const manifestPairs = [
    ['package.json', ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']],
    ['pubspec.yaml', ['pubspec.lock']],
  ];
  for (const [mf, locks] of manifestPairs) {
    const hasManifest = files.some((f) => basename(f) === mf);
    const hasLock = files.some((f) => locks.includes(basename(f)));
    if (hasManifest && !hasLock) {
      out.push(mk('AVS-511', 'M05/R5.2', 'WARNING', mf, 0,
        `${mf} present with no committed lockfile`,
        `Commit ${locks[0]} and install from it in CI (npm ci / --frozen-lockfile).`));
    }
  }

  // -- Loose version ranges -------------------------------------------------
  for (const f of files.filter((x) => basename(x) === 'package.json')) {
    let pkg;
    try { pkg = JSON.parse(read(f)); } catch { continue; }
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    const loose = Object.entries(deps).filter(([, v]) => typeof v === 'string' && /^[\^~]|^\*$|^latest$/.test(v));
    if (loose.length) {
      out.push(mk('AVS-512', 'M05/R5.2', 'WARNING', rel(f), 0,
        `${loose.length} dependency version range(s) not pinned exactly (e.g. ${loose.slice(0, 3).map(([k, v]) => `${k}@${v}`).join(', ')})`,
        'Pin exact versions and set save-exact=true. A range is a future unreviewed install.'));
    }
  }

  // -- Signing material committed ------------------------------------------
  for (const f of files) {
    const b = basename(f);
    if (/\.(jks|keystore|p12|pfx|p8|mobileprovision)$/i.test(b) || b === 'key.properties') {
      out.push(mk('AVS-513', 'M05/R5.4', 'ERROR', rel(f), 0,
        'Signing material present in the working tree',
        'Remove, revoke, and reissue. Signing keys belong in the CI secret store or an HSM.', true));
    }
  }

  // -- .gitignore covers secrets -------------------------------------------
  const gi = files.find((f) => basename(f) === '.gitignore');
  if (gi) {
    const src = read(gi);
    const missing = ['.env', '*.jks', '*.p12', 'key.properties'].filter((p) => !src.includes(p));
    if (missing.length) {
      out.push(mk('AVS-514', 'M05/R5.4', 'WARNING', rel(gi), 0,
        `.gitignore does not cover: ${missing.join(', ')}`,
        'Add these patterns before any such file is created, not after.'));
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// Dependency existence check (--check-deps)
// ---------------------------------------------------------------------------

async function checkDependencies(ctx) {
  const { files, root, read } = ctx;
  const out = [];
  const rel = (f) => relative(root, f).split(sep).join('/');
  const targets = [];

  for (const f of files.filter((x) => basename(x) === 'package.json')) {
    let pkg; try { pkg = JSON.parse(read(f)); } catch { continue; }
    if (pkg.private && !pkg.dependencies && !pkg.devDependencies) continue;
    for (const name of Object.keys({ ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) })) {
      targets.push({ name, registry: 'npm', file: rel(f) });
    }
  }

  for (const f of files.filter((x) => basename(x) === 'pubspec.yaml')) {
    const src = read(f);
    const body = src.split(/^dev_dependencies:/m)[0];
    const m = body.split(/^dependencies:/m)[1];
    if (!m) continue;
    for (const line of m.split('\n')) {
      const mm = /^\s{2}([a-z0-9_]+)\s*:/.exec(line);
      if (mm && mm[1] !== 'flutter' && mm[1] !== 'sdk') targets.push({ name: mm[1], registry: 'pub', file: rel(f) });
    }
  }

  if (!targets.length) return { findings: out, checked: 0, skipped: false };

  const seen = new Set();
  let networkFailed = 0;
  let checked = 0;

  const probe = async ({ name, registry, file }) => {
    const key = `${registry}:${name}`;
    if (seen.has(key)) return;
    seen.add(key);
    const url = registry === 'npm'
      ? `https://registry.npmjs.org/${encodeURIComponent(name).replace('%40', '@')}`
      : `https://pub.dev/api/packages/${encodeURIComponent(name)}`;
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 10_000);
      const res = await fetch(url, { signal: ctrl.signal, headers: { accept: 'application/json' } });
      clearTimeout(t);
      checked++;
      if (res.status === 404) {
        out.push(mk('AVS-521', 'M05/R5.1', 'ERROR', file, 0,
          `Dependency "${name}" does not exist in the ${registry} registry`,
          'Do not guess a similar name — near-misses are what attackers pre-register. Remove it, or confirm the correct package with its maintainer.'));
        return;
      }
      if (!res.ok) return;
      const data = await res.json();
      const created = registry === 'npm' ? data?.time?.created : data?.latest?.published;
      if (created) {
        const ageDays = (Date.now() - Date.parse(created)) / 86_400_000;
        if (ageDays < 90) {
          out.push(mk('AVS-522', 'M05/R5.1', 'WARNING', file, 0,
            `Dependency "${name}" is ${Math.floor(ageDays)} days old`,
            'Packages under 90 days old warrant manual provenance review before use.'));
        }
      }
    } catch {
      networkFailed++;
    }
  };

  const queue = [...targets];
  const workers = Array.from({ length: 8 }, async () => {
    while (queue.length) await probe(queue.shift());
  });
  await Promise.all(workers);

  return { findings: out, checked, skipped: networkFailed > 0 && checked === 0, networkFailed };
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

function isCode(f) { return CODE_EXT.has(extname(f)); }
function isConfig(f) { return CONFIG_EXT.has(extname(f)); }

function mk(id, rule, severity, file, line, title, fix, rotate = false) {
  return { id, rule, severity, file, line, title, fix, rotate };
}

let EXCLUDES = [];
function isExcluded(p) {
  if (!EXCLUDES.length) return false;
  const norm = p.split(sep).join('/');
  return EXCLUDES.some((x) => norm.includes(x));
}

function walk(dir, acc = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return acc; }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (isExcluded(full)) continue;
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name) || e.name.startsWith('.') && e.name !== '.github') continue;
      walk(full, acc);
    } else if (e.isFile()) {
      if (SELF_SKIP.has(e.name)) continue;
      const ext = extname(e.name);
      if (!CODE_EXT.has(ext) && !CONFIG_EXT.has(ext) && !/\.(jks|keystore|p12|pfx|p8|mobileprovision)$/i.test(e.name)
          && e.name !== 'key.properties' && e.name !== '.gitignore') continue;
      try { if (statSync(full).size > MAX_FILE_BYTES) continue; } catch { continue; }
      acc.push(full);
    }
  }
  return acc;
}

function lineOf(src, index) {
  let line = 1;
  for (let i = 0; i < index && i < src.length; i++) if (src.charCodeAt(i) === 10) line++;
  return line;
}

function scanFile(file, src, root) {
  const findings = [];
  const rel = relative(root, file).split(sep).join('/');
  for (const rule of RULES) {
    if (!rule.where(file)) continue;
    const re = new RegExp(rule.re.source, rule.re.flags.includes('g') ? rule.re.flags : rule.re.flags + 'g');
    let m, hits = 0;
    while ((m = re.exec(src)) !== null) {
      findings.push(mk(rule.id, rule.rule, rule.severity, rel, lineOf(src, m.index), rule.title, rule.fix, rule.rotate));
      if (++hits >= 20) break;
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

function report(findings, meta, opts) {
  const c = opts.color
    ? { red: (s) => `\x1b[31m${s}\x1b[0m`, yellow: (s) => `\x1b[33m${s}\x1b[0m`,
        green: (s) => `\x1b[32m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m`,
        bold: (s) => `\x1b[1m${s}\x1b[0m` }
    : { red: (s) => s, yellow: (s) => s, green: (s) => s, dim: (s) => s, bold: (s) => s };

  const errors = findings.filter((f) => f.severity === 'ERROR');
  const warnings = findings.filter((f) => f.severity === 'WARNING');

  console.log('');
  console.log(c.bold('  App-Vibe-Security — native application audit'));
  console.log(c.dim(`  ${meta.root}`));
  console.log(c.dim(`  ${meta.fileCount} files scanned${meta.depsChecked ? `, ${meta.depsChecked} dependencies verified` : ''}`));
  if (EXCLUDES.length) console.log(c.dim(`  excluded: ${EXCLUDES.join(', ')}`));
  console.log('');

  const groups = [['ERROR', errors, c.red], ['WARNING', warnings, c.yellow]];
  for (const [label, list, paint] of groups) {
    if (!list.length) continue;
    console.log(paint(`  ${label} (${list.length})`));
    console.log('');
    const byFile = new Map();
    for (const f of list) {
      if (!byFile.has(f.file)) byFile.set(f.file, []);
      byFile.get(f.file).push(f);
    }
    for (const [file, items] of byFile) {
      console.log(`  ${c.bold(file)}`);
      for (const it of items) {
        const loc = it.line ? `:${it.line}` : '';
        console.log(`    ${paint(it.id)} ${c.dim(`[${it.rule}]`)}${loc}  ${it.title}`);
        console.log(`      ${c.dim('fix:')} ${it.fix}`);
        if (it.rotate) console.log(`      ${c.red('ROTATE THIS CREDENTIAL BEFORE CHANGING CODE.')}`);
      }
      console.log('');
    }
  }

  if (!findings.length) {
    console.log(c.green('  No findings from the deterministic checks.'));
    console.log('');
  }

  console.log(c.dim('  ─────────────────────────────────────────────────────────────'));
  console.log(`  ${c.red(`ERROR: ${errors.length}`)}   ${c.yellow(`WARNING: ${warnings.length}`)}`);
  const rotate = findings.filter((f) => f.rotate);
  if (rotate.length) console.log(`  ${c.red(`Credentials requiring rotation: ${rotate.length}`)}`);
  if (meta.depsSkipped) console.log(c.yellow('  Dependency check skipped — no network access.'));
  console.log('');
  if (!opts.quiet) {
    console.log(c.dim('  Static checks are a floor, not a ceiling. Follow with:'));
    console.log(c.dim('    semgrep --config skills/semgrep-rules.yml .'));
    console.log(c.dim('    node scripts/scan-artifacts.mjs <built-artifact>'));
    console.log(c.dim('    the adversarial review in skills/audit-prompt.md'));
    console.log('');
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const argv = process.argv.slice(2);
  const flags = new Set(argv.filter((a) => a.startsWith('--')));

  EXCLUDES = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--exclude' && argv[i + 1]) {
      EXCLUDES.push(...argv[i + 1].split(',').map((x) => x.trim()).filter(Boolean));
    }
  }
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) { if (argv[i] === '--exclude') i++; continue; }
    if (argv[i - 1] === '--exclude') continue;
    positional.push(argv[i]);
  }
  const root = positional[0] || '.';

  if (flags.has('--help') || flags.has('-h')) {
    console.log('usage: node scripts/audit-native.mjs [path] [--check-deps] [--exclude <path>] [--json] [--quiet] [--no-color]');
    process.exit(0);
  }
  if (!existsSync(root)) {
    console.error(`audit-native: path not found: ${root}`);
    process.exit(2);
  }

  const files = walk(root);
  const cache = new Map();
  const read = (f) => {
    if (!cache.has(f)) {
      try { cache.set(f, readFileSync(f, 'utf8')); } catch { cache.set(f, ''); }
    }
    return cache.get(f);
  };

  let findings = [];
  for (const f of files) {
    const src = read(f);
    if (!src) continue;
    findings.push(...scanFile(f, src, root));
  }
  findings.push(...structuralChecks({ files, root, read }));

  let depsChecked = 0;
  let depsSkipped = false;
  if (flags.has('--check-deps')) {
    const r = await checkDependencies({ files, root, read });
    findings.push(...r.findings);
    depsChecked = r.checked;
    depsSkipped = r.skipped;
  }

  const order = { ERROR: 0, WARNING: 1 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);

  if (flags.has('--json')) {
    console.log(JSON.stringify({ root, fileCount: files.length, depsChecked, findings }, null, 2));
  } else {
    report(findings, { root, fileCount: files.length, depsChecked, depsSkipped }, {
      color: !flags.has('--no-color') && process.stdout.isTTY !== false,
      quiet: flags.has('--quiet'),
    });
  }

  process.exit(findings.some((f) => f.severity === 'ERROR') ? 1 : 0);
}

main().catch((e) => { console.error('audit-native: ' + (e?.stack || e)); process.exit(2); });
