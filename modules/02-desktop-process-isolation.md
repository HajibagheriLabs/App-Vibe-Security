# Module 02 — Desktop Process Isolation

> **Target vulnerability class:** Electron process-isolation bypass and unsafe IPC bridges
> **Risk profile:** **Critical — CVSS 9.6 to 10.0** for the node-integration bypass class
> **Observed in the wild:** CVE-2026-32626 (AnythingLLM Desktop, CVSS 9.6), CVE-2026-33336 (Vikunja Desktop, CVSS 8.8), CVE-2026-34765 (child-window permission inheritance via `window.open`)
> **CWE mapping:** CWE-1188 (Insecure Default Initialization), CWE-829 (Inclusion of Functionality from an Untrusted Control Sphere), CWE-94 (Code Injection), CWE-668 (Exposure of Resource to Wrong Sphere), CWE-940 (Improper Verification of Source of a Communication Channel)

---

## 1. Root Cause

Electron fuses a Chromium renderer with a Node.js runtime in one application. The security of that
arrangement rests entirely on a boundary: **renderer code is untrusted, main-process code is
trusted, and only a narrow, validated bridge connects them.**

Code generation models dismantle that boundary as a debugging step. The pattern is mechanical and
repeatable:

1. A developer prompts for a feature that needs the OS — "let the user pick a file", "open this in the default browser", "run ffmpeg on this video".
2. The model writes renderer code calling `require('fs')` or `require('child_process')` directly, because that is the shape of the Node.js examples in its training data.
3. The renderer throws `require is not defined`.
4. The developer pastes the error back. The model resolves it the shortest way available: `nodeIntegration: true`, `contextIsolation: false`.
5. The feature works. The application now has no security boundary at all.

The result is that **every** rendering-layer flaw becomes remote code execution on the host. Not
privilege escalation within the app — full RCE as the logged-in user. The escalation path needs
only one untrusted string reaching the DOM:

- A markdown or HTML preview of user-supplied content
- A chat message, issue title, or document title rendered with `innerHTML`
- A retrieval-augmented generation pipeline rendering model output or scraped page text
- A filename, tag, or profile field from a synced remote source
- An iframe, embedded video, or third-party script

This is exactly the mechanism behind CVE-2026-32626 and CVE-2026-33336: in both cases an
ordinary web-layer rendering flaw — the kind that yields a contained XSS in a browser — was
converted into full host compromise by an insecure Electron flag configuration.

The second failure mode survives correct flags. With `contextIsolation: true`, the model still
needs to reach the OS, so it writes a preload script that exposes the capability wholesale:

```js
// The bridge is "secure" and the app is still fully compromised.
contextBridge.exposeInMainWorld('api', {
  exec: (cmd) => require('child_process').exec(cmd),
  readFile: (p) => fs.readFileSync(p, 'utf8'),
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
});
```

Context isolation prevents prototype-pollution attacks across the boundary. It does not stop the
renderer from calling a function that the preload deliberately handed it. `api.exec` is
`child_process.exec` with extra steps. The generic `invoke(channel, ...args)` passthrough is worse:
it re-exposes the entire IPC surface, including every handler added later by any contributor.

---

## 2. Non-Negotiable Rules

### R2.1 — Mandatory `webPreferences` on every window, view, and webview

Applied to every `BrowserWindow`, `BrowserView`, `WebContentsView`, child window, and `<webview>`
tag — with no exceptions for "internal", "trusted", "dev-only", or "splash" windows:

```js
webPreferences: {
  nodeIntegration: false,            // default since Electron 5 — never re-enable
  nodeIntegrationInWorker: false,
  nodeIntegrationInSubFrames: false,
  contextIsolation: true,            // default since Electron 12 — never disable
  sandbox: true,                     // OS-level renderer sandbox
  webSecurity: true,                 // never disable to fix a CORS error
  allowRunningInsecureContent: false,
  experimentalFeatures: false,
  webviewTag: false,                 // enable only with a will-attach-webview handler
  enableBlinkFeatures: '',           // never set
  safeDialogs: true,
  spellcheck: true,
  preload: path.join(__dirname, 'preload.js'),
}
```

Call `app.enableSandbox()` before `app.whenReady()` so the sandbox applies process-wide and cannot
be forgotten on a window added later.

### R2.2 — A security flag is never the fix for a functional bug

`nodeIntegration: true`, `contextIsolation: false`, `webSecurity: false`, and
`allowRunningInsecureContent: true` are **prohibited in all builds, including development**. A dev
build with the boundary removed teaches the codebase habits that ship.

When a feature appears to require one of these flags, the requirement is always one of:

| Symptom | Correct fix |
|---|---|
| `require is not defined` in the renderer | Add a narrow, named IPC channel (R2.3) |
| CORS error loading an API | Make the request from the main process, or fix the server headers |
| `__dirname` / `process` undefined | Pass the value across the bridge as data |
| Third-party library "needs Node" | Run it in the main process or a utility process, expose only its result |

Never set `ELECTRON_DISABLE_SECURITY_WARNINGS`. Those warnings are the only in-band signal that a
window is misconfigured.

### R2.3 — `contextBridge` exposes named operations, never capabilities

The preload script is the entire security surface of the application. It exposes a **fixed,
enumerable list of single-purpose functions**, each with typed parameters.

**Prohibited in a preload script, without exception:**

- Exposing a module: `fs`, `child_process`, `shell`, `path`, `os`, `net`, `require`, `process`, `Buffer`, `electron` itself
- Exposing `ipcRenderer` in any form, including bound methods and wrapped objects
- A generic passthrough: `invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args)`
- Any function that takes a command string, a shell string, an arbitrary file path, a URL, or a SQL fragment
- Any function whose name is a verb without an object (`run`, `exec`, `call`, `send`, `eval`, `open`)
- Returning a Node object, stream, handle, or class instance across the bridge — pass plain serialisable data only

**Required shape:** one function per business operation, with the privileged decision made in the
main process.

```js
// preload.js — the complete, enumerable API surface
contextBridge.exposeInMainWorld('appApi', {
  exportReport: (reportId, format) => ipcRenderer.invoke('report:export', { reportId, format }),
  openDocsPage: (page) => ipcRenderer.invoke('docs:open', { page }),
  onSyncProgress: (cb) => {
    const handler = (_e, pct) => cb(pct);
    ipcRenderer.on('sync:progress', handler);
    return () => ipcRenderer.removeListener('sync:progress', handler);
  },
});
```

The renderer can request a report export. It cannot express "write these bytes to this path".

Event listeners are registered with a wrapper that drops the `IpcRendererEvent` argument — passing
the raw event object into renderer code leaks `event.sender`, which is a live handle back into the
privileged side.

### R2.4 — Every IPC handler validates sender, schema, and resource

A handler in the main process is a privileged endpoint reachable by any compromised renderer.
Treat it exactly as you would a public HTTP route.

```js
ipcMain.handle('report:export', async (event, payload) => {
  // 1. SENDER — reject frames that are not our own application origin
  if (!isTrustedFrame(event.senderFrame)) throw new Error('E_FORBIDDEN');

  // 2. SCHEMA — parse, never trust the shape
  const { reportId, format } = ExportSchema.parse(payload);   // zod/valibot

  // 3. AUTHORIZE — does this session own this resource?
  await assertOwnership(currentSession(), reportId);

  // 4. CONFINE — the main process chooses the path; the renderer never supplies one
  const target = path.join(app.getPath('downloads'), `${safeSlug(reportId)}.${format}`);
  if (!target.startsWith(app.getPath('downloads') + path.sep)) throw new Error('E_PATH');

  // 5. EXECUTE — no shell, argument array only
  return writeReport(target, reportId, format);
});
```

The five steps are ordered and none is optional:

1. **Verify the sender.** Check `event.senderFrame.url` against the expected origin. Reject subframes and any origin you did not load yourself.
2. **Validate the schema.** Explicit parser, exact fields, enumerated values, bounded lengths. Reject on failure; never coerce.
3. **Authorize the operation** against server-verified or main-process-held session state — never against a flag the renderer sent.
4. **Confine the resource.** Canonicalize with `path.resolve`, confirm containment inside an allowed root, reject symlinks and `..` traversal. The main process derives paths; the renderer names *what*, never *where*.
5. **Execute without a shell.** `execFile(bin, [args])` — never `exec`, never `shell: true`, never a concatenated command string. The binary path is a constant, not a parameter.

Use `ipcMain.handle` with `invoke` for request/response. Never use `ipcMain.on` with a
renderer-supplied reply channel, and never `event.sender.send` to a channel name the renderer chose.

### R2.5 — Navigation and window creation are denied by default

An application that only ever renders its own local assets should be unable to navigate anywhere
else. Enforce this in the main process, where the renderer cannot reach it:

```js
app.on('web-contents-created', (_e, contents) => {
  contents.on('will-navigate', (e, url) => {
    if (!isInternalUrl(url)) e.preventDefault();
  });
  contents.on('will-frame-navigate', (e) => {
    if (!isInternalUrl(e.url)) e.preventDefault();
  });
  contents.setWindowOpenHandler(({ url }) => {
    if (isExternalHttpsUrl(url)) { shell.openExternal(url); }
    return { action: 'deny' };                       // never 'allow'
  });
  contents.on('will-attach-webview', (e, prefs) => {
    delete prefs.preload;
    prefs.nodeIntegration = false;
    prefs.contextIsolation = true;
    if (!isInternalUrl(prefs.src)) e.preventDefault();
  });
});
```

`setWindowOpenHandler` returning `{ action: 'deny' }` is the rule that addresses the
CVE-2026-34765 class: a child window created by an untrusted renderer inherits process
permissions from its opener. Denying creation and routing genuine external links through
`shell.openExternal` removes the inheritance path entirely. If a child window is genuinely
required, return `{ action: 'allow', overrideBrowserWindowOptions: { webPreferences: { ...R2.1 } } }`
with the flags restated explicitly — never rely on inheritance.

### R2.6 — `shell.openExternal` is an RCE primitive

`shell.openExternal` hands a string to the operating system shell resolver. On Windows a
`file:` URL to an `.exe`, `.bat`, `.lnk`, `.scr`, `.msi`, or a UNC path (`\\attacker\share\x.exe`)
executes it. `smb:`, `ms-msdt:`, and similar handlers have their own history.

- Parse with the `URL` constructor and reject anything whose protocol is not exactly `https:` (or `mailto:` where required).
- Reject URLs containing credentials (`user:pass@`), and reject non-ASCII hostnames that have not been punycode-normalised.
- Never pass a renderer-supplied string directly. Prefer an allowlist of known destinations keyed by an identifier the renderer sends.

The same discipline applies to `shell.openPath` and to any file dialog result forwarded into a
process launch.

### R2.7 — Content Security Policy set in the main process

The renderer can rewrite a `<meta>` CSP tag once it is compromised. Set the policy on the response
headers, from the main process:

```js
session.defaultSession.webRequest.onHeadersReceived((details, cb) => {
  cb({ responseHeaders: { ...details.responseHeaders,
    'Content-Security-Policy': [
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;" +
      " object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none';" +
      " connect-src 'self' https://api.example.com"
    ] } });
});
```

No `'unsafe-inline'`. No `'unsafe-eval'`. No wildcard `connect-src`. Load application content from
a local `file://` path or a custom registered scheme — **never load a remote origin into a window
that has a preload script attached.** Remote content plus a privileged preload is the same
vulnerability as `nodeIntegration: true`, one indirection removed.

### R2.8 — Deny device and capability permissions by default

```js
session.defaultSession.setPermissionRequestHandler((_wc, permission, cb) => {
  cb(ALLOWED_PERMISSIONS.has(permission));   // usually an empty set
});
session.defaultSession.setPermissionCheckHandler(() => false);
```

Camera, microphone, geolocation, notifications, clipboard-read, USB, HID, Serial, and MIDI are
denied unless the product genuinely requires them. Also register
`setDevicePermissionHandler` for WebUSB/WebHID and `setBluetoothPairingHandler`.

### R2.9 — Runtime and packaging integrity

- Track a **supported Electron major**. Electron inherits Chromium CVEs; an app pinned to an
  end-of-life major ships known, publicly documented RCEs regardless of how correct its own code is.
- Enable ASAR integrity (`EnableEmbeddedAsarIntegrityValidation` plus the fuse that requires it) so a tampered `app.asar` fails to load.
- Flip the Electron fuses: `runAsNode: false`, `enableNodeCliInspectArguments: false`, `enableNodeOptionsEnvironmentVariable: false`, `onlyLoadAppFromAsar: true`. Left enabled, `ELECTRON_RUN_AS_NODE` turns the signed, trusted binary into a general-purpose Node interpreter for any local attacker.
- Never ship with `--inspect`, `--remote-debugging-port`, or DevTools auto-opened in a production build. A debugging port on localhost is a full code-execution channel reachable by any local process and by any web page through DNS rebinding.
- See [Module 05](05-build-integrity-and-updates.md) for signing and update-channel requirements.

### R2.10 — Native code and subprocess discipline

- Never `exec`, `execSync`, `spawn(..., { shell: true })`, `eval`, `new Function`, or `vm.runInThisContext` with any value influenced by the renderer.
- Use `execFile` with an argument array and a constant binary path resolved at build time.
- Bundled helper binaries are pinned by hash and verified before launch.
- Native addons written in C or C++ carry the memory-safety failure modes that generated code is worst at — missing bounds checks, integer overflow in allocation size, use-after-free. Prefer Rust via Node-API, or a memory-safe language boundary, for any native extension that parses untrusted input.

### R2.11 — Same boundary applies to Tauri, Wails, and Neutralino

The framework changes; the rule does not. Expose named commands with typed parameters, keep the
allowlist minimal, disable the shell and filesystem plugins unless scoped to a specific directory,
and set the CSP explicitly. A Tauri `allowlist` granting `fs: { all: true }` or `shell: { execute: true }`
is the same vulnerability as `nodeIntegration: true`.

---

## 3. Reference Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ RENDERER — untrusted. Assume attacker-controlled JavaScript is running here. │
│                                                                              │
│   nodeIntegration:false  contextIsolation:true  sandbox:true  webSecurity:on │
│   CSP: no unsafe-inline / unsafe-eval          navigation: denied by default  │
│                                                                              │
│   window.appApi.exportReport('rep_42', 'pdf')                                │
└──────────────────────────────┬───────────────────────────────────────────────┘
                               │  ISOLATION BOUNDARY
                               │  Only named channels cross. No modules, no
                               │  ipcRenderer, no generic invoke().
┌──────────────────────────────▼───────────────────────────────────────────────┐
│ PRELOAD — contextBridge. Enumerable list of single-purpose functions.        │
│   exportReport(reportId, format) → ipcRenderer.invoke('report:export', {...}) │
└──────────────────────────────┬───────────────────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────────────────┐
│ MAIN — trusted. Every handler is a privileged endpoint.                      │
│   1 verify senderFrame   2 parse schema   3 authorize   4 confine path        │
│   5 execFile(bin, [args])  — no shell, no renderer-supplied path or command   │
└──────────────────────────────┬───────────────────────────────────────────────┘
                               │
                        ┌──────▼───────┐
                        │ OS resources │  fs · network · subprocess · registry
                        └──────────────┘
```

---

## 4. Detection

**Electron-specific static analysis — run this first:**

```bash
npx @doyensec/electronegativity -i . -l 2
```

**This repository ruleset:**

```bash
semgrep --config skills/semgrep-rules.yml .
```

```bash
node scripts/audit-native.mjs .
```

**Grep the packaged application, not the source.** The shipped `app.asar` is what users run:

```bash
npx @electron/asar extract dist/mac/YourApp.app/Contents/Resources/app.asar /tmp/unpacked
```

```bash
grep -rEn "nodeIntegration: *true|contextIsolation: *false|webSecurity: *false|sandbox: *false|allowRunningInsecureContent: *true" /tmp/unpacked
```

**Manual review checklist — every item is a finding if it fails:**

| Check | Pass condition |
|---|---|
| Every `new BrowserWindow` / `BrowserView` / `WebContentsView` | full R2.1 block present, no inherited defaults |
| Every `exposeInMainWorld` | named operations only; no module, no `ipcRenderer`, no generic `invoke` |
| Every `ipcMain.handle` / `ipcMain.on` | sender check + schema parse + authorization + path confinement |
| Every `loadURL` | local asset or fixed allowlisted origin; never a remote origin with a preload attached |
| `setWindowOpenHandler` | present on every `web-contents-created`, returns `deny` by default |
| `will-navigate` | present and default-deny |
| `shell.openExternal` | https-only after `URL` parsing; never a raw renderer string |
| CSP | set via `onHeadersReceived`, no `unsafe-inline`, no `unsafe-eval` |
| Permission handlers | `setPermissionRequestHandler` and `setPermissionCheckHandler` both set |
| Electron version | within the currently supported majors |
| Fuses | `runAsNode`, `enableNodeCliInspectArguments`, `enableNodeOptionsEnvironmentVariable` all disabled |

**Dynamic proof.** Render a string containing an injection payload through every untrusted
display path — chat messages, markdown preview, file names, model output, synced titles. If
`window.require`, `window.process`, or an over-broad bridge function is reachable from that
context, the boundary is already gone.

---

## 5. Agent Constraints

Copy verbatim into the system prompt or rules file of any coding agent:

```text
ELECTRON PROCESS ISOLATION — HARD CONSTRAINTS
1. Every BrowserWindow/BrowserView/WebContentsView/webview:
   nodeIntegration:false, nodeIntegrationInWorker:false, nodeIntegrationInSubFrames:false,
   contextIsolation:true, sandbox:true, webSecurity:true, allowRunningInsecureContent:false,
   webviewTag:false, experimentalFeatures:false. Call app.enableSandbox() at startup.
2. NEVER set nodeIntegration:true, contextIsolation:false, or webSecurity:false — not in dev,
   not temporarily, not to fix an error. Add an IPC channel instead.
3. NEVER expose fs, child_process, shell, path, os, require, process, Buffer, ipcRenderer,
   or a generic invoke(channel, ...args) through contextBridge.
4. contextBridge exposes named single-purpose functions with typed parameters only.
   Pass plain serialisable data. Never return a Node object or handle.
5. Every ipcMain handler, in order: verify event.senderFrame origin -> parse an explicit
   schema -> authorize against main-process session state -> canonicalize and confine any
   path -> execFile(constBin, [args]).
6. NEVER exec/execSync/shell:true/eval/new Function with renderer-influenced input.
7. web-contents-created: will-navigate denies external URLs, setWindowOpenHandler returns
   deny by default, will-attach-webview strips preload and forces safe prefs.
8. shell.openExternal only after URL parsing, https: protocol only, no credentials in URL.
9. Set CSP from the main process via onHeadersReceived. No unsafe-inline, no unsafe-eval.
10. Never load a remote origin into a window that has a preload script.
11. Deny all permission requests by default via setPermissionRequestHandler.
12. Stay on a supported Electron major. Disable runAsNode / node CLI inspect /
    NODE_OPTIONS fuses. Never ship --inspect or --remote-debugging-port.
13. Tauri/Wails: named commands only, minimal allowlist, no fs.all, no shell.execute.
```

---

## 6. Worked Example

Side-by-side vulnerable vs. remediated IPC bridge, with the full validated channel:
**[examples/electron-ipc-remediation.md](../examples/electron-ipc-remediation.md)**

Related: [Module 04 — Deep Link Verification](04-deep-link-verification.md) covers the Windows
`argv` injection path into `app.setAsDefaultProtocolClient`, which reaches the main process
directly and bypasses everything above.
