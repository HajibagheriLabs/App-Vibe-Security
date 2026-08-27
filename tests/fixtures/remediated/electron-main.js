// FIXTURE — remediated counterpart. Must produce ZERO findings.
const { app, BrowserWindow, ipcMain, shell, session } = require('electron');
const { execFile } = require('node:child_process');
const path = require('node:path');

const APP_ORIGIN = 'app://notes';
const DOCS = new Map([['shortcuts', 'https://docs.example.com/shortcuts']]);

app.enableSandbox();

function createWindow() {
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      nodeIntegrationInSubFrames: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      experimentalFeatures: false,
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  win.loadURL(`${APP_ORIGIN}/index.html`);
}

function isTrustedFrame(frame) {
  try { return frame && frame.parent === null && new URL(frame.url).origin === APP_ORIGIN; }
  catch { return false; }
}

ipcMain.handle('docs:open', async (event, payload) => {
  if (!isTrustedFrame(event.senderFrame)) throw new Error('E_FORBIDDEN');
  const target = DOCS.get(payload && payload.page);
  if (!target) throw new Error('E_UNKNOWN_PAGE');
  if (new URL(target).protocol !== 'https:') throw new Error('E_PROTOCOL');
  await shell.openExternal(target);
  return { opened: true };
});

ipcMain.handle('report:render', async (event, payload) => {
  if (!isTrustedFrame(event.senderFrame)) throw new Error('E_FORBIDDEN');
  const id = String(payload && payload.reportId);
  if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error('E_SCHEMA');
  return new Promise((resolve, reject) => {
    execFile('/usr/local/bin/render-report', [id], (err, out) => (err ? reject(err) : resolve(out)));
  });
});

app.on('web-contents-created', (_e, contents) => {
  const internal = (u) => { try { return new URL(u).origin === APP_ORIGIN; } catch { return false; } };
  contents.on('will-navigate', (e, url) => { if (!internal(url)) e.preventDefault(); });
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});

app.whenReady().then(() => {
  session.defaultSession.setPermissionRequestHandler((_wc, _p, cb) => cb(false));
  session.defaultSession.webRequest.onHeadersReceived((details, cb) => {
    cb({ responseHeaders: { ...details.responseHeaders,
      'Content-Security-Policy': ["default-src 'self'; object-src 'none'; base-uri 'none'"] } });
  });
  createWindow();
});
