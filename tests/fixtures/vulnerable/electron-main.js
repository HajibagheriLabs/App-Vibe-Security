// FIXTURE — deliberately vulnerable. Must be flagged by modules 02 and 04 rules.
const { app, BrowserWindow, ipcMain, shell } = require('electron');
const { exec } = require('child_process');

function createWindow() {
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      webSecurity: false,
      sandbox: false,
    },
  });
  win.loadURL('https://app.example.com/');
}

ipcMain.handle('run-command', async (event, cmd) => {
  return new Promise((resolve) => exec(cmd, (e, out) => resolve(out)));
});

app.on('web-contents-created', (_e, contents) => {
  contents.setWindowOpenHandler(({ url }) => ({ action: 'allow' }));
});

app.on('second-instance', (_event, argv) => {
  mainWindow.loadURL(argv[argv.length - 1]);
});

app.commandLine.appendSwitch('remote-debugging-port', '9229');

module.exports = { createWindow };
