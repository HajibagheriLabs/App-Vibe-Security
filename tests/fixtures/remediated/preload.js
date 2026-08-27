// FIXTURE — remediated counterpart. Must produce ZERO findings.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('appApi', {
  openDocsPage: (page) => ipcRenderer.invoke('docs:open', { page }),
  renderReport: (reportId) => ipcRenderer.invoke('report:render', { reportId }),
  onSyncProgress: (cb) => {
    const handler = (_event, percent) => cb(percent);
    ipcRenderer.on('sync:progress', handler);
    return () => ipcRenderer.removeListener('sync:progress', handler);
  },
});
