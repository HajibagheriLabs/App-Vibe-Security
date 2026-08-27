// FIXTURE — deliberately vulnerable. Must be flagged by module 02 rules.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  fs: require('fs'),
  ipcRenderer,
  bridge: ipcRenderer,
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
  send: (channel, ...args) => ipcRenderer.send(channel, ...args),
});
