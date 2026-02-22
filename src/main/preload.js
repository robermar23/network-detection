const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  scanNetwork: (args) => ipcRenderer.invoke('scan-network', args),
  stopScan: () => ipcRenderer.invoke('stop-scan'),
  saveResults: (results) => ipcRenderer.invoke('save-results', results),
  loadResults: () => ipcRenderer.invoke('load-results'),
  clearResults: () => ipcRenderer.invoke('clear-results'),
  exitApp: () => ipcRenderer.send('exit-app'),

  // Event Listeners for streams
  onHostFound: (callback) => ipcRenderer.on('host-found', (_event, value) => callback(value)),
  onScanComplete: (callback) => ipcRenderer.on('scan-complete', (_event, value) => callback(value)),
  onScanError: (callback) => ipcRenderer.on('scan-error', (_event, value) => callback(value)),

  // Cleanup listeners
  removeListeners: () => {
    ipcRenderer.removeAllListeners('host-found');
    ipcRenderer.removeAllListeners('scan-complete');
    ipcRenderer.removeAllListeners('scan-error');
  }
});
