const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  getInterfaces: () => ipcRenderer.invoke('get-interfaces'),
  scanNetwork: (subnet) => ipcRenderer.invoke('scan-network', subnet),
  stopScan: () => ipcRenderer.invoke('stop-scan'),
  saveResults: (results) => ipcRenderer.invoke('save-results', results),
  loadResults: () => ipcRenderer.invoke('load-results'),
  clearResults: () => ipcRenderer.invoke('clear-results'),
  exitApp: () => ipcRenderer.send('exit-app'),

  // Deep Scan Triggers
  runDeepScan: (ip) => ipcRenderer.invoke('deep-scan-host', ip),
  cancelDeepScan: (ip) => ipcRenderer.invoke('cancel-deep-scan', ip),
  openExternalAction: (payload) => ipcRenderer.invoke('open-external-action', payload),

  // Event Listeners for streams
  onHostFound: (callback) => ipcRenderer.on('host-found', (_event, value) => callback(value)),
  onScanComplete: (callback) => ipcRenderer.on('scan-complete', (_event, value) => callback(value)),
  onScanError: (callback) => ipcRenderer.on('scan-error', (_event, value) => callback(value)),
  
  // Deep Scan Event Streams
  onDeepScanResult: (callback) => ipcRenderer.on('deep-scan-result', (_event, value) => callback(value)),
  onDeepScanProgress: (callback) => ipcRenderer.on('deep-scan-progress', (_event, value) => callback(value)),
  onDeepScanComplete: (callback) => ipcRenderer.on('deep-scan-complete', (_event, value) => callback(value)),

  // Cleanup listeners
  removeListeners: () => {
    ipcRenderer.removeAllListeners('host-found');
    ipcRenderer.removeAllListeners('scan-complete');
    ipcRenderer.removeAllListeners('scan-error');
    ipcRenderer.removeAllListeners('deep-scan-result');
    ipcRenderer.removeAllListeners('deep-scan-progress');
    ipcRenderer.removeAllListeners('deep-scan-complete');
  }
});
