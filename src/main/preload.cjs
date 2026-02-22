// src/main/preload.js
var import_electron = require("electron");

// src/shared/ipc.js
var IPC_CHANNELS = {
  // Main Handlers (renderer -> main)
  GET_INTERFACES: "get-interfaces",
  SCAN_NETWORK: "scan-network",
  STOP_SCAN: "stop-scan",
  SAVE_RESULTS: "save-results",
  LOAD_RESULTS: "load-results",
  CLEAR_RESULTS: "clear-results",
  EXIT_APP: "exit-app",
  RUN_DEEP_SCAN: "deep-scan-host",
  CANCEL_DEEP_SCAN: "cancel-deep-scan",
  OPEN_EXTERNAL_ACTION: "open-external-action",
  // Renderer Listeners (main -> renderer)
  HOST_FOUND: "host-found",
  SCAN_COMPLETE: "scan-complete",
  SCAN_ERROR: "scan-error",
  DEEP_SCAN_RESULT: "deep-scan-result",
  DEEP_SCAN_PROGRESS: "deep-scan-progress",
  DEEP_SCAN_COMPLETE: "deep-scan-complete"
};

// src/main/preload.js
import_electron.contextBridge.exposeInMainWorld("electronAPI", {
  getInterfaces: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.GET_INTERFACES),
  scanNetwork: (subnet) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SCAN_NETWORK, subnet),
  stopScan: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.STOP_SCAN),
  saveResults: (results) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SAVE_RESULTS, results),
  loadResults: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.LOAD_RESULTS),
  clearResults: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CLEAR_RESULTS),
  exitApp: () => import_electron.ipcRenderer.send(IPC_CHANNELS.EXIT_APP),
  // Deep Scan Triggers
  runDeepScan: (ip) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.RUN_DEEP_SCAN, ip),
  cancelDeepScan: (ip) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CANCEL_DEEP_SCAN, ip),
  openExternalAction: (payload) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.OPEN_EXTERNAL_ACTION, payload),
  // Event Listeners for streams
  onHostFound: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.HOST_FOUND, (_event, value) => callback(value)),
  onScanComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.SCAN_COMPLETE, (_event, value) => callback(value)),
  onScanError: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.SCAN_ERROR, (_event, value) => callback(value)),
  // Deep Scan Event Streams
  onDeepScanResult: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_RESULT, (_event, value) => callback(value)),
  onDeepScanProgress: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_PROGRESS, (_event, value) => callback(value)),
  onDeepScanComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_COMPLETE, (_event, value) => callback(value)),
  // Cleanup listeners
  removeListeners: () => {
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.HOST_FOUND);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SCAN_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SCAN_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_RESULT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_PROGRESS);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_COMPLETE);
  }
});
