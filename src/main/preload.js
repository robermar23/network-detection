import { contextBridge, ipcRenderer } from 'electron';
import { IPC_CHANNELS } from '#shared/ipc.js';

contextBridge.exposeInMainWorld('electronAPI', {
  getInterfaces: () => ipcRenderer.invoke(IPC_CHANNELS.GET_INTERFACES),
  scanNetwork: (subnet) => ipcRenderer.invoke(IPC_CHANNELS.SCAN_NETWORK, subnet),
  stopScan: () => ipcRenderer.invoke(IPC_CHANNELS.STOP_SCAN),
  saveResults: (results) => ipcRenderer.invoke(IPC_CHANNELS.SAVE_RESULTS, results),
  loadResults: () => ipcRenderer.invoke(IPC_CHANNELS.LOAD_RESULTS),
  clearResults: () => ipcRenderer.invoke(IPC_CHANNELS.CLEAR_RESULTS),
  exitApp: () => ipcRenderer.send(IPC_CHANNELS.EXIT_APP),

  // Deep Scan Triggers
  runDeepScan: (ip) => ipcRenderer.invoke(IPC_CHANNELS.RUN_DEEP_SCAN, ip),
  cancelDeepScan: (ip) => ipcRenderer.invoke(IPC_CHANNELS.CANCEL_DEEP_SCAN, ip),
  openExternalAction: (payload) => ipcRenderer.invoke(IPC_CHANNELS.OPEN_EXTERNAL_ACTION, payload),

  // Nmap Triggers
  checkNmap: () => ipcRenderer.invoke(IPC_CHANNELS.CHECK_NMAP),
  getNmapScripts: () => ipcRenderer.invoke(IPC_CHANNELS.GET_NMAP_SCRIPTS),
  runNmapScan: (type, targetObj) => ipcRenderer.invoke(IPC_CHANNELS.RUN_NMAP_SCAN, { type, target: targetObj }),
  runNcat: (payloadObj) => ipcRenderer.invoke(IPC_CHANNELS.RUN_NCAT, payloadObj),
  cancelNmapScan: (target) => ipcRenderer.invoke(IPC_CHANNELS.CANCEL_NMAP_SCAN, target),

  // Event Listeners for streams
  onHostFound: (callback) => ipcRenderer.on(IPC_CHANNELS.HOST_FOUND, (_event, value) => callback(value)),
  onScanComplete: (callback) => ipcRenderer.on(IPC_CHANNELS.SCAN_COMPLETE, (_event, value) => callback(value)),
  onScanError: (callback) => ipcRenderer.on(IPC_CHANNELS.SCAN_ERROR, (_event, value) => callback(value)),
  
  // Deep Scan Event Streams
  onDeepScanResult: (callback) => ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_RESULT, (_event, value) => callback(value)),
  onDeepScanProgress: (callback) => ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_PROGRESS, (_event, value) => callback(value)),
  onDeepScanComplete: (callback) => ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_COMPLETE, (_event, value) => callback(value)),

  // Nmap Event Streams
  onNmapScanResult: (callback) => ipcRenderer.on(IPC_CHANNELS.NMAP_SCAN_RESULT, (_event, value) => callback(value)),
  onNmapScanComplete: (callback) => ipcRenderer.on(IPC_CHANNELS.NMAP_SCAN_COMPLETE, (_event, value) => callback(value)),
  onNmapScanError: (callback) => ipcRenderer.on(IPC_CHANNELS.NMAP_SCAN_ERROR, (_event, value) => callback(value)),

  // Cleanup listeners
  removeListeners: () => {
    ipcRenderer.removeAllListeners(IPC_CHANNELS.HOST_FOUND);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SCAN_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.SCAN_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_RESULT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_PROGRESS);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.NMAP_SCAN_RESULT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.NMAP_SCAN_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.NMAP_SCAN_ERROR);
  }
});
