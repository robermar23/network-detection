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

  // Settings Management
  settings: {
    get: (key) => ipcRenderer.invoke(IPC_CHANNELS.GET_SETTING, key),
    set: (key, value) => ipcRenderer.invoke(IPC_CHANNELS.SET_SETTING, { key, value }),
    getAll: () => ipcRenderer.invoke(IPC_CHANNELS.GET_ALL_SETTINGS),
    checkDependency: (toolName) => ipcRenderer.invoke(IPC_CHANNELS.CHECK_DEPENDENCY, toolName)
  },

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

  // Target Scope Management
  importScopeFile: () => ipcRenderer.invoke(IPC_CHANNELS.IMPORT_SCOPE_FILE),
  importNmapXml: () => ipcRenderer.invoke(IPC_CHANNELS.IMPORT_NMAP_XML),
  pingHost: (ip) => ipcRenderer.invoke(IPC_CHANNELS.PING_HOST, ip),
  probeHost: (ip) => ipcRenderer.invoke(IPC_CHANNELS.PROBE_HOST, ip),
  
  // Tshark (VLAN Discovery)
  startTsharkCapture: (interfaceId) => ipcRenderer.invoke(IPC_CHANNELS.START_TSHARK, interfaceId),
  stopTsharkCapture: () => ipcRenderer.invoke(IPC_CHANNELS.STOP_TSHARK),
  onTsharkVlanFound: (callback) => ipcRenderer.on(IPC_CHANNELS.TSHARK_VLAN_FOUND, (_event, value) => callback(value)),
  onTsharkError: (callback) => ipcRenderer.on(IPC_CHANNELS.TSHARK_ERROR, (_event, value) => callback(value)),
  onTsharkComplete: (callback) => ipcRenderer.on(IPC_CHANNELS.TSHARK_COMPLETE, (_event, value) => callback(value)),

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

  // Passive Network Intelligence
  startPassiveCapture: (moduleId, interfaceId, options) => ipcRenderer.invoke(IPC_CHANNELS.START_PASSIVE_CAPTURE, { moduleId, interfaceId, options }),
  stopPassiveCapture: (moduleId) => ipcRenderer.invoke(IPC_CHANNELS.STOP_PASSIVE_CAPTURE, moduleId),
  stopAllPassive: () => ipcRenderer.invoke(IPC_CHANNELS.STOP_ALL_PASSIVE),
  exportPcap: (payload) => ipcRenderer.invoke(IPC_CHANNELS.EXPORT_PCAP, payload),

  // Passive Event Listeners
  onPassiveDhcpAlert: (callback) => ipcRenderer.on(IPC_CHANNELS.PASSIVE_DHCP_ALERT, (_event, value) => callback(value)),
  onPassiveCredFound: (callback) => ipcRenderer.on(IPC_CHANNELS.PASSIVE_CRED_FOUND, (_event, value) => callback(value)),
  onPassiveDnsHost: (callback) => ipcRenderer.on(IPC_CHANNELS.PASSIVE_DNS_HOST, (_event, value) => callback(value)),
  onPassiveArpAlert: (callback) => ipcRenderer.on(IPC_CHANNELS.PASSIVE_ARP_ALERT, (_event, value) => callback(value)),
  onPcapExportComplete: (callback) => ipcRenderer.on(IPC_CHANNELS.PCAP_EXPORT_COMPLETE, (_event, value) => callback(value)),
  onPassiveStatusUpdate: (callback) => ipcRenderer.on(IPC_CHANNELS.PASSIVE_STATUS_UPDATE, (_event, value) => callback(value)),
  onPassiveError: (callback) => {
    ipcRenderer.on(IPC_CHANNELS.PASSIVE_DHCP_ERROR, (_event, value) => callback(value));
    ipcRenderer.on(IPC_CHANNELS.PASSIVE_CRED_ERROR, (_event, value) => callback(value));
    ipcRenderer.on(IPC_CHANNELS.PASSIVE_DNS_ERROR, (_event, value) => callback(value));
    ipcRenderer.on(IPC_CHANNELS.PASSIVE_ARP_ERROR, (_event, value) => callback(value));
    ipcRenderer.on(IPC_CHANNELS.PCAP_EXPORT_ERROR, (_event, value) => callback(value));
  },
  onPassiveCaptureComplete: (callback) => ipcRenderer.on(IPC_CHANNELS.PASSIVE_CAPTURE_COMPLETE, (_event, value) => callback(value)),

  // Engine Status
  checkRustEngine: () => ipcRenderer.invoke(IPC_CHANNELS.RUST_ENGINE_STATUS),
  checkReportsEngine: () => ipcRenderer.invoke(IPC_CHANNELS.REPORTS_ENGINE_STATUS),

  // Scan Profiles (Rust Engine)
  profiles: {
    list: () => ipcRenderer.invoke(IPC_CHANNELS.PROFILE_LIST),
    get: (name) => ipcRenderer.invoke(IPC_CHANNELS.PROFILE_GET, name),
    create: (profile) => ipcRenderer.invoke(IPC_CHANNELS.PROFILE_CREATE, profile),
    update: (name, profile) => ipcRenderer.invoke(IPC_CHANNELS.PROFILE_UPDATE, { name, profile }),
    delete: (name) => ipcRenderer.invoke(IPC_CHANNELS.PROFILE_DELETE, name),
    validate: (profile) => ipcRenderer.invoke(IPC_CHANNELS.PROFILE_VALIDATE, profile),
  },

  // Baseline & Diff (Rust Engine)
  baseline: {
    snapshot: (hosts, label) => ipcRenderer.invoke(IPC_CHANNELS.BASELINE_SNAPSHOT, { hosts, label }),
    list: () => ipcRenderer.invoke(IPC_CHANNELS.BASELINE_LIST),
    get: (id) => ipcRenderer.invoke(IPC_CHANNELS.BASELINE_GET, id),
    delete: (id) => ipcRenderer.invoke(IPC_CHANNELS.BASELINE_DELETE, id),
    diff: (baselineId, currentHosts) => ipcRenderer.invoke(IPC_CHANNELS.BASELINE_DIFF, { baselineId, currentHosts }),
  },

  // Service Fingerprinting (Rust Engine)
  fingerprint: {
    analyze: (host, ports) => ipcRenderer.invoke(IPC_CHANNELS.FINGERPRINT_ANALYZE, { host, ports }),
  },

  // Topology Builder (Rust Engine)
  topology: {
    build: (hosts, fingerprints) => ipcRenderer.invoke(IPC_CHANNELS.TOPOLOGY_BUILD, { hosts, fingerprints }),
  },

  // Report Export (Go Engine)
  exportReport: (opts) => ipcRenderer.invoke(IPC_CHANNELS.EXPORT_REPORT, opts),

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
    ipcRenderer.removeAllListeners(IPC_CHANNELS.TSHARK_VLAN_FOUND);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.TSHARK_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.TSHARK_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DHCP_ALERT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_CRED_FOUND);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DNS_HOST);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_ARP_ALERT);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DHCP_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_CRED_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DNS_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_ARP_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_EXPORT_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_EXPORT_ERROR);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_CAPTURE_COMPLETE);
    ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_STATUS_UPDATE);
  }
});
