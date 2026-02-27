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
  DEEP_SCAN_COMPLETE: "deep-scan-complete",
  // Nmap Channels
  CHECK_NMAP: "check-nmap",
  RUN_NMAP_SCAN: "run-nmap-scan",
  CANCEL_NMAP_SCAN: "cancel-nmap-scan",
  GET_NMAP_SCRIPTS: "get-nmap-scripts",
  RUN_NCAT: "run-ncat",
  NMAP_SCAN_RESULT: "nmap-scan-result",
  NMAP_SCAN_COMPLETE: "nmap-scan-complete",
  NMAP_SCAN_ERROR: "nmap-scan-error",
  // Target Scope Management
  IMPORT_SCOPE_FILE: "import-scope-file",
  IMPORT_NMAP_XML: "import-nmap-xml",
  PING_HOST: "ping-host",
  PROBE_HOST: "probe-host",
  // Settings Management
  GET_SETTING: "get-setting",
  SET_SETTING: "set-setting",
  GET_ALL_SETTINGS: "get-all-settings",
  CHECK_DEPENDENCY: "check-dependency",
  // Tshark (VLAN Discovery)
  START_TSHARK: "start-tshark",
  STOP_TSHARK: "stop-tshark",
  TSHARK_VLAN_FOUND: "tshark-vlan-found",
  TSHARK_ERROR: "tshark-error",
  TSHARK_COMPLETE: "tshark-complete",
  // Passive Network Intelligence
  START_PASSIVE_CAPTURE: "start-passive-capture",
  STOP_PASSIVE_CAPTURE: "stop-passive-capture",
  STOP_ALL_PASSIVE: "stop-all-passive",
  // Rogue DHCP Detection
  PASSIVE_DHCP_ALERT: "passive-dhcp-alert",
  PASSIVE_DHCP_ERROR: "passive-dhcp-error",
  // Cleartext Credential Sniffing
  PASSIVE_CRED_FOUND: "passive-cred-found",
  PASSIVE_CRED_ERROR: "passive-cred-error",
  // DNS Query Harvesting
  PASSIVE_DNS_HOST: "passive-dns-host",
  PASSIVE_DNS_ERROR: "passive-dns-error",
  // Live PCAP Export
  EXPORT_PCAP: "export-pcap",
  PCAP_EXPORT_COMPLETE: "pcap-export-complete",
  PCAP_EXPORT_ERROR: "pcap-export-error",
  // ARP Spoofing Detection
  PASSIVE_ARP_ALERT: "passive-arp-alert",
  PASSIVE_ARP_ERROR: "passive-arp-error",
  // Shared
  PASSIVE_CAPTURE_COMPLETE: "passive-capture-complete",
  PASSIVE_STATUS_UPDATE: "passive-status-update",
  // Scan Profiles (Rust Engine)
  PROFILE_LIST: "profile-list",
  PROFILE_GET: "profile-get",
  PROFILE_CREATE: "profile-create",
  PROFILE_UPDATE: "profile-update",
  PROFILE_DELETE: "profile-delete",
  PROFILE_VALIDATE: "profile-validate",
  // Baseline & Diff (Rust Engine)
  BASELINE_SNAPSHOT: "baseline-snapshot",
  BASELINE_LIST: "baseline-list",
  BASELINE_GET: "baseline-get",
  BASELINE_DELETE: "baseline-delete",
  BASELINE_DIFF: "baseline-diff",
  // Service Fingerprinting (Rust Engine)
  FINGERPRINT_ANALYZE: "fingerprint-analyze",
  // Topology Builder (Rust Engine)
  TOPOLOGY_BUILD: "topology-build",
  // Engine Status
  RUST_ENGINE_STATUS: "rust-engine-status",
  REPORTS_ENGINE_STATUS: "reports-engine-status",
  // Report Export (Go Engine)
  EXPORT_REPORT: "export-report",
  EXPORT_REPORT_COMPLETE: "export-report-complete"
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
  // Settings Management
  settings: {
    get: (key) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.GET_SETTING, key),
    set: (key, value) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.SET_SETTING, { key, value }),
    getAll: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.GET_ALL_SETTINGS),
    checkDependency: (toolName) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CHECK_DEPENDENCY, toolName)
  },
  // Deep Scan Triggers
  runDeepScan: (ip) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.RUN_DEEP_SCAN, ip),
  cancelDeepScan: (ip) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CANCEL_DEEP_SCAN, ip),
  openExternalAction: (payload) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.OPEN_EXTERNAL_ACTION, payload),
  // Nmap Triggers
  checkNmap: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CHECK_NMAP),
  getNmapScripts: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.GET_NMAP_SCRIPTS),
  runNmapScan: (type, targetObj) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.RUN_NMAP_SCAN, { type, target: targetObj }),
  runNcat: (payloadObj) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.RUN_NCAT, payloadObj),
  cancelNmapScan: (target) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.CANCEL_NMAP_SCAN, target),
  // Target Scope Management
  importScopeFile: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.IMPORT_SCOPE_FILE),
  importNmapXml: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.IMPORT_NMAP_XML),
  pingHost: (ip) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PING_HOST, ip),
  probeHost: (ip) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROBE_HOST, ip),
  // Tshark (VLAN Discovery)
  startTsharkCapture: (interfaceId) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.START_TSHARK, interfaceId),
  stopTsharkCapture: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.STOP_TSHARK),
  onTsharkVlanFound: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.TSHARK_VLAN_FOUND, (_event, value) => callback(value)),
  onTsharkError: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.TSHARK_ERROR, (_event, value) => callback(value)),
  onTsharkComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.TSHARK_COMPLETE, (_event, value) => callback(value)),
  // Event Listeners for streams
  onHostFound: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.HOST_FOUND, (_event, value) => callback(value)),
  onScanComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.SCAN_COMPLETE, (_event, value) => callback(value)),
  onScanError: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.SCAN_ERROR, (_event, value) => callback(value)),
  // Deep Scan Event Streams
  onDeepScanResult: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_RESULT, (_event, value) => callback(value)),
  onDeepScanProgress: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_PROGRESS, (_event, value) => callback(value)),
  onDeepScanComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.DEEP_SCAN_COMPLETE, (_event, value) => callback(value)),
  // Nmap Event Streams
  onNmapScanResult: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.NMAP_SCAN_RESULT, (_event, value) => callback(value)),
  onNmapScanComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.NMAP_SCAN_COMPLETE, (_event, value) => callback(value)),
  onNmapScanError: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.NMAP_SCAN_ERROR, (_event, value) => callback(value)),
  // Passive Network Intelligence
  startPassiveCapture: (moduleId, interfaceId, options) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.START_PASSIVE_CAPTURE, { moduleId, interfaceId, options }),
  stopPassiveCapture: (moduleId) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.STOP_PASSIVE_CAPTURE, moduleId),
  stopAllPassive: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.STOP_ALL_PASSIVE),
  exportPcap: (payload) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.EXPORT_PCAP, payload),
  // Passive Event Listeners
  onPassiveDhcpAlert: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_DHCP_ALERT, (_event, value) => callback(value)),
  onPassiveCredFound: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_CRED_FOUND, (_event, value) => callback(value)),
  onPassiveDnsHost: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_DNS_HOST, (_event, value) => callback(value)),
  onPassiveArpAlert: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_ARP_ALERT, (_event, value) => callback(value)),
  onPcapExportComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PCAP_EXPORT_COMPLETE, (_event, value) => callback(value)),
  onPassiveStatusUpdate: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_STATUS_UPDATE, (_event, value) => callback(value)),
  onPassiveError: (callback) => {
    import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_DHCP_ERROR, (_event, value) => callback(value));
    import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_CRED_ERROR, (_event, value) => callback(value));
    import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_DNS_ERROR, (_event, value) => callback(value));
    import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_ARP_ERROR, (_event, value) => callback(value));
    import_electron.ipcRenderer.on(IPC_CHANNELS.PCAP_EXPORT_ERROR, (_event, value) => callback(value));
  },
  onPassiveCaptureComplete: (callback) => import_electron.ipcRenderer.on(IPC_CHANNELS.PASSIVE_CAPTURE_COMPLETE, (_event, value) => callback(value)),
  // Engine Status
  checkRustEngine: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.RUST_ENGINE_STATUS),
  checkReportsEngine: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.REPORTS_ENGINE_STATUS),
  // Scan Profiles (Rust Engine)
  profiles: {
    list: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROFILE_LIST),
    get: (name) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROFILE_GET, name),
    create: (profile) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROFILE_CREATE, profile),
    update: (name, profile) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROFILE_UPDATE, { name, profile }),
    delete: (name) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROFILE_DELETE, name),
    validate: (profile) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.PROFILE_VALIDATE, profile)
  },
  // Baseline & Diff (Rust Engine)
  baseline: {
    snapshot: (hosts, label) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.BASELINE_SNAPSHOT, { hosts, label }),
    list: () => import_electron.ipcRenderer.invoke(IPC_CHANNELS.BASELINE_LIST),
    get: (id) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.BASELINE_GET, id),
    delete: (id) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.BASELINE_DELETE, id),
    diff: (baselineId, currentHosts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.BASELINE_DIFF, { baselineId, currentHosts })
  },
  // Service Fingerprinting (Rust Engine)
  fingerprint: {
    analyze: (host, ports) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.FINGERPRINT_ANALYZE, { host, ports })
  },
  // Topology Builder (Rust Engine)
  topology: {
    build: (hosts, fingerprints) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.TOPOLOGY_BUILD, { hosts, fingerprints })
  },
  // Report Export (Go Engine)
  exportReport: (opts) => import_electron.ipcRenderer.invoke(IPC_CHANNELS.EXPORT_REPORT, opts),
  // Cleanup listeners
  removeListeners: () => {
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.HOST_FOUND);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SCAN_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.SCAN_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_RESULT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_PROGRESS);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.DEEP_SCAN_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.NMAP_SCAN_RESULT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.NMAP_SCAN_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.NMAP_SCAN_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.TSHARK_VLAN_FOUND);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.TSHARK_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.TSHARK_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DHCP_ALERT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_CRED_FOUND);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DNS_HOST);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_ARP_ALERT);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DHCP_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_CRED_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_DNS_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_ARP_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_EXPORT_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PCAP_EXPORT_ERROR);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_CAPTURE_COMPLETE);
    import_electron.ipcRenderer.removeAllListeners(IPC_CHANNELS.PASSIVE_STATUS_UPDATE);
  }
});
