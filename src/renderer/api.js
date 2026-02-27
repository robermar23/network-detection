export const api = {
  checkNmap: async () => window.electronAPI.checkNmap(),
  getNmapScripts: async () => window.electronAPI.getNmapScripts(),
  getInterfaces: async () => window.electronAPI.getInterfaces(),
  scanNetwork: async (subnet) => window.electronAPI.scanNetwork(subnet),
  stopScan: async () => window.electronAPI.stopScan(),
  openExternalAction: async (payload) => window.electronAPI.openExternalAction(payload),
  runDeepScan: async (ip) => window.electronAPI.runDeepScan(ip),
  cancelDeepScan: async (ip) => window.electronAPI.cancelDeepScan(ip),
  runNmapScan: async (type, targetObj) => window.electronAPI.runNmapScan(type, targetObj),
  cancelNmapScan: async (target) => window.electronAPI.cancelNmapScan(target),
  runNcat: async (payloadObj) => window.electronAPI.runNcat(payloadObj),
  saveResults: async (results) => window.electronAPI.saveResults(results),
  loadResults: async () => window.electronAPI.loadResults(),
  clearResults: async () => window.electronAPI.clearResults(),
  exitApp: () => window.electronAPI.exitApp(),
  // Target Scope Management
  importScopeFile: async () => window.electronAPI.importScopeFile(),
  importNmapXml: async () => window.electronAPI.importNmapXml(),
  pingHost: async (ip) => window.electronAPI.pingHost(ip),
  probeHost: async (ip) => window.electronAPI.probeHost(ip),
  
  // Settings
  settings: {
    get: async (key) => window.electronAPI.settings.get(key),
    set: async (key, value) => window.electronAPI.settings.set(key, value),
    getAll: async () => window.electronAPI.settings.getAll(),
    checkDependency: async (toolName) => window.electronAPI.settings.checkDependency(toolName)
  },
  
  // Tshark (VLAN Discovery)
  startTsharkCapture: async (interfaceId) => window.electronAPI.startTsharkCapture(interfaceId),
  stopTsharkCapture: async () => window.electronAPI.stopTsharkCapture(),

  // Passive Network Intelligence
  startPassiveCapture: async (moduleId, interfaceId, options) => window.electronAPI.startPassiveCapture(moduleId, interfaceId, options),
  stopPassiveCapture: async (moduleId) => window.electronAPI.stopPassiveCapture(moduleId),
  stopAllPassive: async () => window.electronAPI.stopAllPassive(),
  exportPcap: async (payload) => window.electronAPI.exportPcap(payload),

  // Engine Status
  checkRustEngine: async () => window.electronAPI.checkRustEngine(),
  checkReportsEngine: async () => window.electronAPI.checkReportsEngine(),

  // Scan Profiles (Rust Engine)
  profiles: {
    list: async () => window.electronAPI.profiles.list(),
    get: async (name) => window.electronAPI.profiles.get(name),
    create: async (profile) => window.electronAPI.profiles.create(profile),
    update: async (name, profile) => window.electronAPI.profiles.update(name, profile),
    delete: async (name) => window.electronAPI.profiles.delete(name),
    validate: async (profile) => window.electronAPI.profiles.validate(profile),
  },

  // Baseline & Diff (Rust Engine)
  baseline: {
    snapshot: async (hosts, label) => window.electronAPI.baseline.snapshot(hosts, label),
    list: async () => window.electronAPI.baseline.list(),
    get: async (id) => window.electronAPI.baseline.get(id),
    delete: async (id) => window.electronAPI.baseline.delete(id),
    diff: async (baselineId, currentHosts) => window.electronAPI.baseline.diff(baselineId, currentHosts),
  },

  // Service Fingerprinting (Rust Engine)
  fingerprint: {
    analyze: async (host, ports) => window.electronAPI.fingerprint.analyze(host, ports),
  },

  // Topology Builder (Rust Engine)
  topology: {
    build: async (hosts, fingerprints) => window.electronAPI.topology.build(hosts, fingerprints),
  },

  // Report Export (Go Engine)
  exportReport: async (opts) => window.electronAPI.exportReport(opts)
};
