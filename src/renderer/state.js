export const state = {
  currentView: 'grid', // 'grid', 'list', 'table'
  sortDirection: 'asc', // 'asc', 'desc'
  isScanning: false,
  hosts: [], // Store host objects
  isNmapInstalled: false,
  nmapScripts: [] // Store custom Nmap scripts catalog
};
