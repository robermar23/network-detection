/**
 * Single Source of Truth for all Inter-Process Communication (IPC) channels.
 */

export const IPC_CHANNELS = {
  // Main Handlers (renderer -> main)
  GET_INTERFACES: 'get-interfaces',
  SCAN_NETWORK: 'scan-network',
  STOP_SCAN: 'stop-scan',
  SAVE_RESULTS: 'save-results',
  LOAD_RESULTS: 'load-results',
  CLEAR_RESULTS: 'clear-results',
  EXIT_APP: 'exit-app',
  
  RUN_DEEP_SCAN: 'deep-scan-host',
  CANCEL_DEEP_SCAN: 'cancel-deep-scan',
  OPEN_EXTERNAL_ACTION: 'open-external-action',

  // Renderer Listeners (main -> renderer)
  HOST_FOUND: 'host-found',
  SCAN_COMPLETE: 'scan-complete',
  SCAN_ERROR: 'scan-error',
  
  DEEP_SCAN_RESULT: 'deep-scan-result',
  DEEP_SCAN_PROGRESS: 'deep-scan-progress',
  DEEP_SCAN_COMPLETE: 'deep-scan-complete',

  // Nmap Channels
  CHECK_NMAP: 'check-nmap',
  RUN_NMAP_SCAN: 'run-nmap-scan',
  CANCEL_NMAP_SCAN: 'cancel-nmap-scan',
  RUN_NCAT: 'run-ncat',
  NMAP_SCAN_RESULT: 'nmap-scan-result',
  NMAP_SCAN_COMPLETE: 'nmap-scan-complete',
  NMAP_SCAN_ERROR: 'nmap-scan-error'
};
