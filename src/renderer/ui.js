export const elements = {
  interfaceSelect: document.getElementById('interface-select'),
  btnRefreshInterfaces: document.getElementById('btn-refresh-interfaces'),
  btnScan: document.getElementById('btn-scan'),
  btnStop: document.getElementById('btn-stop'),
  btnSave: document.getElementById('btn-save'),
  btnLoad: document.getElementById('btn-load'),
  btnClear: document.getElementById('btn-clear'),
  btnExit: document.getElementById('btn-exit'),
  statusText: document.getElementById('status-text'),
  hostGrid: document.getElementById('host-grid'),
  emptyState: document.getElementById('empty-state'),
  detailsPanel: document.getElementById('details-panel'),
  btnCloseDetails: document.getElementById('btn-close-details'),
  detailsContent: document.getElementById('details-content'),
  btnViewGrid: document.getElementById('btn-view-grid'),
  btnViewList: document.getElementById('btn-view-list'),
  btnViewTable: document.getElementById('btn-view-table'),
  btnViewTopology: document.getElementById('btn-view-topology'),
  topologyContainer: document.getElementById('topology-container'),
  filterIp: document.getElementById('filter-ip'),
  filterOs: document.getElementById('filter-os'),
  filterVendor: document.getElementById('filter-vendor'),
  sortSelect: document.getElementById('sort-select'),
  btnSortDir: document.getElementById('btn-sort-dir'),
  resultCountText: document.getElementById('result-count-text'),
  btnDeepScanAll: document.getElementById('btn-deep-scan-all'),
  scanAllGroup: document.getElementById('scan-all-group'),
  scanAllLabel: document.getElementById('scan-all-label'),
  btnScanAllMenu: document.getElementById('btn-scan-all-menu'),
  scanAllDropdown: document.getElementById('scan-all-dropdown'),
  nmapInstallBanner: document.getElementById('nmap-install-banner'),
  btnCloseNmapBanner: document.getElementById('btn-close-nmap-banner'),
  sidebarResizer: document.getElementById('sidebar-resizer'),
  // Scope Management
  btnAddHosts: document.getElementById('btn-add-hosts'),
  btnAddHostsCta: document.getElementById('btn-add-hosts-cta'),
  scopeModalOverlay: document.getElementById('scope-modal-overlay'),
  btnCloseScopeModal: document.getElementById('btn-close-scope-modal'),
  btnScopeCancel: document.getElementById('btn-scope-cancel'),
  btnScopeCommit: document.getElementById('btn-scope-commit'),
  scopePendingCount: document.getElementById('scope-pending-count'),
  // Blacklist
  btnBlacklist: document.getElementById('btn-blacklist'),
  blacklistModalOverlay: document.getElementById('blacklist-modal-overlay'),
  btnCloseBlacklistModal: document.getElementById('btn-close-blacklist-modal'),
  blacklistInput: document.getElementById('blacklist-input'),
  btnBlacklistAdd: document.getElementById('btn-blacklist-add'),
  blacklistEntries: document.getElementById('blacklist-entries'),
  blacklistCount: document.getElementById('blacklist-count'),
  btnBlacklistDone: document.getElementById('btn-blacklist-done')
};

export const domUtils = {
  pulseRing: document.querySelector('.pulse-ring'),
  
  applyViewStyle(state) {
    elements.btnViewGrid.classList.toggle('active', state.currentView === 'grid');
    elements.btnViewList.classList.toggle('active', state.currentView === 'list');
    elements.btnViewTable.classList.toggle('active', state.currentView === 'table');
    elements.btnViewTopology.classList.toggle('active', state.currentView === 'topology');
    
    if (state.currentView === 'topology') {
      elements.hostGrid.style.display = 'none';
      if (elements.topologyContainer) elements.topologyContainer.style.display = 'block';
    } else {
      if (elements.topologyContainer) elements.topologyContainer.style.display = 'none';
      elements.hostGrid.style.display = '';
      elements.hostGrid.className = `host-${state.currentView}`;
    }
    
    if (state.currentView === 'table' && state.hosts.length > 0) {
       const hasHeader = elements.hostGrid.querySelector('.host-table-header');
       if (!hasHeader) {
          const header = document.createElement('div');
          header.className = 'host-table-header';
          header.innerHTML = `
            <div>IP Address</div>
            <div>MAC Address</div>
            <div>Hostname</div>
            <div>Operating System</div>
            <div>Vendor</div>
            <div>Security Posture</div>
            <div>Actions</div>
          `;
          elements.hostGrid.insertBefore(header, elements.hostGrid.firstChild);
       }
    } else {
       const existingHeader = elements.hostGrid.querySelector('.host-table-header');
       if (existingHeader) existingHeader.remove();
    }
  },
  
  setScanningState(scanning, state) {
    state.isScanning = scanning;
    elements.btnScan.disabled = scanning;
    elements.btnStop.disabled = !scanning;
    elements.interfaceSelect.disabled = scanning;
    
    if (scanning) {
      elements.statusText.innerText = 'Scanning network...';
      this.pulseRing.classList.add('scanning');
      if (state.hosts.length === 0) {
        elements.emptyState.querySelector('h2').innerText = 'Scanning...';
        elements.emptyState.querySelector('p').innerText = 'Please wait while hosts are discovered.';
      }
    } else {
      elements.statusText.innerText = `Scan stopped. Found ${state.hosts.length} hosts.`;
      this.pulseRing.classList.remove('scanning');
      if (state.hosts.length === 0) {
        elements.emptyState.querySelector('h2').innerText = 'No Hosts Detected';
        elements.emptyState.querySelector('p').innerText = 'Add hosts to begin working';
      }
    }
  }
};
