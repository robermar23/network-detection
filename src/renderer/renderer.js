// UI Elements
const interfaceSelect = document.getElementById('interface-select');
const btnRefreshInterfaces = document.getElementById('btn-refresh-interfaces');
const btnScan = document.getElementById('btn-scan');
const btnStop = document.getElementById('btn-stop');
const btnSave = document.getElementById('btn-save');
const btnLoad = document.getElementById('btn-load');
const btnClear = document.getElementById('btn-clear');
const btnExit = document.getElementById('btn-exit');

const statusText = document.getElementById('status-text');
const hostGrid = document.getElementById('host-grid');
const emptyState = document.getElementById('empty-state');
const pulseRing = emptyState.querySelector('.pulse-ring');

const detailsPanel = document.getElementById('details-panel');
const btnCloseDetails = document.getElementById('btn-close-details');
const detailsContent = document.getElementById('details-content');

// View Toggles
const btnViewGrid = document.getElementById('btn-view-grid');
const btnViewList = document.getElementById('btn-view-list');
const btnViewTable = document.getElementById('btn-view-table');

const filterIp = document.getElementById('filter-ip');
const filterOs = document.getElementById('filter-os');
const filterVendor = document.getElementById('filter-vendor');
const sortSelect = document.getElementById('sort-select');
const btnSortDir = document.getElementById('btn-sort-dir');
const resultCountText = document.getElementById('result-count-text');
const btnDeepScanAll = document.getElementById('btn-deep-scan-all');

let currentView = 'grid'; // 'grid', 'list', 'table'
let sortDirection = 'asc'; // 'asc', 'desc'

// State
let isScanning = false;
let hosts = []; // Store host objects

// --- UI State Management ---

function applyViewStyle() {
  // Update toggle button active states
  btnViewGrid.classList.toggle('active', currentView === 'grid');
  btnViewList.classList.toggle('active', currentView === 'list');
  btnViewTable.classList.toggle('active', currentView === 'table');

  // Update main container class
  hostGrid.className = `host-${currentView}`;
  
  // Conditionally add table headers if switching to table view
  if (currentView === 'table' && hosts.length > 0) {
     const hasHeader = hostGrid.querySelector('.host-table-header');
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
        hostGrid.insertBefore(header, hostGrid.firstChild);
     }
  } else {
     // Remove table header for grid/list
     const existingHeader = hostGrid.querySelector('.host-table-header');
     if (existingHeader) existingHeader.remove();
  }
}

btnViewGrid.addEventListener('click', () => { currentView = 'grid'; applyViewStyle(); });
btnViewList.addEventListener('click', () => { currentView = 'list'; applyViewStyle(); });
btnViewTable.addEventListener('click', () => { currentView = 'table'; applyViewStyle(); });

async function initInterfaces() {
  if (!window.electronAPI) return;
  
  try {
    const interfaces = await window.electronAPI.getInterfaces();
    interfaceSelect.innerHTML = ''; // Clear loading text
    
    if (interfaces.length === 0) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = 'No interfaces found';
      interfaceSelect.appendChild(opt);
      return;
    }

    interfaces.forEach(iface => {
      const opt = document.createElement('option');
      opt.value = iface.subnet;
      opt.textContent = iface.label;
      interfaceSelect.appendChild(opt);
    });

    interfaceSelect.disabled = false;
    btnScan.disabled = false; // Enable scan once interfaces load
  } catch (e) {
    console.error('Failed to load interfaces:', e);
    interfaceSelect.innerHTML = '<option value="">Error loading</option>';
  }
}

// Call init on load
initInterfaces();

btnRefreshInterfaces.addEventListener('click', () => {
  interfaceSelect.innerHTML = '<option value="">Refreshing...</option>';
  interfaceSelect.disabled = true;
  btnScan.disabled = true;
  initInterfaces();
});

function getActionButtonsHtml(ip, data) {
  let actionsHtml = '';
  if (data.port === 80 || data.port === 8080) {
    actionsHtml = `<button class="btn-action" onclick="window.electronAPI.openExternalAction({type:'http', ip:'${ip}', port:${data.port}})"><span class="icon">🌐</span> Open HTTP</button>`;
  } else if (data.port === 443 || data.port === 8443) {
    actionsHtml = `<button class="btn-action" onclick="window.electronAPI.openExternalAction({type:'https', ip:'${ip}', port:${data.port}})"><span class="icon">🔒</span> Open HTTPS</button>`;
  } else if (data.port === 22) {
    const inputId = `ssh-user-${ip.replace(/\./g, '-')}-${data.port}`;
    actionsHtml = `
      <div style="display:flex; gap: 4px; align-items: center;">
        <input type="text" id="${inputId}" class="text-input" style="width: 70px; padding: 4px 6px; font-size: 11px;" placeholder="root" value="root" title="SSH Username">
        <button class="btn-action" onclick="window.electronAPI.openExternalAction({type:'ssh', ip:'${ip}', username: document.getElementById('${inputId}').value || 'root'})"><span class="icon">⌨️</span> Connect SSH</button>
      </div>`;
  } else if (data.port === 3389) {
    actionsHtml = `<button class="btn-action" onclick="window.electronAPI.openExternalAction({type:'rdp', ip:'${ip}'})"><span class="icon">🖥️</span> Remote Desktop</button>`;
  }
  return actionsHtml ? `<div class="ds-actions">${actionsHtml}</div>` : '';
}

// --- Details Panel ---
function openDetailsPanel(host) {
  // Build previously saved Deep Scan results (if any)
  let savedDeepScanHtml = '';
  if (host.deepAudit && host.deepAudit.history && host.deepAudit.history.length > 0) {
     host.deepAudit.history.forEach(data => {
        let bannerHtml = '';
        if (data.rawBanner) {
           const safeBanner = data.rawBanner.replace(/</g, "&lt;").replace(/>/g, "&gt;");
           bannerHtml = `<div class="ds-banner">${safeBanner}</div>`;
        }

        let actionTag = '';
        if (data.vulnerable) {
           const cl = data.severity === 'critical' ? 'danger' : 'warning';
           actionTag = `<span style="font-size: 10px; color: var(--${cl}); border: 1px solid var(--${cl}); padding: 2px 4px; border-radius: 2px;">${data.severity.toUpperCase()}</span>`;
        }
        
        savedDeepScanHtml += `
          <div class="ds-record" style="${data.vulnerable ? 'border-left-color: var(--danger); background: rgba(235,94,94,0.05);' : ''}">
            <div class="ds-header">
              <div class="ds-header-title">
                <span class="ds-port">PORT ${data.port}</span>
                <span class="ds-service">${data.serviceName}</span>
                ${actionTag}
              </div>
              ${getActionButtonsHtml(host.ip, data)}
            </div>
            <div class="ds-details" style="${data.vulnerable ? 'color: var(--danger); font-weight: 500;' : ''}">${data.details}</div>
            ${bannerHtml}
          </div>
        `;
     });
  }

  detailsContent.innerHTML = `
    <div class="info-row">
      <span class="label">IP Address</span>
      <div class="value">${host.ip}</div>
    </div>
    <div class="info-row">
      <span class="label">MAC Address</span>
      <div class="value" style="font-family: monospace;">${host.mac || 'Unknown'}</div>
    </div>
    <div class="info-row">
      <span class="label">Hostname</span>
      <div class="value">${host.hostname || 'Unknown'}</div>
    </div>
    <div class="info-row">
      <span class="label">Operating System</span>
      <div class="value">${host.os || 'Unknown'}</div>
    </div>
    <div class="info-row">
      <span class="label">Hardware Vendor</span>
      <div class="value">${host.vendor || 'Unknown'}</div>
    </div>
    
    <div style="margin-top: 10px; border-top: 1px solid var(--border-glass); padding-top: 16px;">
      <span class="label" style="display:block; margin-bottom: 12px; font-weight: 500; font-size: 14px; color: white;">Open Ports</span>
      <div>
        ${(host.ports && host.ports.length > 0) 
          ? host.ports.map(p => `<span class="port-item">${p}</span>`).join('') 
          : '<span class="value">No common open ports detected.</span>'}
      </div>
    </div>
    
    <div class="deep-scan-container">
      <button id="btn-run-deep-scan" class="btn warning full-width" data-ip="${host.ip}">
        <span class="icon">☢️</span> ${host.deepAudit ? 'Re-Run Deep Scan' : 'Run Deep Scan'}
      </button>
      <div id="deep-scan-results" class="deep-scan-results">
        ${savedDeepScanHtml}
      </div>
    </div>
  `;
  detailsPanel.classList.add('open');

  // Attach Deep Scan listener
  const btnRunDeepScan = document.getElementById('btn-run-deep-scan');
  const dsResults = document.getElementById('deep-scan-results');

  btnRunDeepScan.addEventListener('click', async () => {
    // If it's already scanning and the user clicks it again, trigger cancel state
    if (btnRunDeepScan.getAttribute('data-scanning') === 'true') {
      window.electronAPI.cancelDeepScan(host.ip);
      btnRunDeepScan.innerHTML = `<span class="icon">🛑</span> Cancelling...`;
      btnRunDeepScan.setAttribute('data-scanning', 'cancelling');
      return;
    }

    btnRunDeepScan.setAttribute('data-scanning', 'true');
    btnRunDeepScan.classList.add('pulsing', 'danger-pulsing'); // Use danger pulsing for explicit cancel visibility
    btnRunDeepScan.classList.remove('warning');
    btnRunDeepScan.innerHTML = `<span class="icon">🛑</span> Cancel Scan...`;
    dsResults.innerHTML = ''; // clear previous
    
    // Reset Data State
    const hostIdx = hosts.findIndex(h => h.ip === host.ip);
    if (hostIdx >= 0) {
      hosts[hostIdx].deepAudit = { history: [], vulnerabilities: 0, warnings: 0 };
    }
    
    await window.electronAPI.runDeepScan(host.ip);
  });
}

btnCloseDetails.addEventListener('click', () => {
  detailsPanel.classList.remove('open');
});

function setScanningState(scanning) {
  isScanning = scanning;
  btnScan.disabled = scanning;
  btnStop.disabled = !scanning;
  interfaceSelect.disabled = scanning;
  
  if (scanning) {
    statusText.innerText = 'Scanning network...';
    pulseRing.classList.add('scanning');
    if (hosts.length === 0) {
      emptyState.querySelector('h2').innerText = 'Scanning...';
      emptyState.querySelector('p').innerText = 'Please wait while hosts are discovered.';
    }
  } else {
    statusText.innerText = `Scan stopped. Found ${hosts.length} hosts.`;
    pulseRing.classList.remove('scanning');
    if (hosts.length === 0) {
      emptyState.querySelector('h2').innerText = 'No Hosts Detected';
      emptyState.querySelector('p').innerText = 'Click "Scan Network" to begin discovering devices';
    }
  }
}

// --- Dynamic Rendering ---

function getSecurityBadgeHtml(host) {
  let posture = 'Unknown';
  let badgeClass = 'secondary';
  let icon = '❔';

  if (host.deepAudit) {
    if (host.deepAudit.vulnerabilities > 0) {
      posture = 'Vulnerable';
      badgeClass = 'danger';
      icon = '🛑';
    } else if (host.deepAudit.warnings > 0) {
      posture = 'Warning';
      badgeClass = 'warning';
      icon = '⚠️';
    } else {
      posture = 'Audited Secure';
      badgeClass = 'success';
      icon = '🛡️';
    }
  } else if (host.ports && host.ports.length > 0) {
    const p = new Set(host.ports);
    if (p.has(21) || p.has(23) || p.has(3306) || p.has(1433) || p.has(27017)) {
       posture = 'Risky Ports';
       badgeClass = 'danger';
       icon = '🛑';
    } else if (p.has(80) || p.has(445) || p.has(135)) {
       posture = 'Exposed Services';
       badgeClass = 'warning';
       icon = '⚠️';
    } else {
       posture = 'Unscanned';
       badgeClass = 'secondary';
       icon = '❔';
    }
  } else {
    posture = 'Unscanned';
    badgeClass = 'secondary';
    icon = '❔';
  }

  return `<span style="font-size: 11px; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--${badgeClass}); color: var(--${badgeClass}); background: rgba(0,0,0,0.2);">${icon} ${posture}</span>`;
}

function getFilteredAndSortedHosts() {
  const ipTerm = filterIp.value.toLowerCase();
  const osTerm = filterOs.value.toLowerCase();
  const vendorTerm = filterVendor.value.toLowerCase();
  
  let filteredHosts = hosts.filter((h) => {
    const matchIp = h.ip ? h.ip.toLowerCase().includes(ipTerm) : false;
    const matchOs = h.os ? String(h.os).toLowerCase().includes(osTerm) : false;
    const matchVendor = h.vendor ? String(h.vendor).toLowerCase().includes(vendorTerm) : false;
    return (ipTerm === '' || matchIp) && (osTerm === '' || matchOs) && (vendorTerm === '' || matchVendor);
  });

  const sortBy = sortSelect.value;
  filteredHosts.sort((a, b) => {
    let valA = a[sortBy] || '';
    let valB = b[sortBy] || '';
    
    if (sortBy === 'ip') {
       try {
         const numA = Number(valA.split('.').map(n => (`000${n}`).slice(-3)).join(''));
         const numB = Number(valB.split('.').map(n => (`000${n}`).slice(-3)).join(''));
         valA = numA; valB = numB;
       } catch (e) {}
    } else {
       valA = String(valA).toLowerCase();
       valB = String(valB).toLowerCase();
    }
    
    if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
    if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
    return 0;
  });
  
  return filteredHosts;
}

function renderAllHosts() {
  const filteredHosts = getFilteredAndSortedHosts();

  resultCountText.innerText = `Showing ${filteredHosts.length} of ${hosts.length} hosts`;
  
  if (filteredHosts.length > 0) {
    btnDeepScanAll.style.display = 'inline-flex';
    emptyState.classList.add('hidden');
  } else {
    btnDeepScanAll.style.display = 'none';
    if (hosts.length === 0) {
      emptyState.classList.remove('hidden');
    } else {
      emptyState.classList.add('hidden');
    }
  }

  if (typeof applyViewStyle === 'function') {
     applyViewStyle();
  }

  const allCards = Array.from(hostGrid.querySelectorAll('.host-card'));
  allCards.forEach(c => c.style.display = 'none');
  
  filteredHosts.forEach(host => {
     let card = document.getElementById(`host-${host.ip.replace(/\./g, '-')}`);
     if (!card) {
       card = createHostCardDOM(host);
     } else {
       card.style.display = '';
     }
     hostGrid.appendChild(card);
  });
}

filterIp.addEventListener('input', renderAllHosts);
filterOs.addEventListener('input', renderAllHosts);
filterVendor.addEventListener('input', renderAllHosts);
sortSelect.addEventListener('change', renderAllHosts);

btnSortDir.addEventListener('click', () => {
  sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
  btnSortDir.innerText = sortDirection === 'asc' ? '⬇️' : '⬆️';
  btnSortDir.dataset.dir = sortDirection;
  renderAllHosts();
});

let renderTimeout;
function debouncedRenderAllHosts() {
  clearTimeout(renderTimeout);
  renderTimeout = setTimeout(() => {
    renderAllHosts();
  }, 100);
}

// --- Deep Scan All Logic ---
let isDeepScanningAll = false;
let deepScanAllQueue = [];
let deepScanAllActive = new Set();
let deepScanAllTotal = 0;
let deepScanAllCompleted = 0;
let deepScanHostProgress = {}; // Store percentage per IP
const MAX_CONCURRENT_DEEP_SCANS = 3;

function updateDeepScanAllProgress() {
  if (!isDeepScanningAll) return;
  
  let activePercentageSum = 0;
  let activeCount = 0;
  
  for (const ip of deepScanAllActive) {
    if (deepScanHostProgress[ip] !== undefined) {
      activePercentageSum += deepScanHostProgress[ip];
      activeCount++;
    }
  }
  
  // Calculate total progress correctly instead of just active batch average
  // Total progress = (completed * 100 + activeSum) / (total * 100)
  let totalPercentageVal = 0;
  if (deepScanAllTotal > 0) {
    const totalMaxProgress = deepScanAllTotal * 100;
    const currentProgressTotal = (deepScanAllCompleted * 100) + activePercentageSum;
    totalPercentageVal = Math.round((currentProgressTotal / totalMaxProgress) * 100);
  }
  
  if (isDeepScanningAll) {
    statusText.innerText = `Deep scanning: ${deepScanAllCompleted}/${deepScanAllTotal} hosts completed - ${totalPercentageVal}%`;
  }
}

function pumpDeepScanQueue() {
  if (!isDeepScanningAll) return;
  
  while (deepScanAllActive.size < MAX_CONCURRENT_DEEP_SCANS && deepScanAllQueue.length > 0) {
    const ip = deepScanAllQueue.shift();
    deepScanAllActive.add(ip);
    
    // Reset Data State
    const hostIdx = hosts.findIndex(h => h.ip === ip);
    if (hostIdx >= 0) {
      hosts[hostIdx].deepAudit = { history: [], vulnerabilities: 0, warnings: 0 };
    }
    
    // Visual update for Details Panel
    const btnRunDeepScan = document.getElementById('btn-run-deep-scan');
    if (btnRunDeepScan && btnRunDeepScan.getAttribute('data-ip') === ip) {
       btnRunDeepScan.setAttribute('data-scanning', 'true');
       btnRunDeepScan.classList.add('pulsing', 'danger-pulsing');
       btnRunDeepScan.classList.remove('warning');
       btnRunDeepScan.innerHTML = `<span class="icon">🛑</span> Cancel Scan...`;
       const dsResults = document.getElementById('deep-scan-results');
       if (dsResults) dsResults.innerHTML = '';
    }

    window.electronAPI.runDeepScan(ip);
  }
  
  if (deepScanAllQueue.length === 0 && deepScanAllActive.size === 0) {
    isDeepScanningAll = false;
    btnDeepScanAll.innerHTML = `<span class="icon">⚡</span> Deep Scan All`;
    btnDeepScanAll.classList.remove('danger');
    btnDeepScanAll.classList.add('info');
    statusText.innerText = `Deep scan all finished (${deepScanAllTotal} hosts).`;
  } else {
    updateDeepScanAllProgress();
  }
}

btnDeepScanAll.addEventListener('click', () => {
  if (isDeepScanningAll) {
    isDeepScanningAll = false;
    for (const ip of deepScanAllActive) {
      window.electronAPI.cancelDeepScan(ip);
    }
    deepScanAllActive.clear();
    deepScanAllQueue = [];
    
    btnDeepScanAll.innerHTML = `<span class="icon">⚡</span> Deep Scan All`;
    btnDeepScanAll.classList.remove('danger');
    btnDeepScanAll.classList.add('info');
    statusText.innerText = 'Deep scan all cancelled.';
    return;
  }

  const filteredHosts = getFilteredAndSortedHosts();
  if (filteredHosts.length === 0) return;

  isDeepScanningAll = true;
  deepScanAllQueue = filteredHosts.map(h => h.ip);
  deepScanAllTotal = deepScanAllQueue.length;
  deepScanAllCompleted = 0;
  deepScanAllActive.clear();
  deepScanHostProgress = {};
  
  btnDeepScanAll.innerHTML = `<span class="icon">🛑</span> Cancel Deep Scan All`;
  btnDeepScanAll.classList.remove('info');
  btnDeepScanAll.classList.add('danger');
  
  pumpDeepScanQueue();
});

function createHostCardDOM(host) {
  const card = document.createElement('div');
  card.className = 'host-card glass-panel';
  card.id = `host-${host.ip.replace(/\./g, '-')}`;

  card.innerHTML = `
    <div class="status-indicator online"></div>
    <div class="host-header">
      <h3>${host.ip}</h3>
      <p class="mac">${host.mac || 'Unknown MAC'}</p>
    </div>
    <div class="host-body">
      <div class="info-row"><span class="label">Hostname:</span> <span class="value" title="${host.hostname}">${host.hostname || 'Unknown'}</span></div>
      <div class="info-row"><span class="label">OS:</span> <span class="value">${host.os || 'Unknown'}</span></div>
      <div class="info-row"><span class="label">Vendor:</span> <span class="value" title="${host.vendor}">${host.vendor || 'Unknown'}</span></div>
      <div class="security-badge-container">
         ${getSecurityBadgeHtml(host)}
         ${(isDeepScanningAll && deepScanAllActive.has(host.ip) && deepScanHostProgress[host.ip]) ? `<span class="ds-progress-badge" style="font-size: 11px; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--info); color: var(--text-main); background: rgba(94, 114, 235, 0.2); margin-left: 6px;">⏳ ${deepScanHostProgress[host.ip]}%</span>` : ''}
      </div>
    </div>
    <div class="host-footer" style="padding-top: 8px;">
      <button class="btn info full-width btn-view">View Details</button>
    </div>
  `;

  const btnView = card.querySelector('.btn-view');
  if (btnView) {
    btnView.addEventListener('click', () => openDetailsPanel(host));
  }
  
  return card;
}

function clearGrid() {
  hosts = [];
  hostGrid.innerHTML = '';
  // Re-initialize headers if currently in table view
  if (typeof applyViewStyle === 'function') {
     applyViewStyle();
  }
  
  emptyState.classList.remove('hidden');
  detailsPanel.classList.remove('open');
  statusText.innerText = 'Ready to scan.';
  setScanningState(false);
}

// --- IPC Communication ---

// 1. Control Actions
btnScan.addEventListener('click', async () => {
  const subnet = interfaceSelect.value;
  if (!subnet) {
    alert('Please select a valid network interface first.');
    return;
  }
  
  setScanningState(true);
  const response = await window.electronAPI.scanNetwork(subnet);
  console.log('Main response:', response);
});

btnStop.addEventListener('click', async () => {
  setScanningState(false);
  const response = await window.electronAPI.stopScan();
  console.log('Main response:', response);
});

btnSave.addEventListener('click', async () => {
  const response = await window.electronAPI.saveResults(hosts);
  if (response.status === 'saved') {
    statusText.innerText = `Results saved to ${response.path}`;
  }
});

btnLoad.addEventListener('click', async () => {
  const response = await window.electronAPI.loadResults();
  if (response.status === 'loaded' && response.data) {
    clearGrid();
    hosts = response.data;
    
    renderAllHosts();
    statusText.innerText = `Loaded ${hosts.length} hosts from ${response.path}`;
  }
});

btnClear.addEventListener('click', async () => {
  clearGrid();
  await window.electronAPI.clearResults();
});

btnExit.addEventListener('click', () => {
  window.electronAPI.exitApp();
});

// 2. Incoming Event Streams
if (window.electronAPI) {
  window.electronAPI.onHostFound((hostData) => {
    const existingIdx = hosts.findIndex(h => h.ip === hostData.ip);
    
    if (existingIdx >= 0) {
      hosts[existingIdx] = { ...hosts[existingIdx], ...hostData };
      const card = document.getElementById(`host-${hostData.ip.replace(/\./g, '-')}`);
      if (card) {
         card.querySelector('.host-body .info-row:nth-child(1) .value').innerText = hostData.hostname || 'Unknown';
         card.querySelector('.host-body .info-row:nth-child(2) .value').innerText = hostData.os || 'Unknown';
         card.querySelector('.host-body .info-row:nth-child(3) .value').innerText = hostData.vendor || 'Unknown';
      }
      debouncedRenderAllHosts();
    } else {
      hosts.push(hostData);
      debouncedRenderAllHosts();
    }
  });

  window.electronAPI.onScanComplete(({ message }) => {
    setScanningState(false);
    statusText.innerText = message || `Scan complete. Found ${hosts.length} hosts.`;
  });

  window.electronAPI.onScanError(({ error }) => {
    setScanningState(false);
    statusText.innerText = `Scan error: ${error}`;
    console.error('Scan Error:', error);
  });

  // Deep Scan Receivers
  window.electronAPI.onDeepScanProgress && window.electronAPI.onDeepScanProgress((data) => {
    const btnRunDeepScan = document.getElementById('btn-run-deep-scan');
    if (btnRunDeepScan && btnRunDeepScan.getAttribute('data-ip') === data.ip && btnRunDeepScan.getAttribute('data-scanning') === 'true') {
      btnRunDeepScan.innerHTML = `<span class="icon">🛑</span> Cancel Scan (${data.percent}%)`;
    }
    
    // Update global progress if part of Deep Scan All
    if (isDeepScanningAll && deepScanAllActive.has(data.ip)) {
      deepScanHostProgress[data.ip] = data.percent;
      updateDeepScanAllProgress();
    }

    // Update individual host card
    const card = document.getElementById(`host-${data.ip.replace(/\./g, '-')}`);
    if (card) {
      // Find the specific badge container for THIS card
      const badgeContainer = card.querySelector('.security-badge-container');
      if (badgeContainer) {
        let progressBadge = badgeContainer.querySelector('.ds-progress-badge');
        if (!progressBadge) {
          progressBadge = document.createElement('span');
          progressBadge.className = 'ds-progress-badge';
          progressBadge.style.cssText = 'font-size: 11px; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--info); color: var(--text-main); background: rgba(94, 114, 235, 0.2); margin-left: 6px;';
          badgeContainer.appendChild(progressBadge);
        }
        progressBadge.innerHTML = `⏳ ${data.percent}%`;
      }
    }
  });

  window.electronAPI.onDeepScanResult((data) => {
    // 1. Permanently Save to Host State (For JSON Export & Live Score Retallying)
    const hostIdx = hosts.findIndex(h => h.ip === data.ip);
    if (hostIdx >= 0) {
       // Initialize structure if first port
       if (!hosts[hostIdx].deepAudit) {
         hosts[hostIdx].deepAudit = { history: [], vulnerabilities: 0, warnings: 0 };
       }
       
       // Deduplicate
       if (!hosts[hostIdx].deepAudit.history.some(h => h.port === data.port)) {
         hosts[hostIdx].deepAudit.history.push(data);
         if (data.vulnerable && data.severity === 'critical') hosts[hostIdx].deepAudit.vulnerabilities++;
         if (data.vulnerable && data.severity === 'warning') hosts[hostIdx].deepAudit.warnings++;
         
         // Dynamically re-render the card Security Badge safely
         const card = document.getElementById(`host-${data.ip.replace(/\\./g, '-')}`);
         if (card) {
            const badgeContainer = card.querySelector('.security-badge-container');
            if (badgeContainer) badgeContainer.innerHTML = getSecurityBadgeHtml(hosts[hostIdx]);
         }
       }
    }

    // 2. Stream to Live Feed UI if panel is open
    const dsResults = document.getElementById('deep-scan-results');
    if (!dsResults) return; // Panel closed

    const record = document.createElement('div');
    record.className = 'ds-record';
    if (data.vulnerable) {
      record.style.borderLeftColor = 'var(--danger)';
      record.style.background = 'rgba(235,94,94,0.05)';
    }
    
    let bannerHtml = '';
    if (data.rawBanner) {
       // Escape basic HTML
       const safeBanner = data.rawBanner.replace(/</g, "&lt;").replace(/>/g, "&gt;");
       bannerHtml = `<div class="ds-banner">${safeBanner}</div>`;
    }

    let actionTag = '';
    if (data.vulnerable) {
       const cl = data.severity === 'critical' ? 'danger' : 'warning';
       actionTag = `<span style="font-size: 10px; color: var(--${cl}); border: 1px solid var(--${cl}); margin-left: 8px; padding: 2px 4px; border-radius: 2px;">${data.severity.toUpperCase()}</span>`;
    }

    // Determine Action Buttons
    let actionsHtml = '';
    const ip = document.getElementById('btn-run-deep-scan')?.getAttribute('data-ip');
    
    if (ip) {
      actionsHtml = getActionButtonsHtml(ip, data);
    }

    record.innerHTML = `
      <div class="ds-header">
        <div class="ds-header-title">
          <span class="ds-port">PORT ${data.port}</span>
          <span class="ds-service">${data.serviceName}</span>
          ${actionTag}
        </div>
        ${actionsHtml}
      </div>
      <div class="ds-details" style="${data.vulnerable ? 'color: var(--danger); font-weight: 500;' : ''}">${data.details}</div>
      ${bannerHtml}
    `;
    
    dsResults.appendChild(record);
  });

  window.electronAPI.onDeepScanComplete(({ ip }) => {
    const btnRunDeepScan = document.getElementById('btn-run-deep-scan');
    if (btnRunDeepScan && btnRunDeepScan.getAttribute('data-ip') === ip) {
      const wasCancelled = btnRunDeepScan.getAttribute('data-scanning') === 'cancelling';
      
      btnRunDeepScan.classList.remove('pulsing', 'danger-pulsing');
      btnRunDeepScan.classList.add('warning');
      btnRunDeepScan.removeAttribute('data-scanning');
      
      if (wasCancelled) {
        btnRunDeepScan.innerHTML = `<span class="icon">⚠️</span> Scan Cancelled`;
      } else {
        btnRunDeepScan.innerHTML = `<span class="icon">✅</span> Scan Complete`;
      }
      
      const dsResults = document.getElementById('deep-scan-results');
      if (dsResults && dsResults.innerHTML.trim() === '') {
        dsResults.innerHTML = `<div class="ds-record" style="text-align:center; color: var(--text-muted); opacity: 0.7;">${wasCancelled ? 'Scan stopped before ports were found.' : 'No open ports discovered.'}</div>`;
      }
    }

    if (deepScanAllActive.has(ip)) {
      deepScanHostProgress[ip] = 100; // Force to 100% just in case before removal
      updateDeepScanAllProgress();
      
      // Delay removal slightly so the UI gets a chance to render 100%
      setTimeout(() => {
        if (deepScanAllActive.has(ip)) {
          deepScanAllActive.delete(ip);
          delete deepScanHostProgress[ip]; // Clean up memory
          deepScanAllCompleted++;
          if (isDeepScanningAll) {
             pumpDeepScanQueue();
             updateDeepScanAllProgress(); // Ensure 100% calculation reflects removed item
          }
        }
      }, 500);
    }
    
    // Refresh the card for this IP so the badge updates and the progress badge is removed
    const card = document.getElementById(`host-${ip.replace(/\./g, '-')}`);
    const host = hosts.find(h => h.ip === ip);
    if (card && host) {
       const badgeContainer = card.querySelector('.security-badge-container');
       if (badgeContainer) {
         badgeContainer.innerHTML = getSecurityBadgeHtml(host);
       }
    }
  });
}
