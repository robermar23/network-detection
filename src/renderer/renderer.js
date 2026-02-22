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
let isNmapInstalled = false;

// Check Nmap Installation on load
window.electronAPI.checkNmap().then(installed => {
  isNmapInstalled = installed;
  if (!installed) {
    document.getElementById('nmap-install-banner').style.display = 'block';
  }
});

document.getElementById('btn-close-nmap-banner').addEventListener('click', () => {
  document.getElementById('nmap-install-banner').style.display = 'none';
});

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
      <div class="value" id="dp-hostname">${host.hostname || 'Unknown'}</div>
    </div>
    <div class="info-row">
      <span class="label">Operating System</span>
      <div class="value" id="dp-os">${host.os || 'Unknown'}</div>
    </div>
    <div class="info-row" id="dp-device-row" style="display: ${host.deviceType ? 'flex' : 'none'};">
      <span class="label">Device Type</span>
      <div class="value" id="dp-device">${host.deviceType || ''}</div>
    </div>
    <div class="info-row" id="dp-kernel-row" style="display: ${host.kernel ? 'flex' : 'none'};">
      <span class="label" style="min-width: 60px;">Kernel</span>
      <div class="value" id="dp-kernel" style="text-align: right;">${host.kernel || ''}</div>
    </div>
    <div class="info-row">
      <span class="label">Hardware Vendor</span>
      <div class="value" id="dp-vendor">${host.vendor || 'Unknown'}</div>
    </div>
    
    <div style="margin-top: 10px; border-top: 1px solid var(--border-glass); padding-top: 16px;">
      <span class="label" style="display:block; margin-bottom: 12px; font-weight: 500; font-size: 14px; color: white;">Open Ports</span>
      <div>
        ${(host.ports && host.ports.length > 0) 
          ? host.ports.map(p => `<span class="port-item" data-port="${p}" style="cursor: pointer;" title="Click to Nmap Scan Port ${p}">${p}</span>`).join('') 
          : '<span class="value">No common open ports detected.</span>'}
      </div>
    </div>
    
    <div class="deep-scan-container" style="margin-top: 10px;">
      <div style="display: flex; gap: 8px; margin-bottom: 12px; align-items: center; background: rgba(0,0,0,0.2); border-radius: 6px; padding: 4px; border: 1px solid var(--border-glass); justify-content: center;">
        <span style="font-size: 12px; color: var(--text-muted); margin-right: 4px;">Engine:</span>
        <button id="btn-engine-native" class="btn icon-only active" title="Native Scanner" style="padding: 4px 12px; border-radius: 4px; font-size: 12px; height: 24px; box-shadow: none;">Native</button>
        <button id="btn-engine-nmap" class="btn icon-only" title="Nmap Scanner" style="padding: 4px 12px; border-radius: 4px; font-size: 12px; height: 24px; box-shadow: none;">Nmap</button>
        <button id="btn-engine-ncat" class="btn icon-only" title="Ncat Netcat" style="padding: 4px 12px; border-radius: 4px; font-size: 12px; height: 24px; box-shadow: none;">Ncat</button>
      </div>

      <!-- Native Actions -->
      <div id="native-actions">
        <button id="btn-run-deep-scan" class="btn warning full-width" data-ip="${host.ip}">
          <span class="icon">☢️</span> ${host.deepAudit && host.deepAudit.history.length > 0 ? 'Re-Run Deep Scan' : 'Run Deep Scan'}
        </button>
      </div>

      <!-- Nmap Actions -->
      <div id="nmap-actions" style="display: none; flex-direction: column; gap: 8px;">
        <button id="btn-nmap-deep" class="btn warning full-width" data-ip="${host.ip}" title="Aggressive scan all 65k ports">
          <span class="icon">☢️</span> Nmap Deep Scan (All Ports)
        </button>
        <button id="btn-nmap-host" class="btn info full-width" data-ip="${host.ip}" title="Standard host scan">
          <span class="icon">🖥️</span> Nmap Standard Host Scan
        </button>
        <button id="btn-nmap-vuln" class="btn danger full-width" data-ip="${host.ip}" title="Run Nmap vulnerability scripts">
          <span class="icon">🛡️</span> Nmap Vuln Scan (Scripts)
        </button>
      </div>

      <!-- Ncat Actions -->
      <div id="ncat-actions" style="display: none; flex-direction: column; gap: 8px; background: rgba(0,0,0,0.2); padding: 12px; border-radius: 6px; border: 1px solid var(--border-glass);">
        <div style="display: flex; gap: 8px;">
          <input type="number" id="input-ncat-port" class="text-input" placeholder="Port" style="width: 80px;" min="1" max="65535">
          <input type="text" id="input-ncat-payload" class="text-input" placeholder="Payload (e.g. GET / HTTP/1.0)" style="flex-grow: 1;">
        </div>
        <button id="btn-run-ncat" class="btn primary full-width" data-ip="${host.ip}" title="Launch Ncat connection">
          <span class="icon">🔌</span> Connect & Send
        </button>
      </div>

      <!-- Results Containers -->
      <div id="deep-scan-results" class="deep-scan-results selectable-text">
        ${savedDeepScanHtml}
      </div>

      <div id="nmap-scan-results" class="selectable-text" style="display: none; margin-top: 12px; flex-direction: column; gap: 8px;">
        ${getSavedNmapHtml(host)}
      </div>
    </div>
  `;
  detailsPanel.classList.add('open');
  document.getElementById('sidebar-resizer').style.display = 'block';

  // Attach Listeners
  attachDetailsPanelListeners(host);
}

btnCloseDetails.addEventListener('click', () => {
  detailsPanel.classList.remove('open');
  document.getElementById('sidebar-resizer').style.display = 'none';
  detailsPanel.style.width = ''; // Reset custom drag width
});

// --- Sidebar Resizer Logic ---
const resizer = document.getElementById('sidebar-resizer');
let isResizing = false;
let startX;
let startWidth;

resizer.addEventListener('mousedown', (e) => {
  isResizing = true;
  startX = e.clientX;
  startWidth = parseInt(document.defaultView.getComputedStyle(detailsPanel).width, 10);
  resizer.classList.add('is-resizing');
  document.body.style.cursor = 'col-resize';
  // Prevent highlighting text while dragging
  e.preventDefault();
});

document.addEventListener('mousemove', (e) => {
  if (!isResizing) return;
  // Calculate new width (mouse moving left increases width because panel is on right)
  const newWidth = startWidth - (e.clientX - startX);
  
  // Enforce bounds
  if (newWidth > 300 && newWidth < Math.min(800, window.innerWidth - 100)) {
    detailsPanel.style.width = `${newWidth}px`;
  }
});

document.addEventListener('mouseup', () => {
  if (isResizing) {
    isResizing = false;
    resizer.classList.remove('is-resizing');
    document.body.style.cursor = '';
  }
});

function getSavedNmapHtml(host) {
  if (!host.nmapData) return '';
  let html = '';
  ['deep', 'host', 'vuln'].forEach(type => {
    if (host.nmapData[type]) {
      const safeText = host.nmapData[type].replace(/</g, "&lt;").replace(/>/g, "&gt;");
      html += `<div class="ds-record"><div class="ds-service">Saved Nmap ${type.toUpperCase()} Scan</div><div class="ds-banner">${safeText}</div></div>`;
    }
  });
  if (host.nmapData.ports) {
    Object.keys(host.nmapData.ports).forEach(port => {
      const safeText = host.nmapData.ports[port].replace(/</g, "&lt;").replace(/>/g, "&gt;");
      html += `<div class="ds-record"><div class="ds-service">Saved Nmap Port Scan (Port ${port})</div><div class="ds-banner">${safeText}</div></div>`;
    });
  }
  return html;
}

function attachDetailsPanelListeners(host) {
  const btnRunDeepScan = document.getElementById('btn-run-deep-scan');
  const btnEngineNative = document.getElementById('btn-engine-native');
  const btnEngineNmap = document.getElementById('btn-engine-nmap');
  const btnEngineNcat = document.getElementById('btn-engine-ncat');
  
  const nativeActions = document.getElementById('native-actions');
  const nmapActions = document.getElementById('nmap-actions');
  const ncatActions = document.getElementById('ncat-actions');
  
  const dsResults = document.getElementById('deep-scan-results');
  const nmapScanResults = document.getElementById('nmap-scan-results');

  // Engine toggles
  btnEngineNative.addEventListener('click', () => {
    btnEngineNative.classList.add('active');
    btnEngineNmap.classList.remove('active');
    btnEngineNcat.classList.remove('active');
    nativeActions.style.display = 'block';
    nmapActions.style.display = 'none';
    ncatActions.style.display = 'none';
    dsResults.style.display = 'flex';
    nmapScanResults.style.display = 'none';
  });

  btnEngineNmap.addEventListener('click', () => {
    if (!isNmapInstalled) {
       document.getElementById('nmap-install-banner').style.display = 'block';
       return;
    }
    btnEngineNmap.classList.add('active');
    btnEngineNative.classList.remove('active');
    btnEngineNcat.classList.remove('active');
    nmapActions.style.display = 'flex';
    nativeActions.style.display = 'none';
    ncatActions.style.display = 'none';
    nmapScanResults.style.display = 'flex';
    dsResults.style.display = 'none';
  });

  btnEngineNcat.addEventListener('click', () => {
    if (!isNmapInstalled) {
       document.getElementById('nmap-install-banner').style.display = 'block';
       return;
    }
    btnEngineNcat.classList.add('active');
    btnEngineNative.classList.remove('active');
    btnEngineNmap.classList.remove('active');
    ncatActions.style.display = 'flex';
    nativeActions.style.display = 'none';
    nmapActions.style.display = 'none';
    nmapScanResults.style.display = 'flex'; // Share nmap results space
    dsResults.style.display = 'none';
  });

  // Ncat Logic
  const btnRunNcat = document.getElementById('btn-run-ncat');
  if (btnRunNcat) {
    btnRunNcat.addEventListener('click', async () => {
      const portVal = document.getElementById('input-ncat-port').value;
      if (!portVal) {
        alert("Please specify a Target Port for Ncat.");
        return;
      }
      
      const isScanning = btnRunNcat.getAttribute('data-scanning') === 'true';
      if (isScanning) {
        // Handle cancel
        if (btnRunNcat.getAttribute('data-scanning') === 'cancelling') return;
        btnRunNcat.setAttribute('data-scanning', 'cancelling');
        btnRunNcat.innerHTML = `<span class="icon">🛑</span> Stopping...`;
        window.electronAPI.cancelNmapScan(host.ip); // Shared cancel registry in backend
        return;
      }

      btnRunNcat.setAttribute('data-scanning', 'true');
      btnRunNcat.classList.add('pulsing');
      btnRunNcat.innerHTML = `<span class="icon">🔄</span> Running...`;

      // Build live UI block
      let block = document.getElementById(`nmap-live-banner-ncat`);
      if (!block) {
        block = document.createElement('pre');
        block.id = `nmap-live-banner-ncat`;
        block.className = 'ds-banner selectable-text';
        nmapScanResults.prepend(block);
      }
      block.innerText = 'Connecting via Ncat...';
      
      const payloadObj = {
         target: host.ip,
         port: portVal,
         payload: document.getElementById('input-ncat-payload').value
      };

      await window.electronAPI.runNcat(payloadObj);
    });
  }

  // Native Deep Scan Logic
  btnRunDeepScan.addEventListener('click', async () => {
    if (btnRunDeepScan.getAttribute('data-scanning') === 'true') {
      window.electronAPI.cancelDeepScan(host.ip);
      btnRunDeepScan.innerHTML = `<span class="icon">🛑</span> Cancelling...`;
      btnRunDeepScan.setAttribute('data-scanning', 'cancelling');
      return;
    }

    btnRunDeepScan.setAttribute('data-scanning', 'true');
    btnRunDeepScan.classList.add('pulsing', 'danger-pulsing');
    btnRunDeepScan.classList.remove('warning');
    btnRunDeepScan.innerHTML = `<span class="icon">🛑</span> Cancel Scan...`;
    dsResults.innerHTML = ''; 
    
    const hostIdx = hosts.findIndex(h => h.ip === host.ip);
    if (hostIdx >= 0) {
      hosts[hostIdx].deepAudit = { history: [], vulnerabilities: 0, warnings: 0 };
    }
    await window.electronAPI.runDeepScan(host.ip);
  });

  // Nmap Buttons Logic
  const handleNmapScan = async (btnId, type, label) => {
    const btn = document.getElementById(btnId);
    if (btn.getAttribute('data-scanning') === 'true') {
      window.electronAPI.cancelNmapScan(type === 'port' ? `${host.ip}:${btn.getAttribute('data-port')}` : host.ip);
      btn.innerHTML = `<span class="icon">🛑</span> Cancelling...`;
      btn.setAttribute('data-scanning', 'cancelling');
      return;
    }

    btn.setAttribute('data-scanning', 'true');
    btn.classList.add('pulsing', 'danger-pulsing');
    btn.innerHTML = `<span class="icon">🛑</span> Cancel ${label}...`;

    // Construct clear blocks block
    let newBlock = document.createElement('div');
    newBlock.className = 'ds-record';
    newBlock.id = `nmap-live-${type}`;
    newBlock.innerHTML = `<div class="ds-service">Live Nmap ${label}</div><div class="ds-banner" id="nmap-live-banner-${type}">Initializing...</div>`;
    nmapScanResults.prepend(newBlock);

    await window.electronAPI.runNmapScan(type, type === 'port' ? `${host.ip}:${btn.getAttribute('data-port')}` : host.ip);
  };

  document.getElementById('btn-nmap-deep').addEventListener('click', () => handleNmapScan('btn-nmap-deep', 'deep', 'Deep Scan'));
  document.getElementById('btn-nmap-host').addEventListener('click', () => handleNmapScan('btn-nmap-host', 'host', 'Host Scan'));
  document.getElementById('btn-nmap-vuln').addEventListener('click', () => handleNmapScan('btn-nmap-vuln', 'vuln', 'Vuln Scan'));

  // Clickable ports logic
  document.querySelectorAll('.port-item').forEach(el => {
    el.addEventListener('click', () => {
       if (!isNmapInstalled) return alert('Nmap not installed');
       const port = el.getAttribute('data-port');
       
       // Programmatically switch to Nmap
       btnEngineNmap.click();
       
       const btnId = `btn-nmap-port-${port}`;
       // If a temporary button doesn't exist, create it
       if (!document.getElementById(btnId)) {
          const newBtn = document.createElement('button');
          newBtn.id = btnId;
          newBtn.className = 'btn warning full-width';
          newBtn.setAttribute('data-port', port);
          newBtn.innerHTML = `<span class="icon">🎯</span> Nmap specific port: ${port}`;
          newBtn.addEventListener('click', () => handleNmapScan(btnId, 'port', `Port ${port} Scan`));
          nmapActions.appendChild(newBtn);
       }
       document.getElementById(btnId).click();
    });
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

  // Nmap Event Receivers
  window.electronAPI.onNmapScanResult && window.electronAPI.onNmapScanResult((data) => {
    let type = data.type;
    const chunk = data.chunk;
    
    // Parse Progress Stats
    // Example: "Stats: 0:00:03 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan\nSYN Stealth Scan Timing: About 15.38% done; ETC: 14:10 (0:00:17 remaining)"
    const timingMatch = chunk.match(/Timing:\s*About\s*([\d.]+)%\s*done/i);
    if (timingMatch) {
       const percent = parseFloat(timingMatch[1]).toFixed(1);
       const target = data.target;
       const port = type === 'port' ? target.split(':')[1] : null;
       const btnIds = { 'deep': 'btn-nmap-deep', 'host': 'btn-nmap-host', 'vuln': 'btn-nmap-vuln', 'port': `btn-nmap-port-${port}` };
       const btn = document.getElementById(btnIds[type]);
       
       if (btn && btn.getAttribute('data-scanning') === 'true') {
         // Determine original label
         let label = 'Scan';
         if (type === 'deep') label = 'Deep Scan';
         if (type === 'host') label = 'Host Scan';
         if (type === 'vuln') label = 'Vuln Scan';
         if (type === 'port') label = `Port ${port} Scan`;
         
         btn.innerHTML = `<span class="icon">🛑</span> Cancel ${label}... (${percent}%)`;
       }
    }
    
    const bannerBlock = document.getElementById(`nmap-live-banner-${type}`);
    if (bannerBlock) {
      if (bannerBlock.innerText === 'Initializing...') bannerBlock.innerText = '';
      const safeChunk = chunk.replace(/</g, "&lt;").replace(/>/g, "&gt;");
      bannerBlock.innerHTML += safeChunk;
    }
  });

  window.electronAPI.onNmapScanComplete && window.electronAPI.onNmapScanComplete((data) => {
    const target = data.target;
    const type = data.type;
    const ip = type === 'port' ? target.split(':')[0] : target;
    const port = type === 'port' ? target.split(':')[1] : null;

    // Save state
    const hostIdx = hosts.findIndex(h => h.ip === ip);
    if (hostIdx >= 0) {
      if (!hosts[hostIdx].nmapData) hosts[hostIdx].nmapData = { ports: {} };
      if (type === 'port') {
         hosts[hostIdx].nmapData.ports[port] = data.fullOutput;
      } else {
         hosts[hostIdx].nmapData[type] = data.fullOutput;
      }

      // Metadata Extraction for Dashboard
      let metadataChanged = false;
      const fullOutput = data.fullOutput;

      // Extract OS
      if (type === 'host' || type === 'deep') {
        // OS Extraction
        const osMatch1 = fullOutput.match(/OS details:\s*([^\r\n]+)/i);
        const osMatch2 = fullOutput.match(/Service Info:.*?OS:\s*([^;]+);/i);
        const osName = (osMatch1 && osMatch1[1]) || (osMatch2 && osMatch2[1]);
        if (osName) {
           hosts[hostIdx].os = `(Nmap) ${osName.substring(0, 30)}`;
           metadataChanged = true;
        }

        // Hostname Extraction
        const hostMatch = fullOutput.match(/Nmap scan report for (([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|[a-zA-Z0-9-]+)\s+\(/);
        if (hostMatch && hostMatch[1]) {
           const foundName = hostMatch[1];
           // Always overwrite if Nmap gives us a real name (not just echoing the IP)
           if (foundName !== ip) {
             hosts[hostIdx].hostname = foundName;
             metadataChanged = true;
           }
        }

        // Hardware Vendor Extraction (from MAC Address line)
        const macMatch = fullOutput.match(/MAC Address:\s*[0-9A-Fa-f:]{17}\s*\(([^\)]+)\)/i);
        if (macMatch && macMatch[1] && macMatch[1] !== 'Unknown') {
           hosts[hostIdx].vendor = macMatch[1];
           metadataChanged = true;
        }

        // Device Type Extraction
        const deviceMatch = fullOutput.match(/Device type:\s*([^\r\n]+)/i);
        if (deviceMatch && deviceMatch[1]) {
           hosts[hostIdx].deviceType = deviceMatch[1];
           metadataChanged = true;
        }

        // Kernel Extraction
        const kernelMatch = fullOutput.match(/Running(?:\s*\(JUST GUESSING\))?:\s*([^\r\n]+)/i);
        if (kernelMatch && kernelMatch[1]) {
           hosts[hostIdx].kernel = kernelMatch[1];
           metadataChanged = true;
        }

        // Extract Open Ports to bump Security Badge
        const portMatches = [...fullOutput.matchAll(/(\d+)\/tcp\s+open\s+/g)];
        if (portMatches.length > 0) {
           const foundPorts = portMatches.map(m => parseInt(m[1], 10));
           const existingSet = new Set(hosts[hostIdx].ports || []);
           let newPortsAdded = false;
           foundPorts.forEach(fp => {
             if (!existingSet.has(fp)) {
                existingSet.add(fp);
                newPortsAdded = true;
             }
           });
           if (newPortsAdded) {
              hosts[hostIdx].ports = Array.from(existingSet).sort((a,b) => a-b);
              metadataChanged = true;
           }
        }
      }

      if (metadataChanged) {
        debouncedRenderAllHosts();
        
        // Also cleanly update the specific opened Details panel port map if it's the active one
        const btnRunDeepScan = document.getElementById('btn-run-deep-scan');
        if (btnRunDeepScan && btnRunDeepScan.getAttribute('data-ip') === ip) {
           const elOs = document.getElementById('dp-os');
           if (elOs) elOs.innerText = hosts[hostIdx].os || 'Unknown';

           const elHostname = document.getElementById('dp-hostname');
           if (elHostname) elHostname.innerText = hosts[hostIdx].hostname || 'Unknown';

           const elVendor = document.getElementById('dp-vendor');
           if (elVendor) elVendor.innerText = hosts[hostIdx].vendor || 'Unknown';
           
           const elDevice = document.getElementById('dp-device');
           const elDeviceRow = document.getElementById('dp-device-row');
           if (elDeviceRow && hosts[hostIdx].deviceType) {
              elDeviceRow.style.display = 'flex';
              if (elDevice) elDevice.innerText = hosts[hostIdx].deviceType;
           }

           const elKernel = document.getElementById('dp-kernel');
           const elKernelRow = document.getElementById('dp-kernel-row');
           if (elKernelRow && hosts[hostIdx].kernel) {
              elKernelRow.style.display = 'flex';
              if (elKernel) elKernel.innerText = hosts[hostIdx].kernel;
           }
        }
      }
    }

    // Reset UI buttons
    const btnIds = {
      'deep': 'btn-nmap-deep',
      'host': 'btn-nmap-host',
      'vuln': 'btn-nmap-vuln',
      'port': `btn-nmap-port-${port}`,
      'ncat': 'btn-run-ncat'
    };
    
    const btn = document.getElementById(btnIds[type]);
    if (btn) {
      const wasCancelled = btn.getAttribute('data-scanning') === 'cancelling';
      btn.classList.remove('pulsing', 'danger-pulsing');
      btn.removeAttribute('data-scanning');
      
      if (type === 'ncat') {
         btn.innerHTML = wasCancelled ? `<span class="icon">⚠️</span> Disconnected` : `<span class="icon">🔌</span> Connect & Send`;
      } else {
         btn.innerHTML = wasCancelled ? `<span class="icon">⚠️</span> Scan Cancelled` : `<span class="icon">✅</span> Scan Complete`;
      }

      if (wasCancelled) {
        const bannerBlock = document.getElementById(`nmap-live-banner-${type}`);
        if (bannerBlock) bannerBlock.innerHTML += '\n\n[DISCONNECTED]';
      }
    }
  });

  window.electronAPI.onNmapScanError && window.electronAPI.onNmapScanError((data) => {
    const type = data.type;
    const bannerBlock = document.getElementById(`nmap-live-banner-${type}`);
    if (bannerBlock) {
       bannerBlock.innerHTML += `\n\n[ERROR]: ${data.error}`;
    }
    
    const target = data.target;
    const port = type === 'port' ? target.split(':')[1] : null;
    const btnIds = { 'deep': 'btn-nmap-deep', 'host': 'btn-nmap-host', 'vuln': 'btn-nmap-vuln', 'port': `btn-nmap-port-${port}`, 'ncat': 'btn-run-ncat' };
    const btn = document.getElementById(btnIds[type]);
    if (btn) {
      btn.classList.remove('pulsing', 'danger-pulsing');
      btn.removeAttribute('data-scanning');
      btn.innerHTML = type === 'ncat' ? `<span class="icon">❌</span> Connection Failed` : `<span class="icon">❌</span> Scan Failed`;
    }
  });
}
