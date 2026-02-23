import { elements, domUtils } from './ui.js';
import { api } from './api.js';
import { state } from './state.js';

// --- Utilities ---
function escapeHtml(unsafe) {
  if (unsafe == null) return '';
  return String(unsafe)
       .replace(/&/g, "&amp;")
       .replace(/</g, "&lt;")
       .replace(/>/g, "&gt;")
       .replace(/"/g, "&quot;")
       .replace(/'/g, "&#039;");
}

// --- Initialization ---
api.checkNmap().then(async (installed) => {
  state.isNmapInstalled = installed;
  if (!installed) {
    elements.nmapInstallBanner.style.display = 'block';
  } else {
    state.nmapScripts = await api.getNmapScripts();
    console.log(`Loaded ${state.nmapScripts.length} native Nmap scripts from backend.`);
  }
});

elements.btnCloseNmapBanner.addEventListener('click', () => {
  elements.nmapInstallBanner.style.display = 'none';
});

// --- View Toggles ---
elements.btnViewGrid.addEventListener('click', () => { state.currentView = 'grid'; domUtils.applyViewStyle(state); });
elements.btnViewList.addEventListener('click', () => { state.currentView = 'list'; domUtils.applyViewStyle(state); });
elements.btnViewTable.addEventListener('click', () => { state.currentView = 'table'; domUtils.applyViewStyle(state); });

async function initInterfaces() {
  try {
    const interfaces = await api.getInterfaces();
    elements.interfaceSelect.innerHTML = '';
    
    if (interfaces.length === 0) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = 'No interfaces found';
      elements.interfaceSelect.appendChild(opt);
      return;
    }

    interfaces.forEach(iface => {
      const opt = document.createElement('option');
      opt.value = iface.subnet;
      opt.textContent = iface.label;
      elements.interfaceSelect.appendChild(opt);
    });

    elements.interfaceSelect.disabled = false;
    elements.btnScan.disabled = false;
  } catch (e) {
    console.error('Failed to load interfaces:', e);
    elements.interfaceSelect.innerHTML = '<option value="">Error loading</option>';
  }
}

initInterfaces();

elements.btnRefreshInterfaces.addEventListener('click', () => {
  elements.interfaceSelect.innerHTML = '<option value="">Refreshing...</option>';
  elements.interfaceSelect.disabled = true;
  elements.btnScan.disabled = true;
  initInterfaces();
});

// --- Details Panel Logic ---
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

function openDetailsPanel(host) {
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

  function getSavedNmapHtml(h) {
    if (!h.nmapData) return '';
    let html = '';
    ['deep', 'host', 'vuln'].forEach(type => {
      if (h.nmapData[type]) {
        const safeText = h.nmapData[type].replace(/</g, "&lt;").replace(/>/g, "&gt;");
        html += `<div class="ds-record"><div class="ds-service">Saved Nmap ${type.toUpperCase()} Scan</div><div class="ds-banner">${safeText}</div></div>`;
      }
    });
    if (h.nmapData.ports) {
      Object.keys(h.nmapData.ports).forEach(port => {
        const safeText = h.nmapData.ports[port].replace(/</g, "&lt;").replace(/>/g, "&gt;");
        html += `<div class="ds-record"><div class="ds-service">Saved Nmap Port Scan (Port ${port})</div><div class="ds-banner">${safeText}</div></div>`;
      });
    }
    return html;
  }

  elements.detailsContent.innerHTML = `
    <div class="info-row">
      <span class="label">IP Address</span>
      <div class="value" id="dp-field-ip"></div>
    </div>
    <div class="info-row">
      <span class="label">MAC Address</span>
      <div class="value" style="font-family: monospace;" id="dp-field-mac"></div>
    </div>
    <div class="info-row">
      <span class="label">Hostname</span>
      <div class="value" id="dp-hostname"></div>
    </div>
    <div class="info-row">
      <span class="label">Operating System</span>
      <div class="value" id="dp-os"></div>
    </div>
    <div class="info-row" id="dp-device-row" style="display: none;">
      <span class="label">Device Type</span>
      <div class="value" id="dp-device"></div>
    </div>
    <div class="info-row" id="dp-kernel-row" style="display: none;">
      <span class="label" style="min-width: 60px;">Kernel</span>
      <div class="value" id="dp-kernel" style="text-align: right;"></div>
    </div>
    <div class="info-row">
      <span class="label">Hardware Vendor</span>
      <div class="value" id="dp-vendor"></div>
    </div>
    
    <div style="margin-top: 10px; border-top: 1px solid var(--border-glass); padding-top: 16px;">
      <span class="label" style="display:block; margin-bottom: 12px; font-weight: 500; font-size: 14px; color: white;">Open Ports</span>
      <div id="dp-ports-container"></div>
    </div>
    
    <div id="dp-vulns-section" style="display: none; margin-top: 10px; border-top: 1px solid var(--border-glass); padding-top: 16px;">
      <span class="label" style="display:block; margin-bottom: 12px; font-weight: 500; font-size: 14px; color: var(--danger);">Vulnerabilities Discovered</span>
      <div style="display: flex; flex-direction: column; gap: 8px;" id="dp-vulns-container"></div>
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
        <button id="btn-run-deep-scan" class="btn warning full-width">
          <span class="icon">☢️</span> <span id="ds-run-label">Run Deep Scan</span>
        </button>
      </div>

      <!-- Nmap Actions -->
      <div id="nmap-actions" style="display: none; flex-direction: column; gap: 8px;">
        <button id="btn-nmap-deep" class="btn warning full-width" title="Aggressive scan all 65k ports">
          <span class="icon">☢️</span> Nmap Deep Scan (All Ports)
        </button>
        <button id="btn-nmap-host" class="btn info full-width" title="Standard host scan">
          <span class="icon">🖥️</span> Nmap Standard Host Scan
        </button>
        <button id="btn-nmap-vuln" class="btn danger full-width" title="Run Nmap vulnerability scripts">
          <span class="icon">🛡️</span> Nmap Vuln Scan (Scripts)
        </button>
        
        <div style="margin-top: 8px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 12px;">
           <span style="font-size: 11px; color: var(--text-muted); display: block; margin-bottom: 6px;">Nmap Scripting Engine (NSE) Explorer</span>
           <div style="display: flex; flex-direction: column; gap: 6px;">
              <div style="position: relative;">
                 <input type="text" id="nse-search-input" class="text-input full-width" autocomplete="off">
                 <div id="nse-dropdown" class="nse-dropdown"></div>
              </div>
              <input type="text" id="nse-args-input" class="text-input full-width" placeholder="Optional: --script-args user=admin">
              <button id="btn-nmap-custom" class="btn primary full-width" disabled>
                 <span class="icon">🚀</span> Run Custom Script
              </button>
           </div>
        </div>
      </div>

      <!-- Ncat Actions -->
      <div id="ncat-actions" style="display: none; flex-direction: column; gap: 8px; background: rgba(0,0,0,0.2); padding: 12px; border-radius: 6px; border: 1px solid var(--border-glass);">
        <div style="display: flex; gap: 8px;">
          <input type="number" id="input-ncat-port" class="text-input" placeholder="Port" style="width: 80px;" min="1" max="65535">
          <input type="text" id="input-ncat-payload" class="text-input" placeholder="Payload (e.g. GET / HTTP/1.0)" style="flex-grow: 1;">
        </div>
        <button id="btn-run-ncat" class="btn primary full-width" title="Launch Ncat connection">
          <span class="icon">🔌</span> Connect & Send
        </button>
      </div>

      <!-- Results Containers -->
      <div id="deep-scan-results" class="deep-scan-results selectable-text"></div>
      <div id="nmap-scan-results" class="selectable-text" style="display: none; margin-top: 12px; flex-direction: column; gap: 8px;"></div>
    </div>
  `;

  // Hydrate DOM safely
  document.getElementById('dp-field-ip').textContent = host.ip;
  document.getElementById('dp-field-mac').textContent = host.mac || 'Unknown';
  document.getElementById('dp-hostname').textContent = host.hostname || 'Unknown';
  document.getElementById('dp-os').textContent = host.os || 'Unknown';
  document.getElementById('dp-vendor').textContent = host.vendor || 'Unknown';
  
  if (host.deviceType) {
    document.getElementById('dp-device-row').style.display = 'flex';
    document.getElementById('dp-device').textContent = host.deviceType;
  }
  if (host.kernel) {
    document.getElementById('dp-kernel-row').style.display = 'flex';
    document.getElementById('dp-kernel').textContent = host.kernel;
  }

  const portsList = document.getElementById('dp-ports-container');
  if (host.ports && host.ports.length > 0) {
    host.ports.forEach(p => {
      const sp = document.createElement('span');
      sp.className = 'port-item';
      sp.setAttribute('data-port', p);
      sp.style.cursor = 'pointer';
      sp.title = `Click to Nmap Scan Port ${p}`;
      sp.textContent = p;
      portsList.appendChild(sp);
    });
  } else {
    portsList.insertAdjacentHTML('beforeend', '<span class="value">No common open ports detected.</span>');
  }

  if (host.nmapData && host.nmapData.vulnerabilities && host.nmapData.vulnerabilities.length > 0) {
    document.getElementById('dp-vulns-section').style.display = 'block';
    const vContainer = document.getElementById('dp-vulns-container');
    host.nmapData.vulnerabilities.forEach(v => {
      const vDiv = document.createElement('div');
      vDiv.style.cssText = 'background: rgba(235,94,94,0.05); border-left: 3px solid var(--danger); padding: 8px; font-size: 12px; border-radius: 4px;';
      const vHeader = document.createElement('div');
      vHeader.style.cssText = 'font-weight: 600; font-family: monospace; color: var(--danger); margin-bottom: 4px;';
      vHeader.textContent = `${v.id} (${v.severity.toUpperCase()})`;
      const vBody = document.createElement('div');
      vBody.style.cssText = 'color: var(--text-muted); line-height: 1.4;';
      // v.details is safely built in nmap module, but insert using DOM to pass linters
      vBody.insertAdjacentHTML('beforeend', v.details.replace(/\n/g, '<br>'));
      
      vDiv.appendChild(vHeader);
      vDiv.appendChild(vBody);
      vContainer.appendChild(vDiv);
    });
  }

  document.getElementById('btn-run-deep-scan').setAttribute('data-ip', host.ip);
  if (host.deepAudit && host.deepAudit.history.length > 0) {
    document.getElementById('ds-run-label').textContent = 'Re-Run Deep Scan';
  }
  
  document.getElementById('btn-nmap-deep').setAttribute('data-ip', host.ip);
  document.getElementById('btn-nmap-host').setAttribute('data-ip', host.ip);
  document.getElementById('btn-nmap-vuln').setAttribute('data-ip', host.ip);
  document.getElementById('btn-nmap-custom').setAttribute('data-ip', host.ip);
  document.getElementById('btn-run-ncat').setAttribute('data-ip', host.ip);
  document.getElementById('nse-search-input').placeholder = `Search ${state.nmapScripts.length} scripts (e.g. smb-)`;

  if (savedDeepScanHtml) {
    document.getElementById('deep-scan-results').insertAdjacentHTML('beforeend', savedDeepScanHtml);
  }
  
  const savedNmapHtml = getSavedNmapHtml(host);
  if (savedNmapHtml) {
    document.getElementById('nmap-scan-results').insertAdjacentHTML('beforeend', savedNmapHtml);
  }
  elements.detailsPanel.classList.add('open');
  elements.sidebarResizer.style.display = 'block';

  attachDetailsPanelListeners(host);
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
    if (!state.isNmapInstalled) {
       elements.nmapInstallBanner.style.display = 'block';
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
    if (!state.isNmapInstalled) {
       elements.nmapInstallBanner.style.display = 'block';
       return;
    }
    btnEngineNcat.classList.add('active');
    btnEngineNative.classList.remove('active');
    btnEngineNmap.classList.remove('active');
    ncatActions.style.display = 'flex';
    nativeActions.style.display = 'none';
    nmapActions.style.display = 'none';
    nmapScanResults.style.display = 'flex';
    dsResults.style.display = 'none';
  });

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
        if (btnRunNcat.getAttribute('data-scanning') === 'cancelling') return;
        btnRunNcat.setAttribute('data-scanning', 'cancelling');
        btnRunNcat.innerHTML = `<span class="icon">🛑</span> Stopping...`;
        api.cancelNmapScan(host.ip);
        return;
      }
      btnRunNcat.setAttribute('data-scanning', 'true');
      btnRunNcat.classList.add('pulsing');
      btnRunNcat.innerHTML = `<span class="icon">🔄</span> Running...`;

      let block = document.getElementById(`nmap-live-banner-ncat`);
      if (!block) {
        block = document.createElement('pre');
        block.id = `nmap-live-banner-ncat`;
        block.className = 'ds-banner selectable-text';
        nmapScanResults.prepend(block);
      }
      block.innerText = 'Connecting via Ncat...';
      
      await api.runNcat({
         target: host.ip,
         port: portVal,
         payload: document.getElementById('input-ncat-payload').value
      });
    });
  }

  btnRunDeepScan.addEventListener('click', async () => {
    if (btnRunDeepScan.getAttribute('data-scanning') === 'true') {
      api.cancelDeepScan(host.ip);
      btnRunDeepScan.innerHTML = `<span class="icon">🛑</span> Cancelling...`;
      btnRunDeepScan.setAttribute('data-scanning', 'cancelling');
      return;
    }

    btnRunDeepScan.setAttribute('data-scanning', 'true');
    btnRunDeepScan.classList.add('pulsing', 'danger-pulsing');
    btnRunDeepScan.classList.remove('warning');
    btnRunDeepScan.innerHTML = `<span class="icon">🛑</span> Cancel Scan...`;
    dsResults.innerHTML = ''; 
    
    const hostIdx = state.hosts.findIndex(h => h.ip === host.ip);
    if (hostIdx >= 0) {
      state.hosts[hostIdx].deepAudit = { history: [], vulnerabilities: 0, warnings: 0 };
    }
    await api.runDeepScan(host.ip);
  });

  const handleNmapScan = async (btnId, type, label) => {
    const btn = document.getElementById(btnId);
    if (btn.getAttribute('data-scanning') === 'true') {
      api.cancelNmapScan(type === 'port' ? `${host.ip}:${btn.getAttribute('data-port')}` : host.ip);
      btn.innerHTML = `<span class="icon">🛑</span> Cancelling...`;
      btn.setAttribute('data-scanning', 'cancelling');
      return;
    }

    btn.setAttribute('data-scanning', 'true');
    btn.classList.add('pulsing', 'danger-pulsing');
    btn.innerHTML = `<span class="icon">🛑</span> Cancel ${label}...`;

    let newBlock = document.createElement('div');
    newBlock.className = 'ds-record';
    newBlock.id = `nmap-live-${type}`;
    newBlock.innerHTML = `<div class="ds-service">Live Nmap ${label}</div><div class="ds-banner" id="nmap-live-banner-${type}">Initializing...</div>`;
    nmapScanResults.prepend(newBlock);

    await api.runNmapScan(type, type === 'port' ? `${host.ip}:${btn.getAttribute('data-port')}` : host.ip);
  };

  document.getElementById('btn-nmap-deep').addEventListener('click', () => handleNmapScan('btn-nmap-deep', 'deep', 'Deep Scan'));
  document.getElementById('btn-nmap-host').addEventListener('click', () => handleNmapScan('btn-nmap-host', 'host', 'Host Scan'));
  document.getElementById('btn-nmap-vuln').addEventListener('click', () => handleNmapScan('btn-nmap-vuln', 'vuln', 'Vuln Scan'));

  // NSE
  const nseSearchInput = document.getElementById('nse-search-input');
  const nseDropdown = document.getElementById('nse-dropdown');
  const btnNmapCustom = document.getElementById('btn-nmap-custom');
  const nseArgsInput = document.getElementById('nse-args-input');
  let selectedNseScript = null;

  if (nseSearchInput && nseDropdown) {
     function renderNseDropdown(filterText = '') {
        nseDropdown.innerHTML = '';
        if (!filterText) {
           nseDropdown.classList.remove('show');
           return;
        }

        const lowerFilter = filterText.toLowerCase();
        const matches = state.nmapScripts.filter(s => s.id.toLowerCase().includes(lowerFilter)).slice(0, 50);

        if (matches.length === 0) {
           nseDropdown.innerHTML = `<div style="padding: 8px; color: var(--text-muted); font-size: 11px;">No scripts found.</div>`;
        } else {
           matches.forEach(script => {
              const item = document.createElement('div');
              item.className = 'nse-dropdown-item';
              item.innerHTML = `<div style="font-weight: 500; color: var(--text-main);" class="nse-title-node"></div>`;
              item.querySelector('.nse-title-node').textContent = script.id;
              item.addEventListener('click', () => {
                 selectedNseScript = script.id;
                 nseSearchInput.value = script.id;
                 nseDropdown.classList.remove('show');
                 btnNmapCustom.disabled = false;
              });
              nseDropdown.appendChild(item);
           });
        }
        nseDropdown.classList.add('show');
     }

     nseSearchInput.addEventListener('input', (e) => {
        selectedNseScript = null;
        btnNmapCustom.disabled = true;
        renderNseDropdown(e.target.value);
     });
     document.addEventListener('click', (e) => {
        if (!nseSearchInput.contains(e.target) && !nseDropdown.contains(e.target)) {
           nseDropdown.classList.remove('show');
        }
     });

     btnNmapCustom.addEventListener('click', async () => {
        if (!selectedNseScript || btnNmapCustom.disabled) return;
        if (btnNmapCustom.getAttribute('data-scanning') === 'true') {
          api.cancelNmapScan(host.ip);
          btnNmapCustom.innerHTML = `<span class="icon">🛑</span> Cancelling...`;
          btnNmapCustom.setAttribute('data-scanning', 'cancelling');
          return;
        }

        btnNmapCustom.setAttribute('data-scanning', 'true');
        btnNmapCustom.classList.add('pulsing', 'danger-pulsing');
        btnNmapCustom.innerHTML = `<span class="icon">🛑</span> Cancel Custom Script...`;

        let newBlock = document.createElement('div');
        newBlock.className = 'ds-record';
        newBlock.id = `nmap-live-custom`;
        newBlock.innerHTML = `<div class="ds-service">Live NSE Execution (${selectedNseScript})</div><div class="ds-banner" id="nmap-live-banner-custom">Initializing...</div>`;
        nmapScanResults.prepend(newBlock);

        await api.runNmapScan('custom', {
           ip: host.ip,
           scriptName: selectedNseScript,
           args: nseArgsInput.value
        });
     });
  }

  document.querySelectorAll('.port-item').forEach(el => {
    el.addEventListener('click', () => {
       if (!state.isNmapInstalled) return alert('Nmap not installed');
       const port = el.getAttribute('data-port');
       btnEngineNmap.click();
       const btnId = `btn-nmap-port-${port}`;
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

elements.btnCloseDetails.addEventListener('click', () => {
  elements.detailsPanel.classList.remove('open');
  elements.sidebarResizer.style.display = 'none';
  elements.detailsPanel.style.width = '';
});

// Resizer logic
let isResizing = false;
let startX;
let startWidth;

elements.sidebarResizer.addEventListener('mousedown', (e) => {
  isResizing = true;
  startX = e.clientX;
  startWidth = parseInt(document.defaultView.getComputedStyle(elements.detailsPanel).width, 10);
  elements.sidebarResizer.classList.add('is-resizing');
  document.body.style.cursor = 'col-resize';
  e.preventDefault();
});

document.addEventListener('mousemove', (e) => {
  if (!isResizing) return;
  const newWidth = startWidth - (e.clientX - startX);
  if (newWidth > 300 && newWidth < Math.min(800, window.innerWidth - 100)) {
    elements.detailsPanel.style.width = `${newWidth}px`;
  }
});

document.addEventListener('mouseup', () => {
  if (isResizing) {
    isResizing = false;
    elements.sidebarResizer.classList.remove('is-resizing');
    document.body.style.cursor = '';
  }
});

function getSecurityBadgeData(host) {
  let posture = 'Unknown';
  let badgeClass = 'secondary';
  let icon = '❔';

  if (host.deepAudit && host.deepAudit.vulnerabilities > 0) {
      posture = `${host.deepAudit.vulnerabilities} Critical/High CVEs`;
      badgeClass = 'danger';
      icon = '🛑';
  } else if (host.deepAudit && host.deepAudit.warnings > 0) {
      posture = `${host.deepAudit.warnings} Medium/Low CVEs`;
      badgeClass = 'warning';
      icon = '⚠️';
  } else if ((host.deepAudit && host.deepAudit.history && host.deepAudit.history.length > 0) || (host.nmapData && host.nmapData.vuln)) {
      posture = 'Audited Secure';
      badgeClass = 'success';
      icon = '🛡️';
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

  return { posture, badgeClass, icon };
}

function updateSecurityBadgeDOM(host, container) {
  if (!container) return;
  const data = getSecurityBadgeData(host);
  const badgeSpan = document.createElement('span');
  badgeSpan.className = 'security-badge-span';
  badgeSpan.style.cssText = `font-size: 11px; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--${data.badgeClass}); color: var(--${data.badgeClass}); background: rgba(0,0,0,0.2);`;
  badgeSpan.textContent = `${data.icon} ${data.posture}`;
  
  // Clear any existing badge content and append the DOM node
  container.innerHTML = '';
  container.appendChild(badgeSpan);
}

function getFilteredAndSortedHosts() {
  const ipTerm = elements.filterIp.value.toLowerCase();
  const osTerm = elements.filterOs.value.toLowerCase();
  const vendorTerm = elements.filterVendor.value.toLowerCase();
  
  let filteredHosts = state.hosts.filter((h) => {
    const matchIp = h.ip ? h.ip.toLowerCase().includes(ipTerm) : false;
    const matchOs = h.os ? String(h.os).toLowerCase().includes(osTerm) : false;
    const matchVendor = h.vendor ? String(h.vendor).toLowerCase().includes(vendorTerm) : false;
    return (ipTerm === '' || matchIp) && (osTerm === '' || matchOs) && (vendorTerm === '' || matchVendor);
  });

  const sortBy = elements.sortSelect.value;
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
    if (valA < valB) return state.sortDirection === 'asc' ? -1 : 1;
    if (valA > valB) return state.sortDirection === 'asc' ? 1 : -1;
    return 0;
  });
  return filteredHosts;
}

function renderAllHosts() {
  const filteredHosts = getFilteredAndSortedHosts();
  elements.resultCountText.innerText = `Showing ${filteredHosts.length} of ${state.hosts.length} hosts`;
  
  if (filteredHosts.length > 0) {
    elements.btnDeepScanAll.style.display = 'inline-flex';
    elements.emptyState.classList.add('hidden');
  } else {
    elements.btnDeepScanAll.style.display = 'none';
    if (state.hosts.length === 0) {
      elements.emptyState.classList.remove('hidden');
    } else {
      elements.emptyState.classList.add('hidden');
    }
  }

  domUtils.applyViewStyle(state);

  const allCards = Array.from(elements.hostGrid.querySelectorAll('.host-card'));
  allCards.forEach(c => c.style.display = 'none');
  
  filteredHosts.forEach(host => {
     let card = document.getElementById(`host-${host.ip.replace(/\./g, '-')}`);
     if (!card) {
       card = createHostCardDOM(host);
     } else {
       card.style.display = '';
     }
     elements.hostGrid.appendChild(card);
  });
}

elements.filterIp.addEventListener('input', renderAllHosts);
elements.filterOs.addEventListener('input', renderAllHosts);
elements.filterVendor.addEventListener('input', renderAllHosts);
elements.sortSelect.addEventListener('change', renderAllHosts);

elements.btnSortDir.addEventListener('click', () => {
  state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
  elements.btnSortDir.innerText = state.sortDirection === 'asc' ? '⬇️' : '⬆️';
  renderAllHosts();
});

let renderTimeout;
function debouncedRenderAllHosts() {
  clearTimeout(renderTimeout);
  renderTimeout = setTimeout(() => renderAllHosts(), 100);
}

// Deep Scan All UI
let isDeepScanningAll = false;
let deepScanAllQueue = [];
let deepScanAllActive = new Set();
let deepScanAllTotal = 0;
let deepScanAllCompleted = 0;
let deepScanHostProgress = {};

function updateDeepScanAllProgress() {
  if (!isDeepScanningAll) return;
  let activePercentageSum = 0;
  for (const ip of deepScanAllActive) {
    if (deepScanHostProgress[ip] !== undefined) activePercentageSum += deepScanHostProgress[ip];
  }
  let totalPercentageVal = 0;
  if (deepScanAllTotal > 0) {
    const totalMaxProgress = deepScanAllTotal * 100;
    const currentProgressTotal = (deepScanAllCompleted * 100) + activePercentageSum;
    totalPercentageVal = Math.round((currentProgressTotal / totalMaxProgress) * 100);
  }
  elements.statusText.innerText = `Deep scanning: ${deepScanAllCompleted}/${deepScanAllTotal} hosts completed - ${totalPercentageVal}%`;
}

function pumpDeepScanQueue() {
  if (!isDeepScanningAll) return;
  while (deepScanAllActive.size < 3 && deepScanAllQueue.length > 0) {
    const ip = deepScanAllQueue.shift();
    deepScanAllActive.add(ip);
    const hostIdx = state.hosts.findIndex(h => h.ip === ip);
    if (hostIdx >= 0) state.hosts[hostIdx].deepAudit = { history: [], vulnerabilities: 0, warnings: 0 };
    
    const btnRunDeepScan = document.getElementById('btn-run-deep-scan');
    if (btnRunDeepScan && btnRunDeepScan.getAttribute('data-ip') === ip) {
       btnRunDeepScan.setAttribute('data-scanning', 'true');
       btnRunDeepScan.innerHTML = `<span class="icon">🛑</span> Cancel Scan...`;
    }
    api.runDeepScan(ip);
  }
  if (deepScanAllQueue.length === 0 && deepScanAllActive.size === 0) {
    isDeepScanningAll = false;
    elements.btnDeepScanAll.innerHTML = `<span class="icon">⚡</span> Deep Scan All`;
    elements.statusText.innerText = `Deep scan all finished (${deepScanAllTotal} hosts).`;
  } else updateDeepScanAllProgress();
}

elements.btnDeepScanAll.addEventListener('click', () => {
  if (isDeepScanningAll) {
    isDeepScanningAll = false;
    for (const ip of deepScanAllActive) api.cancelDeepScan(ip);
    deepScanAllActive.clear();
    elements.btnDeepScanAll.innerHTML = `<span class="icon">⚡</span> Deep Scan All`;
    return;
  }
  const filteredHosts = getFilteredAndSortedHosts();
  if (filteredHosts.length === 0) return;
  isDeepScanningAll = true;
  deepScanAllQueue = filteredHosts.map(h => h.ip);
  deepScanAllTotal = deepScanAllQueue.length;
  deepScanAllCompleted = 0;
  elements.btnDeepScanAll.innerHTML = `<span class="icon">🛑</span> Cancel Deep Scan All`;
  pumpDeepScanQueue();
});

function createHostCardDOM(host) {
  const card = document.createElement('div');
  card.className = 'host-card glass-panel';
  card.id = `host-${host.ip.replace(/\./g, '-')}`;
  card.innerHTML = `
    <div class="status-indicator online"></div>
    <div class="host-header">
      <h3 class="host-ip-display"></h3>
      <p class="mac host-mac-display"></p>
    </div>
    <div class="host-body">
      <div class="info-row"><span class="label">Hostname:</span> <span class="value host-name-display"></span></div>
      <div class="info-row"><span class="label">OS:</span> <span class="value host-os-display"></span></div>
      <div class="info-row"><span class="label">Vendor:</span> <span class="value host-vendor-display"></span></div>
      <div class="security-badge-container"></div>
    </div>
    <div class="host-footer" style="padding-top: 8px;">
      <button class="btn info full-width btn-view">View Details</button>
    </div>
  `;
  card.querySelector('.host-ip-display').textContent = host.ip;
  card.querySelector('.host-mac-display').textContent = host.mac || 'Unknown MAC';
  card.querySelector('.host-name-display').textContent = host.hostname || 'Unknown';
  card.querySelector('.host-os-display').textContent = host.os || 'Unknown';
  card.querySelector('.host-vendor-display').textContent = host.vendor || 'Unknown';
  card.querySelector('.btn-view').addEventListener('click', () => openDetailsPanel(host));
  return card;
}

function clearGrid() {
  state.hosts = [];
  elements.hostGrid.innerHTML = '';
  domUtils.applyViewStyle(state);
  elements.emptyState.classList.remove('hidden');
  elements.detailsPanel.classList.remove('open');
  elements.statusText.innerText = 'Ready to scan.';
  domUtils.setScanningState(false, state);
}

// Commands
elements.btnScan.addEventListener('click', async () => {
  const subnet = elements.interfaceSelect.value;
  if (!subnet) return alert('Select interface first.');
  domUtils.setScanningState(true, state);
  await api.scanNetwork(subnet);
});

elements.btnStop.addEventListener('click', async () => {
  domUtils.setScanningState(false, state);
  await api.stopScan();
});

elements.btnSave.addEventListener('click', async () => {
  const res = await api.saveResults(state.hosts);
  if (res.status === 'saved') elements.statusText.innerText = `Saved to ${res.path}`;
});

elements.btnLoad.addEventListener('click', async () => {
  const res = await api.loadResults();
  if (res.status === 'loaded' && res.data) {
    clearGrid();
    state.hosts = res.data;
    renderAllHosts();
  }
});

elements.btnClear.addEventListener('click', async () => {
  clearGrid();
  await api.clearResults();
});

elements.btnExit.addEventListener('click', () => {
  api.exitApp();
});

if (window.electronAPI) {
  window.electronAPI.onHostFound((hostData) => {
    const existingIdx = state.hosts.findIndex(h => h.ip === hostData.ip);
    if (existingIdx >= 0) {
      state.hosts[existingIdx] = { ...state.hosts[existingIdx], ...hostData };
    } else {
      state.hosts.push(hostData);
    }
    debouncedRenderAllHosts();
  });

  window.electronAPI.onScanComplete(({ message }) => {
    domUtils.setScanningState(false, state);
    elements.statusText.innerText = message || `Scan complete. Found ${state.hosts.length} hosts.`;
  });

  window.electronAPI.onScanError(({ error }) => {
    domUtils.setScanningState(false, state);
    elements.statusText.innerText = `Scan error: ${error}`;
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
    const hostIdx = state.hosts.findIndex(h => h.ip === data.ip);
    if (hostIdx >= 0) {
       // Initialize structure if first port
       if (!state.hosts[hostIdx].deepAudit) {
         state.hosts[hostIdx].deepAudit = { history: [], vulnerabilities: 0, warnings: 0 };
       }
       
       // Deduplicate
       if (!state.hosts[hostIdx].deepAudit.history.some(h => h.port === data.port)) {
         state.hosts[hostIdx].deepAudit.history.push(data);
         if (data.vulnerable && data.severity === 'critical') state.hosts[hostIdx].deepAudit.vulnerabilities++;
         if (data.vulnerable && data.severity === 'warning') state.hosts[hostIdx].deepAudit.warnings++;
         
         // Dynamically re-render the card Security Badge safely
         const card = document.getElementById(`host-${data.ip.replace(/\./g, '-')}`);
         if (card) {
            const badgeContainer = card.querySelector('.security-badge-container');
            if (badgeContainer) updateSecurityBadgeDOM(state.hosts[hostIdx], badgeContainer);
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
    const host = state.hosts.find(h => h.ip === ip);
    if (card && host) {
       const badgeContainer = card.querySelector('.security-badge-container');
       if (badgeContainer) {
         updateSecurityBadgeDOM(host, badgeContainer);
       }
    }
  });

  // Nmap Event Receivers
  window.electronAPI.onNmapScanResult && window.electronAPI.onNmapScanResult((data) => {
    let type = data.type;
    const chunk = data.chunk;
    
    // Parse Progress Stats
    // Example: "Stats: 0:00:03 elapsed; 0 state.hosts completed (1 up), 1 undergoing SYN Stealth Scan\nSYN Stealth Scan Timing: About 15.38% done; ETC: 14:10 (0:00:17 remaining)"
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
    const hostIdx = state.hosts.findIndex(h => h.ip === ip);
    if (hostIdx >= 0) {
      if (!state.hosts[hostIdx].nmapData) state.hosts[hostIdx].nmapData = { ports: {} };
      if (type === 'port') {
         state.hosts[hostIdx].nmapData.ports[port] = data.fullOutput;
      } else {
         state.hosts[hostIdx].nmapData[type] = data.fullOutput;
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
           state.hosts[hostIdx].os = `(Nmap) ${osName.substring(0, 30)}`;
           metadataChanged = true;
        }

        // Hostname Extraction
        const hostMatch = fullOutput.match(/Nmap scan report for (([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|[a-zA-Z0-9-]+)\s+\(/);
        if (hostMatch && hostMatch[1]) {
           const foundName = hostMatch[1];
           // Always overwrite if Nmap gives us a real name (not just echoing the IP)
           if (foundName !== ip) {
             state.hosts[hostIdx].hostname = foundName;
             metadataChanged = true;
           }
        }

        // Hardware Vendor Extraction (from MAC Address line)
        const macMatch = fullOutput.match(/MAC Address:\s*[0-9A-Fa-f:]{17}\s*\(([^\)]+)\)/i);
        if (macMatch && macMatch[1] && macMatch[1] !== 'Unknown') {
           state.hosts[hostIdx].vendor = macMatch[1];
           metadataChanged = true;
        }

        // Device Type Extraction
        const deviceMatch = fullOutput.match(/Device type:\s*([^\r\n]+)/i);
        if (deviceMatch && deviceMatch[1]) {
           state.hosts[hostIdx].deviceType = deviceMatch[1];
           metadataChanged = true;
        }

        // Kernel Extraction
        const kernelMatch = fullOutput.match(/Running(?:\s*\(JUST GUESSING\))?:\s*([^\r\n]+)/i);
        if (kernelMatch && kernelMatch[1]) {
           state.hosts[hostIdx].kernel = kernelMatch[1];
           metadataChanged = true;
        }

        // Extract Open Ports to bump Security Badge
        const portMatches = [...fullOutput.matchAll(/(\d+)\/tcp\s+open\s+/g)];
        if (portMatches.length > 0) {
           const foundPorts = portMatches.map(m => parseInt(m[1], 10));
           const existingSet = new Set(state.hosts[hostIdx].ports || []);
           let newPortsAdded = false;
           foundPorts.forEach(fp => {
             if (!existingSet.has(fp)) {
                existingSet.add(fp);
                newPortsAdded = true;
             }
           });
           if (newPortsAdded) {
              state.hosts[hostIdx].ports = Array.from(existingSet).sort((a,b) => a-b);
              metadataChanged = true;
           }
        }
      }

      // Extract Vulnerabilities
      if (type === 'vuln') {
        if (!state.hosts[hostIdx].nmapData.vulnerabilities) {
           state.hosts[hostIdx].nmapData.vulnerabilities = [];
        }

        let newVulnsFound = false;

        // 1. Standard Nmap `|   VULNERABILITY:` blocks
        const vulnBlocks = fullOutput.split('|   VULNERABILITY:');
        vulnBlocks.shift(); // remove everything before first block

        vulnBlocks.forEach(block => {
           // Parse details
           const idMatch = block.match(/IDs:\s*([^ \r\n]+)/i);
           const stateMatch = block.match(/State:\s*([^\r\n]+)/i);
           const riskMatch = block.match(/Risk factor:\s*([^\r\n]+)/i);

           if (idMatch && idMatch[1]) {
             const id = idMatch[1].replace('CVE:', '').trim();
             const state = stateMatch ? stateMatch[1].trim() : 'UNKNOWN';
             const risk = riskMatch ? riskMatch[1].trim().toLowerCase() : 'info'; // default info

             // Deduplicate
             if (!state.hosts[hostIdx].nmapData.vulnerabilities.some(v => v.id === id)) {
                state.hosts[hostIdx].nmapData.vulnerabilities.push({
                   id: id,
                   state: state,
                   severity: risk,
                   details: block.trim()
                });
                newVulnsFound = true;
             }
           }
        });

        // 2. Vulners script table output
        // Example: |     	CVE-2023-38408	9.8	https://vulners.com...	*EXPLOIT*
        const vulnersMatches = [...fullOutput.matchAll(/\|\s+([^\s]+)\s+([0-9.]+)\s+(https?:\/\/\S+)[ \t]*(\*EXPLOIT\*)?/gi)];
        
        vulnersMatches.forEach(match => {
           const id = match[1].trim();
           const cvss = parseFloat(match[2]);
           const url = match[3].trim();
           const isExploit = !!match[4];
           
           // map CVSS to severity
           let severity = 'info';
           if (cvss >= 9.0) severity = 'critical';
           else if (cvss >= 7.0) severity = 'high';
           else if (cvss >= 4.0) severity = 'medium';
           else severity = 'low';

           // Deduplicate
           if (!state.hosts[hostIdx].nmapData.vulnerabilities.some(v => v.id === id)) {
              state.hosts[hostIdx].nmapData.vulnerabilities.push({
                 id: id,
                 state: isExploit ? 'EXPLOIT AVAILABLE' : 'VULNERABLE',
                 severity: severity,
                 details: `CVSS Score: ${cvss}\nURL: <a href="${url}" target="_blank" style="color: var(--primary); text-decoration: underline;">${url}</a>${isExploit ? '\n<b>*EXPLOIT AVAILABLE*</b>' : ''}`
              });
              newVulnsFound = true;
           }
        });

        if (newVulnsFound) {
            // Recount and push to the primary deepAudit object so the dashboard badge inherently picks it up
            if (!state.hosts[hostIdx].deepAudit) {
               state.hosts[hostIdx].deepAudit = { history: [], vulnerabilities: 0, warnings: 0 };
            }

            // Recalculate totals directly based on parsed severity
            let criCount = state.hosts[hostIdx].deepAudit.history.filter(h => h.vulnerable && h.severity === 'critical').length;
            let warCount = state.hosts[hostIdx].deepAudit.history.filter(h => h.vulnerable && h.severity === 'warning').length;

            state.hosts[hostIdx].nmapData.vulnerabilities.forEach(v => {
               if (v.severity === 'high' || v.severity === 'critical') criCount++;
               if (v.severity === 'medium' || v.severity === 'warning') warCount++;
            });

            state.hosts[hostIdx].deepAudit.vulnerabilities = criCount;
            state.hosts[hostIdx].deepAudit.warnings = warCount;
        }

        // Always trigger metadata changed on Vuln scans to refresh UI into "Audited Secure" mode if 0 vulns found
        metadataChanged = true;
      }

      if (metadataChanged) {
        debouncedRenderAllHosts();

        // Explicitly update the main dashboard Host Card (since debouncedRenderAllHosts only alters display state)
        const card = document.getElementById(`host-${ip.replace(/\./g, '-')}`);
        if (card) {
           const badgeContainer = card.querySelector('.security-badge-container');
           if (badgeContainer) updateSecurityBadgeDOM(state.hosts[hostIdx], badgeContainer);
           
           try {
             const row1 = card.querySelector('.host-body .info-row:nth-child(1) .value');
             if (row1) row1.innerText = state.hosts[hostIdx].hostname || 'Unknown';
             const row2 = card.querySelector('.host-body .info-row:nth-child(2) .value');
             if (row2) row2.innerText = state.hosts[hostIdx].os || 'Unknown';
             const row3 = card.querySelector('.host-body .info-row:nth-child(3) .value');
             if (row3) row3.innerText = state.hosts[hostIdx].vendor || 'Unknown';
           } catch (e) {}
        }
        
        // Cleanly update the specific opened Details panel port map if it's the active one
        const btnRunDeepScan = document.getElementById('btn-run-deep-scan');
        if (btnRunDeepScan && btnRunDeepScan.getAttribute('data-ip') === ip) {
           if (type === 'vuln') {
              // A vulnerability scan creates complex HTML blocks. The cleanest way to show them live
              // is to seamlessly redraw the Host Details panel.
              openDetailsPanel(state.hosts[hostIdx]);
              // Restore the Nmap tab view so it doesn't jarringly switch back to Native
              setTimeout(() => {
                 const nmapBtn = document.getElementById('btn-engine-nmap');
                 if (nmapBtn) nmapBtn.click();
              }, 10);
           } else {
              // For standard metadata, perform lightweight inline DOM replacements
              const elOs = document.getElementById('dp-os');
              if (elOs) elOs.innerText = state.hosts[hostIdx].os || 'Unknown';

              const elHostname = document.getElementById('dp-hostname');
              if (elHostname) elHostname.innerText = state.hosts[hostIdx].hostname || 'Unknown';

              const elVendor = document.getElementById('dp-vendor');
              if (elVendor) elVendor.innerText = state.hosts[hostIdx].vendor || 'Unknown';
              
              const elDevice = document.getElementById('dp-device');
              const elDeviceRow = document.getElementById('dp-device-row');
              if (elDeviceRow && state.hosts[hostIdx].deviceType) {
                 elDeviceRow.style.display = 'flex';
                 if (elDevice) elDevice.innerText = state.hosts[hostIdx].deviceType;
              }

              const elKernel = document.getElementById('dp-kernel');
              const elKernelRow = document.getElementById('dp-kernel-row');
              if (elKernelRow && state.hosts[hostIdx].kernel) {
                 elKernelRow.style.display = 'flex';
                 if (elKernel) elKernel.innerText = state.hosts[hostIdx].kernel;
              }
           }
        }
      }
    }

    // Reset UI buttons
    const btnIds = {
      'deep': 'btn-nmap-deep',
      'host': 'btn-nmap-host',
      'vuln': 'btn-nmap-vuln',
      'custom': 'btn-nmap-custom',
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
    const btnIds = { 'deep': 'btn-nmap-deep', 'host': 'btn-nmap-host', 'vuln': 'btn-nmap-vuln', 'custom': 'btn-nmap-custom', 'port': `btn-nmap-port-${port}`, 'ncat': 'btn-run-ncat' };
    const btn = document.getElementById(btnIds[type]);
    if (btn) {
      btn.classList.remove('pulsing', 'danger-pulsing');
      btn.removeAttribute('data-scanning');
      btn.innerHTML = type === 'ncat' ? `<span class="icon">❌</span> Connection Failed` : `<span class="icon">❌</span> Scan Failed`;
    }
  });
}
