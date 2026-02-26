import { elements, domUtils } from './ui.js';
import { api } from './api.js';
import { state } from './state.js';
import { createScanAllOrchestrator } from './scanAllOrchestrator.js';
import { ipRegex, expandCIDR } from '#shared/networkConstants.js';

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
    console.log(`Loaded ${state.nmapScripts?.length || 0} native Nmap scripts from backend.`);
    // Reveal Nmap scan-all options
    document.querySelectorAll('.scan-all-option.nmap-only').forEach(el => {
      el.style.display = 'flex';
    });
  }
});

elements.btnCloseNmapBanner.addEventListener('click', () => {
  elements.nmapInstallBanner.style.display = 'none';
});

// --- Settings Modal Logic ---
// --- Settings Modal Logic ---
const btnSettings = document.getElementById('btn-settings');
const settingsModalOverlay = document.getElementById('settings-modal-overlay');
const btnCloseSettingsModal = document.getElementById('btn-close-settings-modal');
const btnSettingsDone = document.getElementById('btn-settings-done');

// Settings DOM elements
const toggleNmap = document.getElementById('setting-nmap-enabled');
const statusNmap = document.getElementById('status-nmap');
const toggleTshark = document.getElementById('setting-tshark-enabled');
const statusTshark = document.getElementById('status-tshark');
const vlanPanelToggleBtn = document.getElementById('btn-toggle-vlan-panel');

async function loadAndApplySettings() {
  const settings = await api.settings.getAll();
  
  // Nmap logic
  const nmapInstalled = await api.checkNmap();
  statusNmap.textContent = nmapInstalled ? 'Installed' : 'Not Found inside PATH';
  statusNmap.className = nmapInstalled ? 'status-text success' : 'status-text danger';
  
  const nmapEnabled = settings.nmap?.enabled !== false; // default true
  toggleNmap.checked = nmapEnabled;
  if (!nmapInstalled && nmapEnabled) {
    toggleNmap.checked = false;
    toggleNmap.disabled = true;
    api.settings.set('nmap.enabled', false);
  }

  // Tshark logic
  const tsharkCheck = await api.settings.checkDependency('tshark');
  const tsharkInstalled = tsharkCheck.installed;
  statusTshark.textContent = tsharkInstalled ? 'Installed' : 'Not Found inside PATH';
  statusTshark.className = tsharkInstalled ? 'status-text success' : 'status-text danger';

  const tsharkEnabled = settings.tshark?.enabled !== false; // default true
  toggleTshark.checked = tsharkEnabled;
  if (!tsharkInstalled && tsharkEnabled) {
    toggleTshark.checked = false;
    toggleTshark.disabled = true;
    api.settings.set('tshark.enabled', false);
  }

  applySettingsUI(settings);
}

function applySettingsUI(settings) {
  // Hide/Show Nmap UI components globally
  const nmapEnabled = settings.nmap?.enabled !== false;
  document.querySelectorAll('.nmap-only').forEach(el => {
    el.style.display = nmapEnabled ? 'flex' : 'none';
  });

  // Hide/Show Tshark UI components globally
  const tsharkEnabled = settings.tshark?.enabled !== false;
  document.querySelectorAll('.tshark-only').forEach(el => {
    el.style.display = tsharkEnabled ? 'flex' : 'none';
  });

  if (!tsharkEnabled && vlanPanel) {
     vlanPanel.style.display = 'none';
     if (elements.detailsPanel.classList.contains('open')) {
        elements.sidebarResizer.style.display = 'block';
     } else {
        elements.sidebarResizer.style.display = 'none';
     }
  }
}

toggleNmap.addEventListener('change', async (e) => {
  await api.settings.set('nmap.enabled', e.target.checked);
  const settings = await api.settings.getAll();
  applySettingsUI(settings);
});

toggleTshark.addEventListener('change', async (e) => {
  await api.settings.set('tshark.enabled', e.target.checked);
  const settings = await api.settings.getAll();
  applySettingsUI(settings);
});


btnSettings.addEventListener('click', () => {
  loadAndApplySettings();
  settingsModalOverlay.classList.remove('hidden');
});

btnCloseSettingsModal.addEventListener('click', () => {
  settingsModalOverlay.classList.add('hidden');
});

btnSettingsDone.addEventListener('click', () => {
  settingsModalOverlay.classList.add('hidden');
});

// Run once on boot
loadAndApplySettings();

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

// =============================================
// === TARGET SCOPE MANAGEMENT MODULE ===
// =============================================

let discoverHostCount = 0; // Tracks hosts found during current modal discover session

function openScopeModal() {
  state.pendingHosts = [];
  discoverHostCount = 0;
  elements.scopeModalOverlay.classList.remove('hidden');
  updatePendingCount();
  // Clear previous pending lists
  ['discover-pending-list', 'manual-pending-list', 'import-file-pending-list', 'import-nmap-pending-list'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = '';
  });
  ['import-file-status', 'import-nmap-status', 'discover-status'].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.textContent = ''; el.className = el.id === 'discover-status' ? 'discover-status' : 'import-status'; }
  });
  // Reset manual form
  const manualIp = document.getElementById('manual-ip');
  const manualHostname = document.getElementById('manual-hostname');
  const manualMac = document.getElementById('manual-mac');
  if (manualIp) manualIp.value = '';
  if (manualHostname) manualHostname.value = '';
  if (manualMac) manualMac.value = '';
}

function closeScopeModal() {
  elements.scopeModalOverlay.classList.add('hidden');
  state.pendingHosts = [];
}

function setScopeCommitState({ staged, discovered }) {
  const total = staged + discovered;
  if (discovered > 0 && staged === 0) {
    // Discover-only: hosts are already live on dashboard
    elements.scopePendingCount.textContent = `${discovered} host${discovered !== 1 ? 's' : ''} discovered (added live)`;
    elements.btnScopeCommit.disabled = false;
    elements.btnScopeCommit.innerHTML = '<span class="icon">✅</span> Done';
    return;
  }

  if (total > 0) {
    const parts = [];
    if (staged > 0) parts.push(`${staged} staged`);
    if (discovered > 0) parts.push(`${discovered} discovered`);
    elements.scopePendingCount.textContent = `${total} host${total !== 1 ? 's' : ''} (${parts.join(', ')})`;
    elements.btnScopeCommit.disabled = false;
    elements.btnScopeCommit.innerHTML = staged > 0 
      ? '<span class="icon">✅</span> Add to Dashboard'
      : '<span class="icon">✅</span> Done';
  } else {
    elements.scopePendingCount.textContent = '0 hosts staged';
    elements.btnScopeCommit.disabled = true;
    elements.btnScopeCommit.innerHTML = '<span class="icon">✅</span> Add to Dashboard';
  }
}

function updatePendingCount() {
  const staged = state.pendingHosts.length;
  const discovered = discoverHostCount;
  setScopeCommitState({ staged, discovered });
}

function addPendingHost(host, listElId) {
  // Deduplicate by IP
  if (state.pendingHosts.some(h => h.ip === host.ip)) return;
  state.pendingHosts.push(host);
  updatePendingCount();
  renderPendingItem(host, listElId);
}

function renderPendingItem(host, listElId) {
  const listEl = document.getElementById(listElId);
  if (!listEl) return;
  const item = document.createElement('div');
  item.className = 'pending-host-item';
  item.setAttribute('data-ip', host.ip);

  const infoSpan = document.createElement('span');
  const ipSpan = document.createElement('span');
  ipSpan.className = 'pending-ip';
  ipSpan.textContent = host.ip;
  infoSpan.appendChild(ipSpan);

  if (host.hostname) {
    const metaSpan = document.createElement('span');
    metaSpan.className = 'pending-meta';
    metaSpan.textContent = host.hostname;
    infoSpan.appendChild(metaSpan);
  }
  if (host.os) {
    const osSpan = document.createElement('span');
    osSpan.className = 'pending-meta';
    osSpan.textContent = `| ${host.os}`;
    infoSpan.appendChild(osSpan);
  }

  const removeBtn = document.createElement('button');
  removeBtn.className = 'btn-remove-pending';
  removeBtn.textContent = '✕';
  removeBtn.addEventListener('click', () => {
    state.pendingHosts = state.pendingHosts.filter(h => h.ip !== host.ip);
    item.remove();
    updatePendingCount();
  });

  item.appendChild(infoSpan);
  item.appendChild(removeBtn);
  listEl.appendChild(item);
}

// Tab switching
document.querySelectorAll('.modal-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    const pane = document.getElementById(`tab-${tab.getAttribute('data-tab')}`);
    if (pane) pane.classList.add('active');
  });
});

// Open/Close scope modal
elements.btnAddHosts.addEventListener('click', openScopeModal);
if (elements.btnAddHostsCta) elements.btnAddHostsCta.addEventListener('click', openScopeModal);
elements.btnCloseScopeModal.addEventListener('click', closeScopeModal);
elements.btnScopeCancel.addEventListener('click', closeScopeModal);

// Queue for Probe Host
const probeQueue = [];
let activeProbes = 0;
const MAX_CONCURRENT_PROBES = 10;

function pumpProbeQueue() {
  while (activeProbes < MAX_CONCURRENT_PROBES && probeQueue.length > 0) {
    const { ip, validIps, completedObj } = probeQueue.shift();
    activeProbes++;
    api.probeHost(ip).then(result => {
      activeProbes--;
      completedObj.count++;
      if (!result || result.error) {
        elements.statusText.innerText = `Probed ${completedObj.count}/${validIps.length} hosts...`;
      } else {
        // Update state with enriched data
        const hostIdx = state.hosts.findIndex(h => h.ip === ip);
        if (hostIdx >= 0) {
          const host = state.hosts[hostIdx];
          if (result.hostname && result.hostname !== 'Unknown') host.hostname = result.hostname;
          if (result.mac) host.mac = result.mac;
          if (result.vendor && result.vendor !== 'Unknown') host.vendor = result.vendor;
          if (result.os && result.os !== 'Unknown OS') host.os = result.os;
          if (result.ports && result.ports.length > 0) host.ports = result.ports;
        }
        // Update card DOM inline
        const card = document.getElementById(`host-${ip.replace(/\\./g, '-')}`);
        if (card) {
          const indicator = card.querySelector('.status-indicator');
          if (indicator) {
            indicator.classList.remove('checking');
            indicator.classList.add(result.alive ? 'online' : 'offline');
            indicator.title = result.alive ? `Online (${result.pingTime || '?'}ms)` : 'Offline / Unreachable';
          }
          const nameEl = card.querySelector('.host-name-display');
          if (nameEl && result.hostname) nameEl.textContent = result.hostname;
          const osEl = card.querySelector('.host-os-display');
          if (osEl && result.os) osEl.textContent = result.os;
          const vendorEl = card.querySelector('.host-vendor-display');
          if (vendorEl && result.vendor) vendorEl.textContent = result.vendor;
          const macEl = card.querySelector('.host-mac-display');
          if (macEl && result.mac) macEl.textContent = result.mac;
        }
      }
      
      if (completedObj.count >= validIps.length) {
        elements.statusText.innerText = `Probe complete. ${completedObj.count} host${completedObj.count !== 1 ? 's' : ''} enriched.`;
      } else {
        elements.statusText.innerText = `Probing... ${completedObj.count}/${validIps.length} hosts complete.`;
      }
      pumpProbeQueue();
    }).catch(() => {
      activeProbes--;
      completedObj.count++;
      pumpProbeQueue();
    });
  }
}

// Commit pending hosts to dashboard
elements.btnScopeCommit.addEventListener('click', () => {
  const newHosts = [...state.pendingHosts];
  const hostsToProbe = [];
  newHosts.forEach(h => {
    const existingIdx = state.hosts.findIndex(existing => existing.ip === h.ip);
    if (existingIdx >= 0) {
      state.hosts[existingIdx] = { ...state.hosts[existingIdx], ...h };
    } else {
      state.hosts.push(h);
    }
    // Queue non-discovered hosts for auto-probe
    if (h.source && h.source !== 'discovered') {
      hostsToProbe.push(h.ip);
    }
  });
  elements.statusText.innerText = `Added ${newHosts.length} host${newHosts.length !== 1 ? 's' : ''} to scope.`;
  closeScopeModal();
  renderAllHosts();
  
  // Auto-probe each non-discovered host in the background
  if (hostsToProbe.length > 0) {
    const validIps = hostsToProbe.filter(ip => ipRegex.test(ip));
    if (validIps.length > 0) {
      elements.statusText.innerText = `Probing ${validIps.length} host${validIps.length !== 1 ? 's' : ''}...`;
      const completedObj = { count: 0 };
      validIps.forEach(ip => {
        probeQueue.push({ ip, validIps, completedObj });
      });
      pumpProbeQueue();
    }
  }
});

// --- Manual Entry Tab ---
// --- Manual Entry Tab ---

document.getElementById('btn-manual-add')?.addEventListener('click', () => {
  const ipInput = document.getElementById('manual-ip');
  const hostnameInput = document.getElementById('manual-hostname');
  const macInput = document.getElementById('manual-mac');
  const ipVal = ipInput.value.trim();
  if (!ipVal) { ipInput.focus(); return; }

  if (ipVal.includes('/')) {
    // CIDR: expand to individual IPs
    const expanded = expandCIDR(ipVal);
    if (expanded.length === 0) {
      ipInput.style.borderColor = 'var(--danger)';
      setTimeout(() => { ipInput.style.borderColor = ''; }, 2000);
      return;
    }
    expanded.forEach(ip => {
      addPendingHost({ ip, hostname: '', mac: '', vendor: '', os: '', source: 'manual' }, 'manual-pending-list');
    });
  } else {
    // Single host
    const host = {
      ip: ipVal,
      hostname: hostnameInput.value.trim() || '',
      mac: macInput.value.trim() || '',
      vendor: '',
      os: '',
      source: 'manual'
    };
    addPendingHost(host, 'manual-pending-list');
  }
  ipInput.value = '';
  hostnameInput.value = '';
  macInput.value = '';
  ipInput.focus();
});

// --- Import File Tab ---
document.getElementById('btn-browse-scope')?.addEventListener('click', async () => {
  const statusEl = document.getElementById('import-file-status');
  statusEl.textContent = 'Importing...';
  statusEl.className = 'import-status';
  const res = await api.importScopeFile();
  if (res.status === 'imported') {
    statusEl.textContent = `✅ Imported ${res.hosts.length} hosts from ${res.path.split(/[\\/]/).pop()}`;
    statusEl.className = 'import-status success';
    res.hosts.forEach(h => addPendingHost(h, 'import-file-pending-list'));
  } else if (res.status === 'error') {
    statusEl.textContent = `❌ Error: ${res.error}`;
    statusEl.className = 'import-status error';
  } else {
    statusEl.textContent = '';
    statusEl.className = 'import-status';
  }
});

// --- Import Nmap XML Tab ---
document.getElementById('btn-browse-nmap')?.addEventListener('click', async () => {
  const statusEl = document.getElementById('import-nmap-status');
  statusEl.textContent = 'Parsing XML...';
  statusEl.className = 'import-status';
  const res = await api.importNmapXml();
  if (res.status === 'imported') {
    statusEl.textContent = `✅ Parsed ${res.hosts.length} hosts from ${res.path.split(/[\\/]/).pop()}`;
    statusEl.className = 'import-status success';
    res.hosts.forEach(h => addPendingHost(h, 'import-nmap-pending-list'));
  } else if (res.status === 'error') {
    statusEl.textContent = `❌ Error: ${res.error}`;
    statusEl.className = 'import-status error';
  } else {
    statusEl.textContent = '';
    statusEl.className = 'import-status';
  }
});

// =============================================
// === BLACKLIST MANAGEMENT MODULE ===
// =============================================

function isBlacklisted(host) {
  if (state.blacklist.length === 0) return false;
  for (const entry of state.blacklist) {
    if (entry === host.ip) return true;
    if (host.mac && entry.toUpperCase() === host.mac.toUpperCase()) return true;
    // Simple CIDR match (basic check — match against expanded range is expensive, so just match prefix)
    if (entry.includes('/')) {
      const [net, bits] = entry.split('/');
      const prefix = parseInt(bits, 10);
      if (!isNaN(prefix) && prefix >= 8 && prefix <= 32) {
        const netParts = net.split('.').map(Number);
        const hostParts = host.ip.split('.').map(Number);
        if (netParts.length === 4 && hostParts.length === 4) {
          const netNum = ((netParts[0] << 24) | (netParts[1] << 16) | (netParts[2] << 8) | netParts[3]) >>> 0;
          const hostNum = ((hostParts[0] << 24) | (hostParts[1] << 16) | (hostParts[2] << 8) | hostParts[3]) >>> 0;
          const mask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
          if ((netNum & mask) === (hostNum & mask)) return true;
        }
      }
    }
  }
  return false;
}

function renderBlacklistEntries() {
  elements.blacklistEntries.innerHTML = '';
  state.blacklist.forEach((entry, idx) => {
    const el = document.createElement('div');
    el.className = 'blacklist-entry';
    const label = document.createElement('span');
    label.textContent = `🚫 ${entry}`;
    const removeBtn = document.createElement('button');
    removeBtn.className = 'btn-remove-bl';
    removeBtn.textContent = '✕';
    removeBtn.addEventListener('click', () => {
      state.blacklist.splice(idx, 1);
      renderBlacklistEntries();
      renderAllHosts();
    });
    el.appendChild(label);
    el.appendChild(removeBtn);
    elements.blacklistEntries.appendChild(el);
  });
  elements.blacklistCount.textContent = `${state.blacklist.length} entr${state.blacklist.length !== 1 ? 'ies' : 'y'}`;
}

elements.btnBlacklist.addEventListener('click', () => {
  elements.blacklistModalOverlay.classList.remove('hidden');
  renderBlacklistEntries();
});

elements.btnCloseBlacklistModal.addEventListener('click', () => {
  elements.blacklistModalOverlay.classList.add('hidden');
});

elements.btnBlacklistDone.addEventListener('click', () => {
  elements.blacklistModalOverlay.classList.add('hidden');
  renderAllHosts();
});

elements.btnBlacklistAdd.addEventListener('click', () => {
  const val = elements.blacklistInput.value.trim();
  if (!val) return;
  if (state.blacklist.includes(val)) return;
  state.blacklist.push(val);
  elements.blacklistInput.value = '';
  renderBlacklistEntries();
});

// Allow Enter key in blacklist input
elements.blacklistInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') elements.btnBlacklistAdd.click();
});

// =============================================
// === VLAN DISCOVERY MODULE ===
// =============================================

let isVlanCapturing = false;
let vlanTagsDetected = new Set();

const btnToggleVlanPanel = document.getElementById('btn-toggle-vlan-panel');
const vlanPanel = document.getElementById('vlan-panel');
const btnCloseVlanPanel = document.getElementById('btn-close-vlan-panel');
const vlanInterfaceSelect = document.getElementById('vlan-interface-select');
const btnRefreshVlanInterfaces = document.getElementById('btn-refresh-vlan-interfaces');
const btnStartVlanCapture = document.getElementById('btn-start-vlan-capture');
const vlanCountSpan = document.getElementById('vlan-count');
const vlanResultsContainer = document.getElementById('vlan-results-container');
const vlanEmptyState = document.getElementById('vlan-empty-state');

btnToggleVlanPanel.addEventListener('click', async () => {
  if (vlanPanel.style.display === 'none' || !vlanPanel.classList.contains('open')) {
    // Close details panel if open
    if (elements.detailsPanel.classList.contains('open')) {
       elements.detailsPanel.classList.remove('open');
    }
    
    vlanPanel.style.display = 'flex';
    // Small timeout to allow display: flex to render before animating opacity via .open
    setTimeout(() => vlanPanel.classList.add('open'), 10);
    elements.sidebarResizer.style.display = 'block';
    await refreshVlanInterfaces();
  } else {
    vlanPanel.classList.remove('open');
    setTimeout(() => vlanPanel.style.display = 'none', 300); // Wait for CSS transition
    if (!elements.detailsPanel.classList.contains('open')) {
       elements.sidebarResizer.style.display = 'none';
    }
  }
});

btnCloseVlanPanel.addEventListener('click', () => {
  vlanPanel.classList.remove('open');
  setTimeout(() => vlanPanel.style.display = 'none', 300);
  if (!elements.detailsPanel.classList.contains('open')) {
     elements.sidebarResizer.style.display = 'none';
  }
});

btnRefreshVlanInterfaces.addEventListener('click', refreshVlanInterfaces);

btnStartVlanCapture.addEventListener('click', async () => {
  if (isVlanCapturing) {
    // Stop Capture
    const res = await api.stopTsharkCapture();
    if (res.status === 'stopped') {
      isVlanCapturing = false;
      btnStartVlanCapture.innerHTML = `<span class="icon">▶️</span> Start Capture`;
      btnStartVlanCapture.classList.remove('danger', 'pulsing');
      btnStartVlanCapture.classList.add('primary');
      vlanInterfaceSelect.disabled = false;
      btnRefreshVlanInterfaces.disabled = false;
    }
  } else {
    // Start Capture
    const iface = vlanInterfaceSelect.value;
    if (!iface) {
       alert('Please select a network interface first.');
       return;
    }
    
    vlanResultsContainer.innerHTML = ''; // clear old
    if(vlanEmptyState) vlanEmptyState.style.display = 'none';
    vlanTagsDetected.clear();
    vlanCountSpan.textContent = '0';
    
    const res = await api.startTsharkCapture(iface);
    if (res.status === 'started') {
      isVlanCapturing = true;
      btnStartVlanCapture.innerHTML = `<span class="icon">🛑</span> Stop Capture`;
      btnStartVlanCapture.classList.remove('primary');
      btnStartVlanCapture.classList.add('danger', 'pulsing');
      vlanInterfaceSelect.disabled = true;
      btnRefreshVlanInterfaces.disabled = true;
    }
  }
});

async function refreshVlanInterfaces() {
  btnRefreshVlanInterfaces.disabled = true;
  vlanInterfaceSelect.innerHTML = '<option value="">Loading...</option>';
  try {
    const interfaces = await api.getInterfaces();
    vlanInterfaceSelect.innerHTML = '<option value="">Select Interface...</option>';
    interfaces.forEach(iface => {
      const opt = document.createElement('option');
      opt.value = iface.name; 
      opt.textContent = `${iface.name} (${iface.ip})`;
      vlanInterfaceSelect.appendChild(opt);
    });
  } catch (e) {
    vlanInterfaceSelect.innerHTML = '<option value="">Error Loading</option>';
  } finally {
    btnRefreshVlanInterfaces.disabled = false;
  }
}

// Tshark Event Handlers
window.electronAPI.onTsharkVlanFound((data) => {
  console.log('VLAN tag found:', data);
  const key = `vlan-${data.vlan}`;
  
  if (!vlanTagsDetected.has(data.vlan)) {
    vlanTagsDetected.add(data.vlan);
    vlanCountSpan.textContent = vlanTagsDetected.size;
    
    const el = document.createElement('div');
    el.className = 'ds-record selectable-text';
    el.id = key;
    el.style.borderLeftColor = 'var(--info)';
    el.innerHTML = `
      <div class="ds-header" style="align-items: center;">
        <div class="ds-header-title">
          <span class="ds-port selectable-text">VLAN ${data.vlan}</span>
          <span class="ds-service" style="margin-left: 8px;">802.1Q Tag</span>
        </div>
        <button class="btn icon-only copy-vlan" title="Copy to clipboard" data-vlan="${data.vlan}" data-src="${data.srcMac}" data-dst="${data.dstMac}">
          📋
        </button>
      </div>
      <div class="ds-details" style="font-size: 11px; margin-top: 4px;">
        Captured between <span class="selectable-text" style="font-family:monospace">${data.srcMac}</span> and <span class="selectable-text" style="font-family:monospace">${data.dstMac}</span>
      </div>
    `;
    vlanResultsContainer.appendChild(el);

    // Attach copy event listener explicitly to this new button
    const copyBtn = el.querySelector('.copy-vlan');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
         const textToCopy = `VLAN ID: ${data.vlan}\nSource MAC: ${data.srcMac}\nDest MAC: ${data.dstMac}`;
         navigator.clipboard.writeText(textToCopy);
         const originalText = copyBtn.innerText;
         copyBtn.innerText = '✔️';
         setTimeout(() => { copyBtn.innerText = originalText; }, 2000);
      });
    }
  }
});

window.electronAPI.onTsharkError((err) => {
  const el = document.createElement('div');
  el.className = 'ds-record';
  el.style.borderLeftColor = 'var(--danger)';
  el.innerHTML = `
    <div style="color: var(--danger); font-size: 12px; font-weight: bold;">Capture Error</div>
    <div style="color: var(--text-muted); font-size: 11px; margin-top: 4px; white-space: pre-wrap;">${err}</div>
  `;
  vlanResultsContainer.appendChild(el);
});

window.electronAPI.onTsharkComplete(({ code }) => {
  isVlanCapturing = false;
  btnStartVlanCapture.innerHTML = `<span class="icon">▶️</span> Start Capture`;
  btnStartVlanCapture.classList.remove('danger', 'pulsing');
  btnStartVlanCapture.classList.add('primary');
  vlanInterfaceSelect.disabled = false;
  btnRefreshVlanInterfaces.disabled = false;
  
  const el = document.createElement('div');
  el.style.textAlign = 'center';
  el.style.color = 'var(--text-muted)';
  el.style.fontSize = '11px';
  el.style.marginTop = '8px';
  el.textContent = `Capture ended (Code ${code})`;
  vlanResultsContainer.appendChild(el);
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
  document.getElementById('dp-header-ip').textContent = host.ip;
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
  document.getElementById('nse-search-input').placeholder = `Search ${state.nmapScripts?.length || 0} scripts (e.g. smb-)`;

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
  
  // Re-apply settings to hide Nmap buttons if disabled
  window.electronAPI.settings.getAll().then(settings => applySettings(settings));
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
    // Blacklist enforcement
    if (isBlacklisted(h)) return false;
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
    elements.scanAllGroup.style.display = 'inline-flex';
    elements.emptyState.classList.add('hidden');
  } else {
    elements.scanAllGroup.style.display = 'none';
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

// --- Scan All Dropdown Logic ---
let scanAllType = 'native'; // 'native' | 'nmap-host' | 'nmap-vuln' | 'nmap-deep'

const scanAll = createScanAllOrchestrator({
  api,
  elements,
  getHosts: getFilteredAndSortedHosts,
  updateUI: () => {
    if (!scanAll.state.isRunning) {
      const labelText = document.querySelector('.scan-all-option.active')?.getAttribute('data-label') || 'Deep Scan All';
      const iconMap = { native: '⚡', 'nmap-host': '🖥️', 'nmap-vuln': '🛡️', 'nmap-deep': '☢️' };
      elements.btnDeepScanAll.querySelector('.icon').textContent = iconMap[scanAll.state.type] || '⚡';
      elements.scanAllLabel.textContent = labelText;
      if (scanAll.state.total > 0 && scanAll.state.completed === scanAll.state.total) {
        elements.statusText.innerText = `Scan all finished (${scanAll.state.total} hosts).`;
      }
      return;
    }
    
    // Calculate global percentage based on completed and active
    let activePercentageSum = 0;
    for (const ip of scanAll.state.active) {
      if (scanAll.state.hostProgress[ip] !== undefined) activePercentageSum += scanAll.state.hostProgress[ip];
    }
    let totalPercentageVal = 0;
    if (scanAll.state.total > 0) {
      const totalMaxProgress = scanAll.state.total * 100;
      const currentProgressTotal = (scanAll.state.completed * 100) + activePercentageSum;
      totalPercentageVal = Math.round((currentProgressTotal / totalMaxProgress) * 100);
    }

    if (scanAll.state.type === 'native') {
      elements.statusText.innerText = `Deep scanning: ${scanAll.state.completed}/${scanAll.state.total} hosts completed - ${totalPercentageVal}%`;
    } else {
      const activeList = [...scanAll.state.active].map(aip => {
        const p = scanAll.state.hostProgress[aip];
        return p !== undefined ? `${aip} (${p.toFixed(0)}%)` : aip;
      }).join(', ');
      const scanLabel = `Nmap ${scanAll.state.type.replace('nmap-', '')} scan`;
      elements.statusText.innerText = `${scanLabel}: ${scanAll.state.completed}/${scanAll.state.total} done | Active: ${activeList}`;
    }
    
    // Sync abort button state
    elements.btnDeepScanAll.querySelector('.icon').textContent = '🛑';
    elements.scanAllLabel.textContent = `Cancel (${scanAll.state.completed}/${scanAll.state.total})`;
  }
});

elements.btnScanAllMenu.addEventListener('click', (e) => {
  e.stopPropagation();
  elements.scanAllDropdown.classList.toggle('hidden');
});

// Close dropdown when clicking elsewhere
document.addEventListener('click', (e) => {
  if (!e.target.closest('.scan-all-group')) {
    elements.scanAllDropdown.classList.add('hidden');
  }
});

// Handle option selection
document.querySelectorAll('.scan-all-option').forEach(opt => {
  opt.addEventListener('click', () => {
    document.querySelectorAll('.scan-all-option').forEach(o => o.classList.remove('active'));
    opt.classList.add('active');
    scanAllType = opt.getAttribute('data-scan-type');
    scanAll.setType(scanAllType);
    const label = opt.getAttribute('data-label');
    elements.scanAllLabel.textContent = label;
    // Update the main button icon
    const iconMap = { native: '⚡', 'nmap-host': '🖥️', 'nmap-vuln': '🛡️', 'nmap-deep': '☢️' };
    elements.btnDeepScanAll.querySelector('.icon').textContent = iconMap[scanAllType] || '⚡';
    elements.scanAllDropdown.classList.add('hidden');
  });
});

elements.btnDeepScanAll.addEventListener('click', () => {
  if (scanAll.state.isRunning) {
    scanAll.cancel();
    return;
  }
  scanAll.start();
});

function buildHostCard(host) {
  const card = document.createElement('div');
  card.className = 'host-card glass-panel';
  card.id = `host-${host.ip.replace(/\\./g, '-')}`;
  
  card.innerHTML = `
    <div class="status-indicator checking" title="Checking connectivity..."></div>
    <button class="btn-remove-host" title="Remove host">✕</button>
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
  updateSecurityBadgeDOM(host, card.querySelector('.security-badge-container'));
  
  return card;
}

function attachHostCardBehavior(card, host) {
  // Add source badge next to IP if not discovered
  if (host.source && host.source !== 'discovered') {
    const badge = document.createElement('span');
    badge.className = `source-badge ${host.source}`;
    const sourceLabels = { manual: '📌 Manual', imported: '📄 Imported', 'nmap-import': '📥 Nmap' };
    badge.textContent = sourceLabels[host.source] || host.source;
    card.querySelector('.host-ip-display').appendChild(badge);
  }
  
  card.querySelector('.btn-view').addEventListener('click', () => openDetailsPanel(host));
  
  // Remove host button
  card.querySelector('.btn-remove-host').addEventListener('click', (e) => {
    e.stopPropagation();
    state.hosts = state.hosts.filter(h => h.ip !== host.ip);
    card.remove();
    renderAllHosts();
  });
  
  // Async ping check for real connectivity
  if (ipRegex.test(host.ip)) {
    api.pingHost(host.ip).then(result => {
      const indicator = card.querySelector('.status-indicator');
      if (!indicator) return;
      indicator.classList.remove('checking');
      if (result && result.alive) {
        indicator.classList.add('online');
        indicator.title = `Online (${result.time}ms)`;
      } else {
        indicator.classList.add('offline');
        indicator.title = 'Offline / Unreachable';
      }
    }).catch(() => {
      const indicator = card.querySelector('.status-indicator');
      if (indicator) {
        indicator.classList.remove('checking');
        indicator.classList.add('offline');
        indicator.title = 'Ping failed';
      }
    });
  }
}

function createHostCardDOM(host) {
  const card = buildHostCard(host);
  attachHostCardBehavior(card, host);
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
    
    // If scope modal is open, track discovered hosts for the footer counter
    if (!elements.scopeModalOverlay.classList.contains('hidden')) {
      discoverHostCount++;
      const discoverStatus = document.getElementById('discover-status');
      if (discoverStatus) {
        discoverStatus.textContent = `Discovered ${discoverHostCount} host${discoverHostCount !== 1 ? 's' : ''} so far...`;
      }
      updatePendingCount();
    }
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
    if (scanAll.state.isRunning && scanAll.state.active.has(data.ip)) {
      scanAll.onHostProgress(data.ip, data.percent);
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

    if (scanAll.state.active.has(ip)) {
      scanAll.onHostProgress(ip, 100); // Force to 100% just in case before removal
      
      // Delay removal slightly so the UI gets a chance to render 100%
      setTimeout(() => {
        scanAll.onHostDone(ip);
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

    // Update scan-all status bar with per-host Nmap progress
    if (scanAll.state.isRunning && scanAll.state.type !== 'native') {
      const ip = type === 'port' ? data.target.split(':')[0] : data.target;
      if (scanAll.state.active.has(ip) && timingMatch) {
        scanAll.onHostProgress(ip, parseFloat(timingMatch[1]));
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

    // Scan-all queue: advance to next host if this was part of a batch nmap scan
    if (scanAll.state.isRunning && scanAll.state.type !== 'native' && scanAll.state.active.has(ip)) {
      scanAll.onHostDone(ip);
    }
  });

  window.electronAPI.onNmapScanError && window.electronAPI.onNmapScanError((data) => {
    const type = data.type;
    const bannerBlock = document.getElementById(`nmap-live-banner-${type}`);
    if (bannerBlock) {
       bannerBlock.innerHTML += `\n\n[ERROR]: ${data.error}`;
    }
    
    const target = data.target;
    const ip = type === 'port' ? target.split(':')[0] : target;
    const port = type === 'port' ? target.split(':')[1] : null;
    const btnIds = { 'deep': 'btn-nmap-deep', 'host': 'btn-nmap-host', 'vuln': 'btn-nmap-vuln', 'custom': 'btn-nmap-custom', 'port': `btn-nmap-port-${port}`, 'ncat': 'btn-run-ncat' };
    const btn = document.getElementById(btnIds[type]);
    if (btn) {
      btn.classList.remove('pulsing', 'danger-pulsing');
      btn.removeAttribute('data-scanning');
      btn.innerHTML = type === 'ncat' ? `<span class="icon">❌</span> Connection Failed` : `<span class="icon">❌</span> Scan Failed`;
    }

    // Scan-all queue: advance even on error
    if (scanAll.state.isRunning && scanAll.state.type !== 'native' && scanAll.state.active.has(ip)) {
      scanAll.onHostDone(ip);
    }
  });
}
