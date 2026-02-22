// UI Elements
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

// State
let isScanning = false;
let hosts = []; // Store host objects

// --- UI State Management ---

function setScanningState(scanning) {
  isScanning = scanning;
  btnScan.disabled = scanning;
  btnStop.disabled = !scanning;
  
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

function renderHostCard(host) {
  // Hide empty state if this is the first item
  if (hosts.length === 1) {
    emptyState.classList.add('hidden');
  }

  // Create DOM Elements
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
    </div>
    <div class="host-footer" style="padding-top: 8px;">
      <button class="btn info full-width" onclick="alert('Host Details for ${host.ip}:\\nPorts: ${host.ports ? host.ports.join(', ') : 'None scanned yet'}')">View Details</button>
    </div>
  `;

  // Inject into grid
  hostGrid.appendChild(card);
}

function clearGrid() {
  hosts = [];
  hostGrid.innerHTML = '';
  emptyState.classList.remove('hidden');
  statusText.innerText = 'Ready to scan.';
  setScanningState(false);
}

// --- IPC Communication ---

// 1. Control Actions
btnScan.addEventListener('click', async () => {
  setScanningState(true);
  const response = await window.electronAPI.scanNetwork();
  console.log('Main response:', response);
});

btnStop.addEventListener('click', async () => {
  setScanningState(false);
  const response = await window.electronAPI.stopScan();
  console.log('Main response:', response);
});

btnSave.addEventListener('click', async () => {
  const response = await window.electronAPI.saveResults(hosts);
  statusText.innerText = 'Results saved.';
});

btnLoad.addEventListener('click', async () => {
  const response = await window.electronAPI.loadResults();
  if (response.data) {
    clearGrid();
    hosts = response.data;
    hosts.forEach(renderHostCard);
    statusText.innerText = `Loaded ${hosts.length} hosts.`;
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
    // Check if duplicate IP, update if exists, otherwise push
    const existingIdx = hosts.findIndex(h => h.ip === hostData.ip);
    if (existingIdx >= 0) {
      hosts[existingIdx] = { ...hosts[existingIdx], ...hostData };
      // Simply re-render everything for now
      hostGrid.innerHTML = '';
      hosts.forEach(renderHostCard);
    } else {
      hosts.push(hostData);
      renderHostCard(hostData);
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
}
