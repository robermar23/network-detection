// src/renderer/scanAllOrchestrator.js
export function createScanAllOrchestrator({ api, elements, getHosts, updateUI }) {
  const state = {
    type: 'native',
    isRunning: false,
    queue: [],
    active: new Set(),
    total: 0,
    completed: 0,
    hostProgress: {},
  };

  function setType(type) {
    state.type = type;
  }

  function start() {
    const hosts = getHosts();
    if (!hosts.length) return;
    state.isRunning = true;
    state.queue = hosts.map(h => h.ip);
    state.total = state.queue.length;
    state.completed = 0;
    state.hostProgress = {};
    updateUI();
    pump();
  }

  function cancel() {
    state.isRunning = false;
    for (const ip of state.active) {
      if (state.type === 'native') api.cancelDeepScan(ip);
      else api.cancelNmapScan(ip);
    }
    state.active.clear();
    state.queue = [];
    updateUI();
  }

  function onHostDone(ip) {
    if (!state.isRunning || !state.active.has(ip)) return;
    state.active.delete(ip);
    delete state.hostProgress[ip];
    state.completed++;
    updateUI();
    
    if (state.active.size === 0 && state.queue.length === 0) {
      state.isRunning = false;
      updateUI();
    } else {
      pump();
    }
  }

  function onHostProgress(ip, percent) {
    if (!state.isRunning) return;
    state.hostProgress[ip] = percent;
    updateUI();
  }

  function pump() {
    if (!state.isRunning) return;
    // Concurrency limit of 3 for deep scans
    while (state.active.size < 3 && state.queue.length) {
      const ip = state.queue.shift();
      state.active.add(ip);
      if (state.type === 'native') api.runDeepScan(ip);
      else api.runNmapScan(state.type.replace('nmap-', ''), ip);
    }
    updateUI();
  }

  return { state, setType, start, cancel, onHostDone, onHostProgress };
}
