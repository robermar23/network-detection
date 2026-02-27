import { spawn } from 'child_process';
import split2 from 'split2';
import path from 'path';
import { app } from 'electron';
import fs from 'fs';

let rustProcess = null;
let requestId = 0;
const pendingRequests = new Map();
const REQUEST_TIMEOUT_MS = 30000;
let spawnRetryCount = 0;
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 2000;

function getEnginePath() {
  const isDev = process.env.NODE_ENV === 'development';
  const ext = process.platform === 'win32' ? '.exe' : '';
  const binaryName = `netspectre-engine${ext}`;

  if (isDev) {
    return path.join(app.getAppPath(), 'engines', 'rust-core', 'target', 'release', binaryName);
  }
  return path.join(process.resourcesPath, 'engines', binaryName);
}

function getDataDir() {
  return path.join(app.getPath('userData'), 'netspectre-data');
}

function spawnEngine() {
  const binPath = getEnginePath();

  // Check if binary exists before attempting spawn
  if (!fs.existsSync(binPath)) {
    console.warn(`[rust-engine] Binary not found at ${binPath}`);
    return;
  }

  const dataDir = getDataDir();
  fs.mkdirSync(dataDir, { recursive: true });

  console.log(`[rust-engine] Spawning: ${binPath} --data-dir ${dataDir}`);

  rustProcess = spawn(binPath, ['--data-dir', dataDir], {
    stdio: ['pipe', 'pipe', 'pipe']
  });

  rustProcess.stdout.pipe(split2()).on('data', (line) => {
    try {
      const msg = JSON.parse(line);
      if (msg.id !== undefined && pendingRequests.has(msg.id)) {
        const { resolve, reject, timer } = pendingRequests.get(msg.id);
        clearTimeout(timer);
        pendingRequests.delete(msg.id);
        if (msg.error) {
          reject(msg.error);
        } else {
          resolve(msg.result);
        }
      }
    } catch (e) {
      console.error('[rust-engine] Failed to parse response:', line);
    }
  });

  rustProcess.stderr.on('data', (data) => {
    console.warn('[rust-engine stderr]', data.toString());
  });

  rustProcess.on('close', (code) => {
    console.log(`[rust-engine] Process exited with code ${code}`);
    rustProcess = null;

    // Reject all pending requests
    for (const [id, { reject, timer }] of pendingRequests) {
      clearTimeout(timer);
      reject({ code: -32603, message: 'Engine process exited unexpectedly' });
    }
    pendingRequests.clear();

    // Auto-restart on unexpected exit
    if (code !== 0 && code !== null && spawnRetryCount < MAX_RETRIES) {
      spawnRetryCount++;
      console.log(`[rust-engine] Retry ${spawnRetryCount}/${MAX_RETRIES} in ${RETRY_DELAY_MS}ms`);
      setTimeout(() => spawnEngine(), RETRY_DELAY_MS);
    }
  });

  rustProcess.on('error', (err) => {
    console.error('[rust-engine] Spawn error:', err.message);
    rustProcess = null;
  });

  // Reset retry counter on successful spawn
  spawnRetryCount = 0;
}

function sendRequest(method, params = {}) {
  return new Promise((resolve, reject) => {
    if (!rustProcess) {
      reject({ code: -32603, message: 'Rust engine not running' });
      return;
    }

    const id = ++requestId;
    const msg = JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';

    const timer = setTimeout(() => {
      pendingRequests.delete(id);
      reject({ code: -32603, message: `Request timed out after ${REQUEST_TIMEOUT_MS}ms` });
    }, REQUEST_TIMEOUT_MS);

    pendingRequests.set(id, { resolve, reject, timer });

    try {
      rustProcess.stdin.write(msg);
    } catch (err) {
      clearTimeout(timer);
      pendingRequests.delete(id);
      reject({ code: -32603, message: `Failed to write to engine stdin: ${err.message}` });
    }
  });
}

// ── Public API ─────────────────────────────────────────────────────

export function initRustEngine() {
  spawnEngine();
}

export function shutdownRustEngine() {
  if (rustProcess) {
    rustProcess.kill('SIGTERM');
    rustProcess = null;
  }
  for (const [, { reject, timer }] of pendingRequests) {
    clearTimeout(timer);
    reject({ code: -32603, message: 'Engine shutting down' });
  }
  pendingRequests.clear();
}

export function isRustEngineRunning() {
  return rustProcess !== null;
}

export async function rustRpc(method, params = {}) {
  return sendRequest(method, params);
}
