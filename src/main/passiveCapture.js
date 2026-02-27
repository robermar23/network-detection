import { spawn } from 'child_process';
import split2 from 'split2';
import { getSetting } from './store.js';

const activeModules = new Map();

export function startModule(moduleId, interfaceId, tsharkArgs, onLineParsed, onError, onComplete) {
  if (activeModules.has(moduleId)) {
    console.warn(`Passive module ${moduleId} is already running.`);
    return false;
  }

  const tsharkExecutable = getSetting('tshark.path') || 'tshark';
  const args = ['-l', '-i', interfaceId, ...tsharkArgs];

  console.log(`Starting passive module ${moduleId} at ${tsharkExecutable} with args: ${args.join(' ')}`);
  
  try {
    const child = spawn(tsharkExecutable, args);

    child.stdout.pipe(split2()).on('data', (line) => {
      if (onLineParsed) onLineParsed(line, child);
    });

    child.stderr.on('data', (data) => {
      const msg = data.toString();
      // Ignore standard tshark noise
      if (msg.includes('Capturing on') || msg.includes('Packets dropped')) return;
      if (onError) onError(msg);
    });

    child.on('close', (code) => {
      console.log(`Passive module ${moduleId} exited with code ${code}`);
      activeModules.delete(moduleId);
      if (onComplete) onComplete({ moduleId, code });
    });

    child.on('error', (err) => {
      console.error(`Failed to start passive module ${moduleId}:`, err);
      activeModules.delete(moduleId);
      if (onError) onError(err.message);
      if (onComplete) onComplete({ moduleId, code: -1, error: err.message });
    });

    activeModules.set(moduleId, child);
    return true;
  } catch (err) {
    console.error(`Spawn failed for ${moduleId}:`, err);
    if (onError) onError(err.message);
    if (onComplete) onComplete({ moduleId, code: -1, error: err.message });
    return false;
  }
}

export function stopModule(moduleId) {
  const child = activeModules.get(moduleId);
  if (child) {
    console.log(`Stopping passive module ${moduleId}`);
    child.kill('SIGINT'); // Let tshark flush to disk if it was exporting
    activeModules.delete(moduleId);
    return true;
  }
  return false;
}

export function stopAll() {
  const stopped = [];
  for (const [moduleId, child] of activeModules.entries()) {
    console.log(`Stopping passive module ${moduleId}`);
    child.kill('SIGINT');
    stopped.push(moduleId);
  }
  activeModules.clear();
  return stopped;
}

export function getStatus() {
  return Array.from(activeModules.keys());
}
