import { spawn, exec } from 'child_process';
import os from 'os';

const activeScans = new Map(); // Store child processes by ID (ip or subnet)

export function checkNmapInstalled() {
  return new Promise((resolve) => {
    exec('nmap -V', (error) => {
      resolve(!error);
    });
  });
}

export function cancelNmapScan(id) {
  const scanProcess = activeScans.get(id);
  if (scanProcess) {
    console.log(`Killing Nmap scan: ${id}`);
    scanProcess.kill('SIGKILL');
    activeScans.delete(id);
    return true;
  }
  return false;
}

export async function runNmapScan(type, target, onResultCallback, onCompleteCallback, onErrorCallback) {
  const isInstalled = await checkNmapInstalled();
  if (!isInstalled) {
    onErrorCallback({ error: 'Nmap is not installed or not in PATH.' });
    return;
  }

  // Define arguments based on scan type
  let args = [];
  if (type === 'deep') {
    // Basic comprehensive scan (skip ping, version detection, all ports, aggressive)
    args = ['-Pn', '-sV', '-p', '1-65535', '-A', '-T4', '--stats-every', '3s', target];
  } else if (type === 'vuln') {
    // Vulnerability script scan
    args = ['-Pn', '-sV', '--script', 'vuln', '--stats-every', '3s', target];
  } else if (type === 'host') {
    // Standard aggressive scan for a single host
    args = ['-Pn', '-A', '-T4', '--stats-every', '3s', target];
  } else if (type === 'port') {
    // Specific port scan. Target is expected to be IP:PORT
    const [ip, port] = target.split(':');
    args = ['-Pn', '-p', port, '-sV', '-sC', '--stats-every', '3s', ip];
  } else {
    onErrorCallback({ error: 'Unknown Nmap scan type' });
    return;
  }

  console.log(`Starting Nmap ${type} scan on ${target} with args:`, args.join(' '));

  const nmapProcess = spawn('nmap', args);
  activeScans.set(target, nmapProcess);

  let outputBuffer = '';

  nmapProcess.stdout.on('data', (data) => {
    const chunk = data.toString();
    outputBuffer += chunk;
    onResultCallback({ chunk });
  });

  nmapProcess.stderr.on('data', (data) => {
    console.error(`Nmap Stderr (${target}):`, data.toString());
  });

  nmapProcess.on('close', (code) => {
    activeScans.delete(target);
    if (code !== 0 && code !== null) { // null if killed
      onErrorCallback({ error: `Nmap process exited with code ${code}` });
    } else {
      onCompleteCallback({ target, fullOutput: outputBuffer });
    }
  });

  nmapProcess.on('error', (err) => {
    activeScans.delete(target);
    onErrorCallback({ error: err.message });
  });
}
