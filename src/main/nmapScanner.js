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

// ==========================================
// NCAT Execution
// ==========================================

export async function runNcat({ target, port, payload }, onResultCallback, onCompleteCallback, onErrorCallback) {
  const isInstalled = await checkNmapInstalled();
  if (!isInstalled) {
    onErrorCallback({ error: 'Nmap (and Ncat) is not installed or not in PATH.' });
    return;
  }

  // Ncat arguments: ncat [options] <host> <port>
  // We use -w 5 for a 5 second timeout so it doesn't hang forever if unresponsive.
  let args = ['-v', '-w', '10', target, port];
  
  console.log(`Starting Ncat on ${target}:${port} with args:`, args.join(' '));

  const ncatProcess = spawn('ncat', args);
  // Share the same activeScans registry so cancellation works seamlessly
  activeScans.set(target, ncatProcess);

  const fullOutput = [];

  ncatProcess.stdout.on('data', (data) => {
    const str = data.toString();
    fullOutput.push(str);
    onResultCallback({ chunk: str });
  });

  ncatProcess.stderr.on('data', (data) => {
    const str = data.toString();
    fullOutput.push(str);
    onResultCallback({ chunk: str });
  });

  // If the user provided a payload, write it to stdin and send EOF
  if (payload && payload.trim() !== '') {
     try {
       // Replace literal \n and \r tags the user might type inside the UI box with actual breaks
       let formattedPayload = payload.replace(/\\n/g, '\n').replace(/\\r/g, '\r');
       if (!formattedPayload.endsWith('\n')) {
         formattedPayload += '\n';
       }
       ncatProcess.stdin.write(formattedPayload);
       // We DO NOT end stdin here anymore so the server stream stays alive continuously.
       // User can click "Stop" in UI to kill the ncat process.
     } catch (e) {
       console.error("Failed to write Ncat payload:", e);
     }
  }

  ncatProcess.on('close', (code) => {
    activeScans.delete(target);
    console.log(`Ncat completed with code ${code}`);
    onCompleteCallback({ success: code === 0, fullOutput: fullOutput.join('') });
  });

  ncatProcess.on('error', (err) => {
    activeScans.delete(target);
    console.error('Ncat spawn error:', err);
    onErrorCallback({ error: err.message });
  });
}
