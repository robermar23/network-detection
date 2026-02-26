import { spawn } from 'child_process';
import split2 from 'split2';
import { getSetting } from './store.js';

let tsharkProcess = null;

export function startTsharkCapture(interfaceId, onVlanDiscovered, onError, onComplete) {
  if (tsharkProcess) {
    console.warn('Tshark capture is already running.');
    return;
  }

  // Fetch the reliable path discovered by dependency checker
  const tsharkExecutable = getSetting('tshark.path') || 'tshark';

  // -l = line buffered
  // -i = interface
  // -Y = display filter (evaluate vlan tags after Wi-Fi/Ethernet decapsulation)
  // -T fields = output specific fields
  // -e vlan.id -e eth.src -e eth.dst
  const args = [
    '-l',
    '-i', interfaceId,
    '-Y', 'vlan',
    '-T', 'fields',
    '-e', 'vlan.id',
    '-e', 'eth.src',
    '-e', 'eth.dst'
  ];

  console.log(`Starting tshark at ${tsharkExecutable} with args: ${args.join(' ')}`);
  tsharkProcess = spawn(tsharkExecutable, args);

  tsharkProcess.stdout.pipe(split2()).on('data', (line) => {
    const parts = line.split('\t').map(p => p.trim());
    if (parts.length >= 3) {
      // Sometimes multiple VLANs are stacked: "10,20"
      const vlans = parts[0].split(',').filter(Boolean);
      const srcMac = parts[1];
      const dstMac = parts[2];
      
      vlans.forEach(vid => {
        if (vid && srcMac) {
          onVlanDiscovered({ vlan: parseInt(vid, 10), srcMac, dstMac });
        }
      });
    }
  });

  tsharkProcess.stderr.on('data', (data) => {
    const msg = data.toString();
    console.log(`[tshark stderr] ${msg}`);
    // Ignore standard tshark noise
    if (msg.includes('Capturing on') || msg.includes('Packets dropped')) return;
    if (onError) onError(msg);
  });

  tsharkProcess.on('close', (code) => {
    console.log(`Tshark process exited with code ${code}`);
    tsharkProcess = null;
    if (onComplete) onComplete({ code });
  });
  
  tsharkProcess.on('error', (err) => {
    console.error('Failed to start tshark:', err);
    tsharkProcess = null;
    if (onError) onError(err.message);
  });
}

export function stopTsharkCapture() {
  if (tsharkProcess) {
    console.log('Stopping tshark capture');
    tsharkProcess.kill('SIGINT');
    tsharkProcess = null;
    return true;
  }
  return false;
}
