import { dialog } from 'electron';
import { spawn } from 'child_process';
import { getSetting } from './store.js';

let exportingProcess = null;

export async function exportPcap(mainWindow, interfaceId, hostIp, durationStr, onComplete, onError) {
  if (exportingProcess) {
    return { success: false, error: 'Export already running' };
  }

  try {
    const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
      title: 'Export PCAP',
      defaultPath: `capture_${Date.now()}.pcap`,
      filters: [{ name: 'PCAP Files', extensions: ['pcap'] }]
    });

    if (canceled || !filePath) return { success: true, status: 'cancelled' };

    const tsharkExecutable = getSetting('tshark.path') || 'tshark';
    const duration = parseInt(durationStr, 10) || 60;
    
    let args = [
      '-i', interfaceId,
      '-w', filePath,
      '-a', `duration:${duration}`,
      '-q' // quiet mode to not print packets to stdout
    ];

    if (hostIp) {
      args.push('-f', `host ${hostIp}`);
    }

    console.log(`Starting PCAP export: ${tsharkExecutable} ${args.join(' ')}`);

    exportingProcess = spawn(tsharkExecutable, args);
    let packetCountLine = '';

    exportingProcess.stderr.on('data', (data) => {
      const msg = data.toString();
      if (msg.includes('Packets captured:')) {
         packetCountLine = msg;
      }
    });

    exportingProcess.on('close', (code) => {
      exportingProcess = null;
      let packetCount = 0;
      const match = packetCountLine.match(/Packets captured:\s+(\d+)/);
      if (match) packetCount = parseInt(match[1], 10);

      if (onComplete) onComplete({ filePath, packetCount, duration, status: 'complete' });
    });

    exportingProcess.on('error', (err) => {
      exportingProcess = null;
      if (onError) onError(err.message);
    });

    return { success: true, status: 'started' };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
