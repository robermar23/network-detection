import { spawn } from 'child_process';
import readline from 'readline';
import { getSetting } from './store.js';

let liveCaptureProcess = null;
let statsInterval = null;

let currentStats = {
  totalPackets: 0,
  totalBytes: 0,
  protocols: {},
  talkers: {}, // map of ip -> bytes
  warnings: []
};

// Reset state
function resetStats() {
  currentStats = {
    totalPackets: 0,
    totalBytes: 0,
    protocols: {},
    talkers: {},
    warnings: []
  };
}

// Process a single JSON packet from tshark -T ek
function processPacket(packetObj, onPacketSummary) {
  if (!packetObj || !packetObj.layers) return;
  const layers = packetObj.layers;

  // Frame details
  const frame = layers.frame;
  if (!frame) return;

  // Tshark EK sometimes returns arrays for fields. Helper to get first element:
  const getFirst = (val) => Array.isArray(val) ? val[0] : val;

  const timestamp = getFirst(frame['frame_frame_time_epoch']) || Date.now() / 1000;
  const length = parseInt(getFirst(frame['frame_frame_len']) || '0', 10);
  
  // IP details
  const ip = layers.ip;
  const ipv6 = layers.ipv6;
  let srcIp = ip ? getFirst(ip['ip_ip_src']) : (ipv6 ? getFirst(ipv6['ipv6_ipv6_src']) : 'Unknown');
  let dstIp = ip ? getFirst(ip['ip_ip_dst']) : (ipv6 ? getFirst(ipv6['ipv6_ipv6_dst']) : 'Unknown');
  
  // Protocol details
  let protocol = 'Other';
  let info = '';
  
  if (layers.tcp) {
    protocol = 'TCP';
    info = `SrcPort: ${getFirst(layers.tcp['tcp_tcp_srcport'])} DstPort: ${getFirst(layers.tcp['tcp_tcp_dstport'])}`;
    if (layers.http) {
       protocol = 'HTTP';
       info = getFirst(layers.http['http_http_request_uri']) || info;
    }
  } else if (layers.udp) {
    protocol = 'UDP';
    info = `SrcPort: ${getFirst(layers.udp['udp_udp_srcport'])} DstPort: ${getFirst(layers.udp['udp_udp_dstport'])}`;
    if (layers.dns) {
      protocol = 'DNS';
      info = getFirst(layers.dns['dns_qry_dns_qry_name']) || 'DNS Query';
    }
  } else if (layers.icmp) {
    protocol = 'ICMP';
    info = 'ICMP Message';
  } else if (layers.arp) {
    protocol = 'ARP';
    const arp = layers.arp;
    srcIp = getFirst(arp['arp_arp_src_proto_ipv4']) || 'ARP';
    dstIp = getFirst(arp['arp_arp_dst_proto_ipv4']) || 'ARP';
    info = 'ARP Request/Reply';
  }

  // Update Stats
  currentStats.totalPackets++;
  currentStats.totalBytes += length;
  currentStats.protocols[protocol] = (currentStats.protocols[protocol] || 0) + 1;

  if (srcIp !== 'Unknown') {
    currentStats.talkers[srcIp] = (currentStats.talkers[srcIp] || 0) + length;
  }
  if (dstIp !== 'Unknown') {
    currentStats.talkers[dstIp] = (currentStats.talkers[dstIp] || 0) + length;
  }
  
  // Warnings
  if (['HTTP', 'FTP', 'Telnet'].includes(protocol)) {
     if (!currentStats.warnings.includes(`Cleartext protocol detected: ${protocol}`)) {
        currentStats.warnings.push(`Cleartext protocol detected: ${protocol}`);
     }
  }

  const summary = {
    timestamp: parseFloat(timestamp) * 1000,
    srcIp,
    dstIp,
    protocol,
    length,
    info
  };

  onPacketSummary(summary);
}

function computeStatsUpdate() {
  // Sort talkers by bytes (Top 10)
  const topTalkers = Object.entries(currentStats.talkers)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ip, bytes]) => ({ ip, bytes }));

  return {
    totalPackets: currentStats.totalPackets,
    totalBytes: currentStats.totalBytes,
    protocols: currentStats.protocols,
    topTalkers: topTalkers,
    warnings: currentStats.warnings
  };
}

export function startLiveCapture(interfaceId, hostIp, options, onPacketSummary, onStats, onError, onComplete) {
  if (liveCaptureProcess) {
    onError('A live capture is already running.');
    return;
  }
  
  resetStats();
  
  const duration = options.duration || 60;
  
  // Build tshark args
  const tsharkExecutable = getSetting('tshark.path') || 'tshark';
  const args = [
    '-l', // Line-buffer output so we get packets in real time!
    '-i', interfaceId,
    '-T', 'ek', // Elasticsearch JSON format
    '-a', `duration:${duration}`,   // auto-stop after N seconds
  ];
  
  // If filtering for a specific host
  if (hostIp) {
    // Prevent "host host 192.168.1.5" syntax errors if user manually typed "host"
    const filterPrefix = hostIp.trim().toLowerCase().startsWith('host') ? '' : 'host ';
    args.push('-f', `${filterPrefix}${hostIp.trim()}`);
  } else if (options.bpfFilter) {
    args.push('-f', options.bpfFilter);
  }

  try {
    console.log(`Starting PCAP live capture: ${tsharkExecutable} ${args.join(' ')}`);
    liveCaptureProcess = spawn(tsharkExecutable, args);

    const rl = readline.createInterface({
      input: liveCaptureProcess.stdout,
      terminal: false
    });

    rl.on('line', (line) => {
      // 'ek' format outputs an index line {"index":{...}} followed by the doc line.
      // We ignore the index line to grab the doc line.
      if (!line || line.startsWith('{"index":')) return;
      try {
        const parsed = JSON.parse(line);
        processPacket(parsed, onPacketSummary);
      } catch (e) {
        // partial or invalid JSON
      }
    });

    let errorOutput = '';
    liveCaptureProcess.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    liveCaptureProcess.on('error', (err) => {
      onError(`Failed to start tshark: ${err.message}`);
      stopLiveCapture();
    });

    liveCaptureProcess.on('close', (code) => {
      liveCaptureProcess = null;
      clearInterval(statsInterval);
      if (code !== 0 && code !== null) {
        // Tshark may exit with code 2 if no packets captured or interface error, we just treat it as done usually unless nothing was captured
        console.warn(`pcapAnalyzer tshark exited with code ${code}. Stderr: ${errorOutput}`);
      }
      onComplete('Capture finished.');
    });

    // Fire stats every 2 seconds
    statsInterval = setInterval(() => {
      onStats(computeStatsUpdate());
    }, 2000);

  } catch (err) {
    onError(err.message);
  }
}

export function stopLiveCapture() {
  if (liveCaptureProcess) {
    if (process.platform === 'win32') {
      spawn('taskkill', ['/pid', liveCaptureProcess.pid, '/f', '/t']);
    } else {
      liveCaptureProcess.kill('SIGKILL');
    }
    liveCaptureProcess = null;
  }
  if (statsInterval) {
    clearInterval(statsInterval);
    statsInterval = null;
  }
}

export async function analyzePcapFile(filePath, onPacketSummary, onStats, onError, onComplete) {
  // Similar logic to live capture but reads from file using -r
  resetStats();
  
  try {
    const args = [
      '-r', filePath,
      '-T', 'ek'
    ];
    
    const analysisProcess = spawn('tshark', args);
    
    const rl = readline.createInterface({
      input: analysisProcess.stdout,
      terminal: false
    });

    rl.on('line', (line) => {
      if (!line || line.startsWith('{"index":')) return;
      try {
        const parsed = JSON.parse(line);
        processPacket(parsed, onPacketSummary);
      } catch (e) {}
    });

    let errorOutput = '';
    analysisProcess.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    analysisProcess.on('error', (err) => {
      onError(`Failed to analyze file: ${err.message}`);
    });

    // For file analysis, we might just want to send stats incrementally or at the end
    const fileStatsInterval = setInterval(() => {
      onStats(computeStatsUpdate());
    }, 1000);

    analysisProcess.on('close', (code) => {
      clearInterval(fileStatsInterval);
      onStats(computeStatsUpdate()); // final update
      
      if (code !== 0 && code !== null) {
        onError(`Analysis warning (code ${code}): ${errorOutput}`);
      }
      onComplete('File analysis finished.');
    });
  } catch(err) {
    onError(err.message);
  }
}
