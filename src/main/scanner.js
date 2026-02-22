import { spawn, exec } from 'child_process';
import net from 'net';
import ping from 'ping';
import os from 'os';
import https from 'https';

let scanActive = false;

// Basic MAC OUI vendor mappings (extensible fallback)
const vendorMap = {
  // Apple
  'E4:5F:01': 'Apple, Inc.',
  'D4:61:9D': 'Apple, Inc.',
  '00:25:00': 'Apple, Inc.',
  'F8:FF:C2': 'Apple, Inc.',
  '00:1E:52': 'Apple, Inc.',
  '00:1C:B3': 'Apple, Inc.',
  'BC:6C:21': 'Apple, Inc.',
  
  // Virtual Machines
  '00:0C:29': 'VMware, Inc.',
  '00:50:56': 'VMware, Inc.',
  '08:00:27': 'PCS Systemtechnik (VirtualBox)',
  '00:15:5D': 'Microsoft Corporation (Hyper-V)',

  // Smart Home / Mobile / IoT
  '00:1A:11': 'Google, Inc.',
  '3C:5A:B4': 'Google, Inc.',
  'F4:F5:D8': 'Google, Inc.',
  'CC:B8:A8': 'Samsung Electronics',
  '00:16:32': 'Samsung Electronics',
  '00:24:E4': 'Withings',
  '44:65:0D': 'Amazon Technologies Inc.',
  '18:74:2E': 'Amazon Technologies Inc.',
  'B4:7C:9C': 'Amazon Technologies Inc.',
  'F4:5E:AB': 'Amazon Technologies Inc.',
  '24:18:1D': 'Amazon Technologies Inc.',
  '54:60:09': 'Google, Inc. (Nest)',

  // Gaming Consoles
  '00:24:8D': 'Sony Interactive Entertainment',
  '00:D9:D1': 'Sony Interactive Entertainment',
  '50:1A:A5': 'Microsoft Corporation (Xbox)',
  // Entertainment & IoT
  'B8:AE:6E': 'Nintendo Co., Ltd',
  '84:EA:ED': 'Roku, Inc',
  '84:E6:57': 'Sony Interactive Entertainment Inc.',
  '00:04:4B': 'NVIDIA',
  '64:52:99': 'The Chamberlain Group, Inc',
  '84:BA:3B': 'CANON INC.',

  // Network Gear & PCs
  'AC:84:C6': 'TP-Link Technologies Co.,Ltd',
  '40:ED:00': 'TP-Link Systems Inc',
  '00:14:22': 'Dell Inc.',
  '18:DB:F2': 'Dell Inc.',
  '00:1B:44': 'Intel Corporate',
  'A4:4C:C8': 'Intel Corporate',
  '00:00:0C': 'Cisco Systems, Inc',
  '00:01:42': 'Cisco Systems, Inc',
  '88:E9:FE': 'Cisco Systems, Inc',
  '00:10:5A': 'Acer Inc.',
  '00:11:0A': 'HP Inc.',
  'B8:27:EB': 'Raspberry Pi Foundation',
  'DC:A6:32': 'Raspberry Pi Foundation',
  'E4:5F:01': 'Raspberry Pi Foundation'
};

// In-memory cache for dynamic MAC API lookups
const ouiCache = { ...vendorMap };

// Queue system to prevent MAC API rate limiting (max 1 req/sec)
const apiQueue = [];
let isApiFetching = false;

function fetchMacVendorAPI(oui) {
  return new Promise((resolve) => {
    https.get(`https://api.macvendors.com/${oui}`, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode === 200) {
          resolve(data.trim());
        } else {
          resolve('Unknown');
        }
      });
    }).on('error', () => {
      resolve('Unknown');
    });
  });
}

async function processApiQueue() {
  if (isApiFetching || apiQueue.length === 0) return;
  isApiFetching = true;

  while (apiQueue.length > 0) {
    const { oui, resolve } = apiQueue.shift();
    
    // Check if another request fulfilled this while we waited
    if (ouiCache[oui] && ouiCache[oui] !== 'Unknown') {
      resolve(ouiCache[oui]);
      continue;
    }

    try {
      const vendorName = await fetchMacVendorAPI(oui);
      ouiCache[oui] = vendorName;
      resolve(vendorName);
    } catch {
      resolve('Unknown');
    }

    // Required 1.2s delay to dodge macvendors.com 429 Rate Limits
    await new Promise(r => setTimeout(r, 1200)); 
  }

  isApiFetching = false;
}

const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 548, 993, 995, 1723, 3306, 3389, 5900, 8080];

/**
 * Gets a list of available IPv4 network interfaces and their CIDR subnets.
 * Returns an array of objects: { name, ip, subnet, label }
 */
export function getNetworkInterfaces() {
  const interfaces = os.networkInterfaces();
  const results = [];
  
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (!iface.internal && iface.family === 'IPv4') {
        const parts = iface.address.split('.');
        parts.pop();
        const subnet = parts.join('.') + '.';
        results.push({
          name: name,
          ip: iface.address,
          subnet: subnet,
          label: `${name} - ${iface.address}`
        });
      }
    }
  }
  return results;
}

/**
 * Gets the current machine's primary IPv4 subnet.
 * Simplistic approach: assumes /24 subnet for local scanning.
 */
function getLocalSubnet() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (!iface.internal && iface.family === 'IPv4') {
        const parts = iface.address.split('.');
        parts.pop();
        return parts.join('.') + '.';
      }
    }
  }
  return '192.168.1.';
}

/**
 * Parses ARP table for MAC addresses based on OS.
 */
function getArpTable() {
  return new Promise((resolve) => {
    exec('arp -a', (err, stdout) => {
      if (err) {
        resolve({});
        return;
      }
      
      const arpMap = {};
      const lines = stdout.split('\n');
      
      lines.forEach(line => {
        // Windows arp -a format matching
        let match = line.match(/(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+/);
        if (!match) {
          // Linux/Mac format matching
          match = line.match(/(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]+)/);
        }
        
        if (match) {
          const ip = match[1];
          const mac = match[2].replace(/-/g, ':').toUpperCase();
          if (mac !== 'FF:FF:FF:FF:FF:FF') {
             arpMap[ip] = mac;
          }
        }
      });
      resolve(arpMap);
    });
  });
}

async function getVendorFromMac(mac) {
  if (!mac || mac === 'Unknown') return 'Unknown';
  
  const oui = mac.substring(0, 8).toUpperCase();
  
  // 1. Check local memory cache (which includes the hardcoded fallbacks)
  if (ouiCache[oui] && ouiCache[oui] !== 'Unknown') {
    return ouiCache[oui];
  }

  // 2. Queue for Live API Resolution if missing
  return new Promise((resolve) => {
    apiQueue.push({ oui, resolve });
    processApiQueue();
  });
}

/**
 * Scans a specific IP for common open ports.
 * Multithreaded via async Promises.
 */
async function scanPorts(ip) {
  const openPorts = [];
  
  const checkPort = (port) => {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(300); // 300ms timeout for fast scanning
      
      socket.on('connect', () => {
        openPorts.push(port);
        socket.destroy();
        resolve();
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        resolve();
      });
      
      socket.on('error', () => {
        socket.destroy();
        resolve();
      });
      
      socket.connect(port, ip);
    });
  };

  if(!scanActive) return [];

  // Concurrently scan all common ports
  const promises = COMMON_PORTS.map(port => checkPort(port));
  await Promise.all(promises);
  
  return openPorts.sort((a,b) => a - b);
}

/**
 * Advanced OS Fingerprinting combining Port Heuristics + Vendor OUI
 */
function guessOS(ports, vendor) {
  const p = new Set(ports);

  // 1. Definitives based on distinct port signatures
  if (p.has(3389) || p.has(135) || p.has(139) || p.has(445)) {
    return 'Windows';
  }
  
  if (p.has(548) || (vendor === 'Apple, Inc.' && p.has(5900))) {
    return 'macOS';
  }

  // 2. Vendor Overrides
  if (vendor === 'Apple, Inc.') return 'iOS / macOS';
  if (vendor === 'Samsung Electronics' || vendor === 'Google, Inc.') return 'Android / ChromeOS';
  if (vendor === 'Raspberry Pi Foundation') return 'Linux (Raspbian)';
  
  // 3. Fallbacks
  if (p.has(22)) {
    return 'Linux / Unix';
  }

  return 'Unknown OS';
}

/**
 * Main Network Scanner Orchestrator
 * @param {string} subnet
 * @param {Function} onHostFoundCallback 
 * @param {Function} onCompleteCallback 
 */
export async function startNetworkScan(subnet, onHostFoundCallback, onCompleteCallback) {
  if (scanActive) return;
  scanActive = true;
  
  console.log(`Starting scan on subnet: ${subnet}0/24`);

  // Phase 1: Ping Sweep (Fast concurrent sweeps)
  const activeIps = [];
  const pingPromises = [];

  for (let i = 1; i < 255; i++) {
    if(!scanActive) break;
    const targetIp = subnet + i;
    
    // Spawn ping asynchronously
    pingPromises.push(
      ping.promise.probe(targetIp, { timeout: 1 }).then(res => {
        if (res.alive) activeIps.push(targetIp);
      })
    );
  }

  await Promise.all(pingPromises);
  if (!scanActive) return;

  // Phase 2: Resolve MACs from ARP Table
  const arpTable = await getArpTable();

  // Phase 3: Deep Scan Active Hosts Concurrently (Ports, Hostnames, OS)
  const hostPromises = activeIps.map(async (ip) => {
    if (!scanActive) return;

    let hostname = 'Unknown';
    try {
      const { hostnames } = await os.promises?.dns?.reverse(ip) || require('dns').promises.reverse(ip);
      if (hostnames && hostnames.length > 0) hostname = hostnames[0];
    } catch(e) {} // DNS Reverse failure is common/expected

    const mac = arpTable[ip] || null;
    
    // Phase 4: Identify Vendor & Scan Ports concurrently
    const [vendor, ports] = await Promise.all([
      getVendorFromMac(mac),
      scanPorts(ip)
    ]);
    
    const gOS = guessOS(ports, vendor);

    const hostData = {
      ip,
      mac,
      hostname,
      vendor,
      os: gOS,
      ports
    };

    if (scanActive) {
      onHostFoundCallback(hostData);
    }
  });

  await Promise.all(hostPromises);

  if (scanActive) {
    scanActive = false;
    onCompleteCallback({ message: `Scan complete. Found ${activeIps.length} active hosts.` });
  }
}

export function stopNetworkScan() {
  scanActive = false;
}
