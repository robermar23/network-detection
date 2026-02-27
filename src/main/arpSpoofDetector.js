import { startModule, stopModule } from './passiveCapture.js';

const MODULE_ID = 'arp';
const arpTable = new Map(); // IP -> MAC

export function startArpDetection(interfaceId, onAlert, onError, onComplete) {
  arpTable.clear();

  const tsharkArgs = [
    '-Y', 'arp.opcode == 2',
    '-T', 'fields',
    '-e', 'arp.src.proto_ipv4',
    '-e', 'arp.src.hw_mac',
    '-e', 'arp.dst.proto_ipv4',
    '-e', 'arp.dst.hw_mac'
  ];

  function onLineParsed(line) {
    const parts = line.split('\t').map(p => p.trim());
    if (parts.length >= 2) {
      const srcIp = parts[0].split(',')[0];
      const srcMac = parts[1].split(',')[0];
      const dstIp = parts[2] ? parts[2].split(',')[0] : '';

      if (!srcIp || !srcMac) return;

      const previousMac = arpTable.get(srcIp);
      arpTable.set(srcIp, srcMac);

      if (previousMac && previousMac !== srcMac) {
        // MAC changed for IP - Alert
        onAlert({
          ip: srcIp,
          previousMac,
          currentMac: srcMac,
          isGateway: false, // Will determine in main.js based on default gateway detection
          isGratuitous: false,
          severity: 'critical',
          timestamp: Date.now()
        });
      } else if (srcIp === dstIp) {
         // Gratuitous ARP (announcement)
         onAlert({
           ip: srcIp,
           previousMac: previousMac || srcMac,
           currentMac: srcMac,
           isGateway: false,
           isGratuitous: true,
           severity: 'warning',
           timestamp: Date.now()
         });
      }
    }
  }

  return startModule(MODULE_ID, interfaceId, tsharkArgs, onLineParsed, onError, onComplete);
}

export function stopArpDetection() {
  return stopModule(MODULE_ID);
}
