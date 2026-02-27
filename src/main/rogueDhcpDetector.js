import { startModule, stopModule } from './passiveCapture.js';

let trustedServers = new Set();
const MODULE_ID = 'dhcp';

export function startDhcpDetection(interfaceId, onAlert, onError, onComplete) {
  // Clear trusted servers on new capture session
  trustedServers.clear();

  const tsharkArgs = [
    '-Y', 'dhcp.type == 2 or dhcp.type == 5',
    '-T', 'fields',
    '-e', 'ip.src',
    '-e', 'eth.src',
    '-e', 'dhcp.option.dhcp_server_id',
    '-e', 'dhcp.option.router',
    '-e', 'dhcp.option.domain_name_server',
    '-e', 'dhcp.option.subnet_mask'
  ];

  function onLineParsed(line) {
    const parts = line.split('\t').map(p => p.trim());
    if (parts.length >= 2) {
      const srcIp = parts[0].split(',')[0];
      const srcMac = parts[1].split(',')[0];
      const serverId = parts[2] ? parts[2].split(',')[0] : srcIp;
      const router = parts[3] ? parts[3].split(',')[0] : '';
      const dns = parts[4] || '';
      const subnetMask = parts[5] || '';

      if (!srcIp) return;

      const isTrusted = trustedServers.size === 0 || trustedServers.has(serverId);
      if (trustedServers.size === 0) {
        trustedServers.add(serverId);
      }

      onAlert({
        serverIp: serverId,
        serverMac: srcMac,
        offeredRouter: router,
        offeredDns: dns,
        offeredSubnet: subnetMask,
        isTrusted,
        timestamp: Date.now()
      });
    }
  }

  return startModule(MODULE_ID, interfaceId, tsharkArgs, onLineParsed, onError, onComplete);
}

export function stopDhcpDetection() {
  return stopModule(MODULE_ID);
}
