import fs from 'fs';

/**
 * Parse an Nmap XML output file and extract host data.
 * Uses regex-based parsing to avoid external XML dependencies.
 * 
 * @param {string} filePath - Absolute path to the Nmap XML file
 * @returns {Array<Object>} Array of host objects compatible with state.hosts
 */
export function parseNmapXml(filePath) {
  const xml = fs.readFileSync(filePath, 'utf8');
  const hosts = [];

  // Split into <host>...</host> blocks
  const hostBlocks = xml.match(/<host[^>]*>[\s\S]*?<\/host>/gi);
  if (!hostBlocks) return hosts;

  for (const block of hostBlocks) {
    // Skip hosts that are "down"
    const statusMatch = block.match(/<status\s+state="([^"]+)"/i);
    if (statusMatch && statusMatch[1].toLowerCase() === 'down') continue;

    const host = {
      source: 'nmap-import',
      ports: [],
      deepAudit: null,
      nmapData: null
    };

    // Extract IP address
    const ipMatch = block.match(/<address\s+addr="([^"]+)"\s+addrtype="ipv4"/i);
    if (ipMatch) {
      host.ip = ipMatch[1];
    } else {
      // Try IPv6
      const ip6Match = block.match(/<address\s+addr="([^"]+)"\s+addrtype="ipv6"/i);
      if (ip6Match) host.ip = ip6Match[1];
    }

    if (!host.ip) continue; // Skip hosts without an IP

    // Extract MAC address  
    const macMatch = block.match(/<address\s+addr="([^"]+)"\s+addrtype="mac"(?:\s+vendor="([^"]*)")?/i);
    if (macMatch) {
      host.mac = macMatch[1];
      if (macMatch[2]) host.vendor = macMatch[2];
    }

    // Extract hostname
    const hostnameMatch = block.match(/<hostname\s+name="([^"]+)"/i);
    if (hostnameMatch) {
      host.hostname = hostnameMatch[1];
    }

    // Extract OS
    const osMatch = block.match(/<osmatch\s+name="([^"]+)"/i);
    if (osMatch) {
      host.os = osMatch[1].substring(0, 50);
    }

    // Extract open ports
    const portBlocks = block.match(/<port[^>]*>[\s\S]*?<\/port>/gi);
    if (portBlocks) {
      const portDetails = [];
      for (const portBlock of portBlocks) {
        const stateMatch = portBlock.match(/<state\s+state="([^"]+)"/i);
        if (!stateMatch || stateMatch[1] !== 'open') continue;

        const portIdMatch = portBlock.match(/portid="(\d+)"/i);
        const protocolMatch = portBlock.match(/protocol="([^"]+)"/i);
        const serviceMatch = portBlock.match(/<service\s+name="([^"]+)"/i);
        const productMatch = portBlock.match(/product="([^"]+)"/i);
        const versionMatch = portBlock.match(/version="([^"]+)"/i);

        if (portIdMatch) {
          const portNum = parseInt(portIdMatch[1], 10);
          host.ports.push(portNum);

          portDetails.push({
            port: portNum,
            protocol: protocolMatch ? protocolMatch[1] : 'tcp',
            service: serviceMatch ? serviceMatch[1] : 'unknown',
            product: productMatch ? productMatch[1] : '',
            version: versionMatch ? versionMatch[1] : ''
          });
        }
      }

      // Store raw port details in nmapData for deep inspection
      if (portDetails.length > 0) {
        host.nmapData = { importedPorts: portDetails };
      }
    }

    host.ports.sort((a, b) => a - b);
    hosts.push(host);
  }

  return hosts;
}
