import fs from 'fs';
import { XMLParser } from 'fast-xml-parser';

/**
 * Parse an Nmap XML output file and extract host data.
 * 
 * @param {string} filePath - Absolute path to the Nmap XML file
 * @returns {Array<Object>} Array of host objects compatible with state.hosts
 */
export function parseNmapXml(filePath) {
  const xml = fs.readFileSync(filePath, 'utf8');
  
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    allowBooleanAttributes: true,
    isArray: (name, jpath, isLeafNode, isAttribute) => { 
      const arrayNodes = ['nmaprun.host', 'nmaprun.host.ports.port', 'nmaprun.host.address', 'nmaprun.host.hostnames.hostname', 'nmaprun.host.os.osmatch'];
      return arrayNodes.indexOf(jpath) !== -1;
    }
  });

  let jsonObj;
  try {
    jsonObj = parser.parse(xml);
  } catch (err) {
    console.error('Failed to parse Nmap XML:', err);
    return [];
  }

  const hosts = [];
  const nmaprun = jsonObj.nmaprun;
  if (!nmaprun || !nmaprun.host) return hosts;

  for (const h of nmaprun.host) {
    // Skip hosts that are "down"
    if (h.status && h.status['@_state'] && h.status['@_state'].toLowerCase() === 'down') continue;

    const host = {
      source: 'nmap-import',
      ports: [],
      deepAudit: null,
      nmapData: null
    };

    // Extract addresses (IP, MAC)
    let addresses = h.address || [];
    if (!Array.isArray(addresses)) addresses = [addresses];

    for (const addr of addresses) {
      if (addr['@_addrtype'] === 'ipv4' || addr['@_addrtype'] === 'ipv6') {
        if (!host.ip) host.ip = addr['@_addr']; // Prioritize first found IP
      } else if (addr['@_addrtype'] === 'mac') {
        host.mac = addr['@_addr'];
        if (addr['@_vendor']) host.vendor = addr['@_vendor'];
      }
    }

    if (!host.ip) continue;

    // Extract hostname
    let hostnames = h.hostnames?.hostname || [];
    if (!Array.isArray(hostnames)) hostnames = [hostnames];
    if (hostnames.length > 0 && hostnames[0]['@_name']) {
        host.hostname = hostnames[0]['@_name'];
    }

    // Extract OS
    let osmatches = h.os?.osmatch || [];
    if (!Array.isArray(osmatches)) osmatches = [osmatches];
    if (osmatches.length > 0 && osmatches[0]['@_name']) {
       host.os = osmatches[0]['@_name'].substring(0, 50);
    }

    // Extract Ports
    let xmlPorts = h.ports?.port || [];
    if (!Array.isArray(xmlPorts)) xmlPorts = [xmlPorts];
    const portDetails = [];

    for (const p of xmlPorts) {
       if (p.state && p.state['@_state'] === 'open' && p['@_portid']) {
          const portNum = parseInt(p['@_portid'], 10);
          host.ports.push(portNum);

          portDetails.push({
             port: portNum,
             protocol: p['@_protocol'] || 'tcp',
             service: p.service ? (p.service['@_name'] || 'unknown') : 'unknown',
             product: p.service ? (p.service['@_product'] || '') : '',
             version: p.service ? (p.service['@_version'] || '') : ''
          });
       }
    }

    if (portDetails.length > 0) {
       host.nmapData = { importedPorts: portDetails };
    }

    host.ports.sort((a, b) => a - b);
    hosts.push(host);
  }

  return hosts;
}
