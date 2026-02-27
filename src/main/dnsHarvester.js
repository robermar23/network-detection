import { startModule, stopModule } from './passiveCapture.js';

const MODULE_ID = 'dns';

export function startDnsHarvesting(interfaceId, onHostFound, onError, onComplete) {
  const tsharkArgs = [
    '-Y', 'dns.qry.name and (dns or mdns)',
    '-T', 'fields',
    '-e', 'dns.qry.name',
    '-e', 'dns.a',
    '-e', 'dns.aaaa',
    '-e', 'ip.src',
    '-e', 'dns.qry.type'
  ];

  function onLineParsed(line) {
    const parts = line.split('\t').map(p => p.trim());
    if (parts.length >= 1) {
      const hostname = parts[0].split(',')[0]; // Sometimes multiple queries, just take first
      const ipv4s = parts[1] ? parts[1].split(',').filter(Boolean) : [];
      const ipv6s = parts[2] ? parts[2].split(',').filter(Boolean) : [];
      const srcIp = parts[3] ? parts[3].split(',')[0] : '';
      const qryType = parts[4] ? parts[4].split(',')[0] : '';

      if (!hostname) return;

      const ips = [...new Set([...ipv4s, ...ipv6s])];
      
      // Determine source type roughly based on mdns presence or typical mdns query types, 
      // but without the 'mdns' field it's just a raw guess. 
      // We know it matched `(dns or mdns)`. `_udp.local` is a good mdns indicator.
      const querySource = hostname.endsWith('.local') ? 'mDNS' : 'DNS';

      onHostFound({
        hostname,
        resolvedIps: ips,
        queryType: qryType,
        querySource,
        srcIp,
        timestamp: Date.now()
      });
    }
  }

  return startModule(MODULE_ID, interfaceId, tsharkArgs, onLineParsed, onError, onComplete);
}

export function stopDnsHarvesting() {
  return stopModule(MODULE_ID);
}
