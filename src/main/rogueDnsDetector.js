import { startModule, stopModule } from './passiveCapture.js';

const trustedDnsServers = new Set();
const MODULE_ID = 'rogue-dns';

/*
  Format from tshark fields:
  ip.src | eth.src | dns.qry.name | dns.a | dns.flags.rcode | dns.count.answers
*/
export function startRogueDnsDetection(interfaceId, onAlert, onError, onComplete) {
  trustedDnsServers.clear(); // Reset on start

  const tsharkArgs = [
    '-Y', 'dns.flags.response == 1 && dns.flags.rcode == 0', // Success DNS responses
    '-T', 'fields',
    '-e', 'ip.src',
    '-e', 'eth.src',
    '-e', 'dns.qry.name',
    '-e', 'dns.a',
    '-e', 'dns.count.answers'
  ];

  function onLineParsed(line) {
    if (!line.trim()) return;

    // tshark tab separator
    const parts = line.split('\t');
    if (parts.length < 5) return;

    const [ipSrc, ethSrc, qryName, aRecord, answerCount] = parts;

    // We only care about valid IPs and MACs
    const serverIp = ipSrc?.split(',')[0] || '';
    const serverMac = (ethSrc || '').toLowerCase();
    
    // Some DNS packets might have empty answers or A records (e.g. SRV queries)
    if (!serverIp || !aRecord) return;

    // Extract first domain and A record nicely if multiple
    const queryArray = qryName.split(',');
    const domain = queryArray[0];

    // Mark first seen server as trusted
    if (trustedDnsServers.size === 0) {
      trustedDnsServers.add(serverIp);
      onAlert({
        serverIp,
        serverMac,
        domain,
        resolvedIp: aRecord,
        isTrusted: true,
        timestamp: new Date().toISOString()
      });
      return;
    }

    const isTrusted = trustedDnsServers.has(serverIp);
    
    // If not trusted, we alert immediately as rogue
    if (!isTrusted) {
      onAlert({
        serverIp,
        serverMac,
        domain,
        resolvedIp: aRecord,
        isTrusted: false,
        timestamp: new Date().toISOString()
      });
    }
  }

  return startModule(MODULE_ID, interfaceId, tsharkArgs, onLineParsed, onError, onComplete);
}

export function stopRogueDnsDetection() {
  return stopModule(MODULE_ID);
}
