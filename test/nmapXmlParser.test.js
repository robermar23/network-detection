import { describe, it, expect, vi, beforeEach } from 'vitest';
import { parseNmapXml } from '../src/main/nmapXmlParser.js';
import fs from 'fs';

vi.mock('fs', () => ({
  default: {
    readFileSync: vi.fn()
  },
  readFileSync: vi.fn()
}));

describe('Nmap XML Parser', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const makeXml = (hostBlock) => `<?xml version="1.0"?>
<nmaprun><host>${hostBlock}</host></nmaprun>`;

  it('should parse a single host with IP, ports, and hostname', () => {
    const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TestVendor"/>
    <hostnames><hostname name="myhost.local"/></hostnames>
    <os><osmatch name="Linux 5.4 - 5.15 this is a very long OS string that goes beyond fifty characters here"/></os>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>
      <port protocol="tcp" portid="443"><state state="closed"/></port>
    </ports>
  </host>
</nmaprun>`;

    fs.readFileSync.mockReturnValue(xml);
    const hosts = parseNmapXml('/fake/path.xml');

    expect(hosts.length).toBe(1);
    expect(hosts[0].ip).toBe('192.168.1.10');
    expect(hosts[0].mac).toBe('AA:BB:CC:DD:EE:FF');
    expect(hosts[0].vendor).toBe('TestVendor');
    expect(hosts[0].hostname).toBe('myhost.local');
    expect(hosts[0].os.length).toBeLessThanOrEqual(50);
    expect(hosts[0].ports).toContain(22);
    expect(hosts[0].ports).toContain(80);
    expect(hosts[0].ports).not.toContain(443); // closed port
    expect(hosts[0].source).toBe('nmap-import');
    expect(hosts[0].nmapData.importedPorts.length).toBe(2);
    expect(hosts[0].nmapData.importedPorts[0].service).toBe('ssh');
    expect(hosts[0].nmapData.importedPorts[0].product).toBe('OpenSSH');
    expect(hosts[0].nmapData.importedPorts[0].version).toBe('8.9');
  });

  it('should skip hosts that are down', () => {
    const xml = `<?xml version="1.0"?>
<nmaprun>
  <host><status state="down"/><address addr="10.0.0.5" addrtype="ipv4"/></host>
  <host><status state="up"/><address addr="10.0.0.6" addrtype="ipv4"/></host>
</nmaprun>`;

    fs.readFileSync.mockReturnValue(xml);
    const hosts = parseNmapXml('/fake/path.xml');
    expect(hosts.length).toBe(1);
    expect(hosts[0].ip).toBe('10.0.0.6');
  });

  it('should skip hosts with no IP address', () => {
    const xml = `<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/></host>
</nmaprun>`;

    fs.readFileSync.mockReturnValue(xml);
    const hosts = parseNmapXml('/fake/path.xml');
    expect(hosts.length).toBe(0);
  });

  it('should return empty array for invalid XML', () => {
    fs.readFileSync.mockReturnValue('<invalid><<<xml');
    const hosts = parseNmapXml('/fake/path.xml');
    expect(hosts).toEqual([]);
  });

  it('should return empty array when nmaprun has no host data', () => {
    fs.readFileSync.mockReturnValue(`<?xml version="1.0"?><nmaprun></nmaprun>`);
    const hosts = parseNmapXml('/fake/path.xml');
    expect(hosts).toEqual([]);
  });

  it('should handle host with no ports', () => {
    const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
  </host>
</nmaprun>`;

    fs.readFileSync.mockReturnValue(xml);
    const hosts = parseNmapXml('/fake/path.xml');
    expect(hosts.length).toBe(1);
    expect(hosts[0].ports).toEqual([]);
    expect(hosts[0].nmapData).toBeNull();
  });

  it('should handle port with no service info', () => {
    const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="9999"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>`;

    fs.readFileSync.mockReturnValue(xml);
    const hosts = parseNmapXml('/fake/path.xml');
    expect(hosts[0].nmapData.importedPorts[0].service).toBe('unknown');
    expect(hosts[0].nmapData.importedPorts[0].product).toBe('');
    expect(hosts[0].nmapData.importedPorts[0].version).toBe('');
  });

  it('should sort ports numerically', () => {
    const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.3" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    </ports>
  </host>
</nmaprun>`;

    fs.readFileSync.mockReturnValue(xml);
    const hosts = parseNmapXml('/fake/path.xml');
    expect(hosts[0].ports).toEqual([22, 80, 443]);
  });
});
