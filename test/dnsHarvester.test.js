import { describe, it, expect, vi, beforeEach } from 'vitest';
import { startDnsHarvesting, stopDnsHarvesting } from '../src/main/dnsHarvester.js';
import * as passiveCapture from '../src/main/passiveCapture.js';

vi.mock('../src/main/passiveCapture.js', () => ({
  startModule: vi.fn(),
  stopModule: vi.fn()
}));

describe('DNS Harvester', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('startDnsHarvesting', () => {
    it('should delegate to startModule with correct arguments', () => {
      passiveCapture.startModule.mockReturnValue(true);
      
      const onFound = vi.fn();
      const onError = vi.fn();
      const onComplete = vi.fn();
      
      const result = startDnsHarvesting('eth0', onFound, onError, onComplete);
      
      expect(result).toBe(true);
      expect(passiveCapture.startModule).toHaveBeenCalledWith(
        'dns',
        'eth0',
        expect.arrayContaining(['-Y', 'dns.qry.name and (dns or mdns)']),
        expect.any(Function),
        onError,
        onComplete
      );
    });

    it('should parse standard DNS query', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onFound = vi.fn();
      startDnsHarvesting('eth0', onFound, vi.fn(), vi.fn());

      // dns.qry.name \t dns.a \t dns.aaaa \t ip.src \t dns.qry.type
      lineParser('example.com\t93.184.216.34\t\t192.168.1.50\t1');
      
      expect(onFound).toHaveBeenCalledTimes(1);
      expect(onFound).toHaveBeenCalledWith(expect.objectContaining({
        hostname: 'example.com',
        resolvedIps: ['93.184.216.34'],
        queryType: '1',
        querySource: 'DNS',
        srcIp: '192.168.1.50'
      }));
    });

    it('should detect mDNS based on .local suffix', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onFound = vi.fn();
      startDnsHarvesting('eth0', onFound, vi.fn(), vi.fn());

      lineParser('printer.local\t192.168.1.100\t\t192.168.1.50\t1');
      
      expect(onFound).toHaveBeenCalledWith(expect.objectContaining({
        hostname: 'printer.local',
        querySource: 'mDNS'
      }));
    });

    it('should handle multiple resolved IPs and deduplicate', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onFound = vi.fn();
      startDnsHarvesting('eth0', onFound, vi.fn(), vi.fn());

      lineParser('pool.ntp.org\t1.1.1.1,2.2.2.2,1.1.1.1\t\t192.168.1.50\t1');
      
      expect(onFound).toHaveBeenCalledWith(expect.objectContaining({
        resolvedIps: ['1.1.1.1', '2.2.2.2']
      }));
    });

    it('should ignore lines without a hostname', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onFound = vi.fn();
      startDnsHarvesting('eth0', onFound, vi.fn(), vi.fn());

      lineParser('\t1.1.1.1\t\t192.168.1.50\t1');
      
      expect(onFound).not.toHaveBeenCalled();
    });
  });

  describe('stopDnsHarvesting', () => {
    it('should call stopModule', () => {
      passiveCapture.stopModule.mockReturnValue(true);
      const res = stopDnsHarvesting();
      expect(res).toBe(true);
      expect(passiveCapture.stopModule).toHaveBeenCalledWith('dns');
    });
  });
});
