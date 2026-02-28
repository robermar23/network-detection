import { describe, it, expect, vi, beforeEach } from 'vitest';
import { startRogueDnsDetection, stopRogueDnsDetection } from '../src/main/rogueDnsDetector.js';
import * as passiveCapture from '../src/main/passiveCapture.js';

vi.mock('../src/main/passiveCapture.js', () => ({
  startModule: vi.fn(),
  stopModule: vi.fn()
}));

describe('Rogue DNS Detector', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('startRogueDnsDetection', () => {
    it('should delegate to startModule with correct arguments', () => {
      passiveCapture.startModule.mockReturnValue(true);
      
      const onAlert = vi.fn();
      const onError = vi.fn();
      const onComplete = vi.fn();
      
      const result = startRogueDnsDetection('eth0', onAlert, onError, onComplete);
      
      expect(result).toBe(true);
      expect(passiveCapture.startModule).toHaveBeenCalledWith(
        'rogue-dns',
        'eth0',
        expect.arrayContaining(['-Y', 'dns.flags.response == 1 && dns.flags.rcode == 0']),
        expect.any(Function),
        onError,
        onComplete
      );
    });

    it('should parse tshark output and alert on first trusted server', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onAlert = vi.fn();
      startRogueDnsDetection('eth0', onAlert, vi.fn(), vi.fn());

      lineParser('8.8.8.8\t11:22:33:44:55:66\tgoogle.com\t142.250.190.46\t1');
      
      expect(onAlert).toHaveBeenCalledTimes(1);
      expect(onAlert).toHaveBeenCalledWith(expect.objectContaining({
        serverIp: '8.8.8.8',
        serverMac: '11:22:33:44:55:66',
        domain: 'google.com',
        resolvedIp: '142.250.190.46',
        isTrusted: true
      }));
    });

    it('should alert on rogue server after trusted server is established', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onAlert = vi.fn();
      startRogueDnsDetection('eth0', onAlert, vi.fn(), vi.fn());

      // Trusted
      lineParser('8.8.8.8\t11:22:33:44:55:66\tgoogle.com\t142.250.190.46\t1');
      // Rogue
      lineParser('10.0.0.1\tAA:BB:CC:DD:EE:FF\tgoogle.com\t6.6.6.6\t1');
      
      expect(onAlert).toHaveBeenCalledTimes(2);
      expect(onAlert).toHaveBeenNthCalledWith(2, expect.objectContaining({
        serverIp: '10.0.0.1',
        serverMac: 'aa:bb:cc:dd:ee:ff',
        domain: 'google.com',
        resolvedIp: '6.6.6.6',
        isTrusted: false
      }));
    });

    it('should extract first domain and IP if there are multiple comma-separated values', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onAlert = vi.fn();
      startRogueDnsDetection('eth0', onAlert, vi.fn(), vi.fn());

      lineParser('8.8.8.8,1.1.1.1\t11:22:33:44:55:66\tsite.com,api.site.com\t1.2.3.4,5.6.7.8\t2');
      
      expect(onAlert).toHaveBeenCalledWith(expect.objectContaining({
        serverIp: '8.8.8.8',
        domain: 'site.com',
        resolvedIp: '1.2.3.4,5.6.7.8'
      }));
    });

    it('should ignore lines missing IP or an A record answer', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onAlert = vi.fn();
      startRogueDnsDetection('eth0', onAlert, vi.fn(), vi.fn());

      // Missing A record answer (e.g. SRV answer)
      lineParser('8.8.8.8\t11:22:33:44:55:66\tsite.com\t\t1');
      
      expect(onAlert).not.toHaveBeenCalled();
    });
  });

  describe('stopRogueDnsDetection', () => {
    it('should call stopModule', () => {
      passiveCapture.stopModule.mockReturnValue(true);
      const res = stopRogueDnsDetection();
      expect(res).toBe(true);
      expect(passiveCapture.stopModule).toHaveBeenCalledWith('rogue-dns');
    });
  });
});
