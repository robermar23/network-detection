import { describe, it, expect, vi, beforeEach } from 'vitest';
import { startDhcpDetection, stopDhcpDetection } from '../src/main/rogueDhcpDetector.js';
import * as passiveCapture from '../src/main/passiveCapture.js';

vi.mock('../src/main/passiveCapture.js', () => ({
  startModule: vi.fn(),
  stopModule: vi.fn()
}));

describe('Rogue DHCP Detector', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('startDhcpDetection', () => {
    it('should delegate to startModule with correct arguments', () => {
      passiveCapture.startModule.mockReturnValue(true);
      
      const onAlert = vi.fn();
      const onError = vi.fn();
      const onComplete = vi.fn();
      
      const result = startDhcpDetection('eth0', onAlert, onError, onComplete);
      
      expect(result).toBe(true);
      expect(passiveCapture.startModule).toHaveBeenCalledWith(
        'dhcp',
        'eth0',
        expect.arrayContaining(['-Y', 'dhcp.type == 2 or dhcp.type == 5']),
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
      startDhcpDetection('eth0', onAlert, vi.fn(), vi.fn());

      lineParser('192.168.1.1\tAA:BB:CC:DD:EE:FF\t192.168.1.1\t192.168.1.1\t8.8.8.8\t255.255.255.0');
      
      expect(onAlert).toHaveBeenCalledTimes(1);
      expect(onAlert).toHaveBeenCalledWith(expect.objectContaining({
        serverIp: '192.168.1.1',
        serverMac: 'AA:BB:CC:DD:EE:FF',
        offeredRouter: '192.168.1.1',
        offeredDns: '8.8.8.8',
        offeredSubnet: '255.255.255.0',
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
      startDhcpDetection('eth0', onAlert, vi.fn(), vi.fn());

      // Trusted
      lineParser('192.168.1.1\tAA:BB:CC:DD:EE:FF\t192.168.1.1\t\t');
      // Rogue
      lineParser('10.0.0.1\t11:22:33:44:55:66\t10.0.0.1\t\t');
      
      expect(onAlert).toHaveBeenCalledTimes(2);
      expect(onAlert).toHaveBeenNthCalledWith(2, expect.objectContaining({
        serverIp: '10.0.0.1',
        serverMac: '11:22:33:44:55:66',
        isTrusted: false
      }));
    });

    it('should handle missing server_id by falling back to ip.src', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onAlert = vi.fn();
      startDhcpDetection('eth0', onAlert, vi.fn(), vi.fn());

      // Missing server_id field
      lineParser('192.168.1.2\tAA:BB:CC:DD:EE:FF\t\t192.168.1.2\t\t');
      
      expect(onAlert).toHaveBeenCalledWith(expect.objectContaining({
        serverIp: '192.168.1.2'
      }));
    });

    it('should ignore short lines', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onAlert = vi.fn();
      startDhcpDetection('eth0', onAlert, vi.fn(), vi.fn());

      lineParser('192.168.1.2'); // Missing mac length=1
      
      expect(onAlert).not.toHaveBeenCalled();
    });
  });

  describe('stopDhcpDetection', () => {
    it('should call stopModule', () => {
      passiveCapture.stopModule.mockReturnValue(true);
      const res = stopDhcpDetection();
      expect(res).toBe(true);
      expect(passiveCapture.stopModule).toHaveBeenCalledWith('dhcp');
    });
  });
});
