import { describe, it, expect, vi, beforeEach } from 'vitest';
import { startArpDetection, stopArpDetection } from '../src/main/arpSpoofDetector.js';
import * as passiveCapture from '../src/main/passiveCapture.js';

vi.mock('../src/main/passiveCapture.js', () => ({
  startModule: vi.fn(),
  stopModule: vi.fn()
}));

describe('ARP Spoofing Detector', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('startArpDetection', () => {
    it('should delegate to startModule with correct arguments', () => {
      passiveCapture.startModule.mockReturnValue(true);
      
      const onAlert = vi.fn();
      const onError = vi.fn();
      const onComplete = vi.fn();
      
      const result = startArpDetection('eth0', onAlert, onError, onComplete);
      
      expect(result).toBe(true);
      expect(passiveCapture.startModule).toHaveBeenCalledWith(
        'arp',
        'eth0',
        expect.arrayContaining(['-Y', 'arp.opcode == 2']),
        expect.any(Function),
        onError,
        onComplete
      );
    });

    it('should populate ARP table and not alert on first MAC binding', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onAlert = vi.fn();
      startArpDetection('eth0', onAlert, vi.fn(), vi.fn());

      // Normal ARP Reply
      // src.ipv4 \t src.mac \t dst.ipv4 \t dst.mac
      lineParser('192.168.1.1\tAA:BB:CC:DD:EE:FF\t192.168.1.50\t11:22:33:44:55:66');
      
      expect(onAlert).not.toHaveBeenCalled();
    });

    it('should alert when MAC address changes for a known IP', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onAlert = vi.fn();
      startArpDetection('eth0', onAlert, vi.fn(), vi.fn());

      // Initial binding
      lineParser('192.168.1.1\tAA:BB:CC:DD:EE:FF\t192.168.1.50\t11:22:33:44:55:66');
      
      // Spoofing packet!
      lineParser('192.168.1.1\tDE:AD:BE:EF:00:00\t192.168.1.50\t11:22:33:44:55:66');
      
      expect(onAlert).toHaveBeenCalledTimes(1);
      expect(onAlert).toHaveBeenCalledWith(expect.objectContaining({
        ip: '192.168.1.1',
        previousMac: 'AA:BB:CC:DD:EE:FF',
        currentMac: 'DE:AD:BE:EF:00:00',
        severity: 'critical'
      }));
    });

    it('should generate a warning for gratuitous ARP (src IP == dst IP)', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onAlert = vi.fn();
      startArpDetection('eth0', onAlert, vi.fn(), vi.fn());

      // Gratuitous ARP announcement
      lineParser('192.168.1.150\t77:88:99:AA:BB:CC\t192.168.1.150\tFF:FF:FF:FF:FF:FF');
      
      expect(onAlert).toHaveBeenCalledTimes(1);
      expect(onAlert).toHaveBeenCalledWith(expect.objectContaining({
        ip: '192.168.1.150',
        currentMac: '77:88:99:AA:BB:CC',
        isGratuitous: true,
        severity: 'warning'
      }));
    });

    it('should ignore short lines missing IP or MAC', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onAlert = vi.fn();
      startArpDetection('eth0', onAlert, vi.fn(), vi.fn());

      lineParser('192.168.1.1\t'); // Missing MAC
      lineParser('\tAA:BB:CC:DD:EE:FF'); // Missing IP
      
      expect(onAlert).not.toHaveBeenCalled();
    });
  });

  describe('stopArpDetection', () => {
    it('should call stopModule', () => {
      passiveCapture.stopModule.mockReturnValue(true);
      const res = stopArpDetection();
      expect(res).toBe(true);
      expect(passiveCapture.stopModule).toHaveBeenCalledWith('arp');
    });
  });
});
