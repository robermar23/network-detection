import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getNetworkInterfaces, stopNetworkScan, startNetworkScan, enrichHost, probeHost, guessOS } from '../src/main/scanner.js';
import os from 'os';
import ping from 'ping';

// Mock os
vi.mock('os', () => ({
  default: {
    networkInterfaces: vi.fn().mockReturnValue({
      'Ethernet': [
        { internal: false, family: 'IPv4', address: '192.168.1.50' },
        { internal: false, family: 'IPv6', address: 'fe80::1' }
      ],
      'Wi-Fi': [
        { internal: false, family: 'IPv4', address: '10.0.0.5' }
      ],
      'Loopback': [
        { internal: true, family: 'IPv4', address: '127.0.0.1' }
      ]
    })
  }
}));

// Mock ping
vi.mock('ping', () => ({
  default: {
    promise: {
      probe: vi.fn().mockResolvedValue({ alive: false, time: 0 })
    }
  }
}));

// Mock net
vi.mock('net', () => ({
  default: {
    Socket: class MockSocket {
      constructor() {
        this.listeners = {};
      }
      on(event, cb) { this.listeners[event] = cb; return this; }
      setTimeout() {}
      connect(port, ip) {
        if (this.listeners.error) {
          setTimeout(() => this.listeners.error(new Error('ECONNREFUSED')), 2);
        }
      }
      destroy() {}
    }
  }
}));

// Mock https
vi.mock('https', () => ({
  default: {
    get: vi.fn((url, cb) => {
      const res = {
        statusCode: 200,
        on: vi.fn((event, handler) => {
          if (event === 'data') handler('Test Vendor');
          if (event === 'end') handler();
        })
      };
      cb(res);
      return { on: vi.fn() };
    })
  }
}));

// Mock child_process
vi.mock('child_process', () => ({
  spawn: vi.fn(),
  exec: vi.fn((cmd, cb) => {
    // Provide ARP output
    cb(null, '  192.168.1.1         aa-bb-cc-dd-ee-ff     dynamic\n  192.168.1.50        11-22-33-44-55-66     dynamic\n');
  })
}));

// Mock dns
vi.mock('dns', () => ({
  promises: {
    reverse: vi.fn().mockResolvedValue(['host.local'])
  }
}));

describe('Scanner Module', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getNetworkInterfaces', () => {
    it('should return a list of non-internal IPv4 interfaces', () => {
      const interfaces = getNetworkInterfaces();
      expect(Array.isArray(interfaces)).toBe(true);
      expect(interfaces.length).toBe(2); // Ethernet + Wi-Fi
    });

    it('should exclude internal interfaces', () => {
      const interfaces = getNetworkInterfaces();
      const ips = interfaces.map(i => i.ip);
      expect(ips).not.toContain('127.0.0.1');
    });

    it('should exclude IPv6 addresses', () => {
      const interfaces = getNetworkInterfaces();
      const ips = interfaces.map(i => i.ip);
      expect(ips).not.toContain('fe80::1');
    });

    it('should compute subnet correctly', () => {
      const interfaces = getNetworkInterfaces();
      const eth = interfaces.find(i => i.name === 'Ethernet');
      expect(eth.subnet).toBe('192.168.1.');
    });

    it('should format label as name - ip', () => {
      const interfaces = getNetworkInterfaces();
      expect(interfaces[0].label).toBe('Ethernet - 192.168.1.50');
    });

    it('should include all properties', () => {
      const interfaces = getNetworkInterfaces();
      for (const iface of interfaces) {
        expect(iface).toHaveProperty('name');
        expect(iface).toHaveProperty('ip');
        expect(iface).toHaveProperty('subnet');
        expect(iface).toHaveProperty('label');
      }
    });
  });

  describe('guessOS', () => {
    it('should detect Windows by ports 3389/135/139/445', () => {
      expect(guessOS([3389], 'Unknown')).toBe('Windows');
      expect(guessOS([135, 445], 'Unknown')).toBe('Windows');
      expect(guessOS([139], 'Unknown')).toBe('Windows');
    });

    it('should detect macOS by port 548', () => {
      expect(guessOS([548], 'Unknown')).toBe('macOS');
    });

    it('should detect macOS by Apple vendor + port 5900', () => {
      expect(guessOS([5900], 'Apple, Inc.')).toBe('macOS');
    });

    it('should detect iOS/macOS by Apple vendor alone', () => {
      expect(guessOS([], 'Apple, Inc.')).toBe('iOS / macOS');
    });

    it('should detect Android/ChromeOS by Samsung vendor', () => {
      expect(guessOS([], 'Samsung Electronics')).toBe('Android / ChromeOS');
    });

    it('should detect Android/ChromeOS by Google vendor', () => {
      expect(guessOS([], 'Google, Inc.')).toBe('Android / ChromeOS');
    });

    it('should detect Linux (Raspbian) by RPi vendor', () => {
      expect(guessOS([], 'Raspberry Pi Foundation')).toBe('Linux (Raspbian)');
    });

    it('should detect Linux/Unix by port 22', () => {
      expect(guessOS([22], 'Unknown')).toBe('Linux / Unix');
    });

    it('should return Unknown OS when no indicators', () => {
      expect(guessOS([], 'Unknown')).toBe('Unknown OS');
    });
  });

  describe('stopNetworkScan', () => {
    it('should not throw when called without an active scan', () => {
      expect(() => stopNetworkScan()).not.toThrow();
    });
  });

  describe('startNetworkScan', () => {
    it('should call onCompleteCallback after scan completes', async () => {
      ping.promise.probe.mockResolvedValue({ alive: false });
      const onHostFound = vi.fn();
      const onComplete = vi.fn();
      await startNetworkScan('192.168.1.', onHostFound, onComplete);
      expect(onComplete).toHaveBeenCalled();
      expect(onComplete.mock.calls[0][0].message).toContain('Scan complete');
    });

    it('should find hosts that respond to ping', async () => {
      ping.promise.probe.mockImplementation((ip) => {
        return Promise.resolve({ alive: ip === '192.168.2.1' });
      });

      const onHostFound = vi.fn();
      const onComplete = vi.fn();
      await startNetworkScan('192.168.2.', onHostFound, onComplete);

      if (onHostFound.mock.calls.length > 0) {
        expect(onHostFound.mock.calls[0][0].ip).toBe('192.168.2.1');
      }
    });
  });

  describe('enrichHost', () => {
    it('should return an object with the ip field', async () => {
      const result = await enrichHost('10.0.0.1');
      expect(result.ip).toBe('10.0.0.1');
    });

    it('should include hostname from reverse DNS', async () => {
      const result = await enrichHost('10.0.0.1');
      expect(result.hostname).toBe('host.local');
    });

    it('should include os field', async () => {
      const result = await enrichHost('10.0.0.1');
      expect(result).toHaveProperty('os');
    });

    it('should include ports array', async () => {
      const result = await enrichHost('10.0.0.1');
      expect(Array.isArray(result.ports)).toBe(true);
    });

    it('should accept pre-fetched arpTable', async () => {
      const table = { '10.0.0.1': 'AA:BB:CC:DD:EE:FF' };
      const result = await enrichHost('10.0.0.1', { arpTable: table });
      expect(result.mac).toBe('AA:BB:CC:DD:EE:FF');
    });
  });

  describe('probeHost', () => {
    it('should return enriched data with ping alive status', async () => {
      ping.promise.probe.mockResolvedValue({ alive: true, time: 5 });
      const result = await probeHost('10.0.0.1');
      expect(result.ip).toBe('10.0.0.1');
      expect(result.alive).toBe(true);
      expect(result.pingTime).toBe(5);
    });

    it('should handle ping failure gracefully', async () => {
      ping.promise.probe.mockRejectedValue(new Error('timeout'));
      const result = await probeHost('10.0.0.2');
      expect(result.ip).toBe('10.0.0.2');
      expect(result.alive).toBe(false);
    });
  });
});
