import { describe, it, expect } from 'vitest';
import { expandCIDR, vendorMap, COMMON_PORTS, ipRegex } from '../src/shared/networkConstants.js';

describe('Network Constants', () => {
  describe('vendorMap', () => {
    it('should be an object with known MAC OUI entries', () => {
      expect(typeof vendorMap).toBe('object');
      expect(vendorMap['00:0C:29']).toBe('VMware, Inc.');
      expect(vendorMap['B8:27:EB']).toBe('Raspberry Pi Foundation');
    });
  });

  describe('COMMON_PORTS', () => {
    it('should be a non-empty array of port numbers', () => {
      expect(Array.isArray(COMMON_PORTS)).toBe(true);
      expect(COMMON_PORTS.length).toBeGreaterThan(0);
      expect(COMMON_PORTS).toContain(80);
      expect(COMMON_PORTS).toContain(443);
      expect(COMMON_PORTS).toContain(22);
    });
  });

  describe('ipRegex', () => {
    it('should match valid IPv4 addresses', () => {
      expect(ipRegex.test('192.168.1.1')).toBe(true);
      expect(ipRegex.test('10.0.0.1')).toBe(true);
      expect(ipRegex.test('255.255.255.255')).toBe(true);
    });

    it('should reject invalid IP strings', () => {
      expect(ipRegex.test('not_an_ip')).toBe(false);
      expect(ipRegex.test('192.168.1')).toBe(false);
      expect(ipRegex.test('http://1.1.1.1')).toBe(false);
      expect(ipRegex.test('')).toBe(false);
    });
  });

  describe('expandCIDR', () => {
    it('should expand a /24 CIDR into 254 host addresses', () => {
      const ips = expandCIDR('192.168.1.0/24');
      expect(ips.length).toBe(254);
      expect(ips[0]).toBe('192.168.1.1');
      expect(ips[253]).toBe('192.168.1.254');
    });

    it('should expand a /30 CIDR into 2 host addresses', () => {
      const ips = expandCIDR('10.0.0.0/30');
      expect(ips.length).toBe(2);
      expect(ips[0]).toBe('10.0.0.1');
      expect(ips[1]).toBe('10.0.0.2');
    });

    it('should expand a /32 CIDR into 1 address', () => {
      const ips = expandCIDR('10.0.0.5/32');
      expect(ips.length).toBe(1);
      expect(ips[0]).toBe('10.0.0.5');
    });

    it('should expand a /31 CIDR into 2 addresses (point-to-point)', () => {
      const ips = expandCIDR('10.0.0.0/31');
      expect(ips.length).toBe(2);
      expect(ips[0]).toBe('10.0.0.0');
      expect(ips[1]).toBe('10.0.0.1');
    });

    it('should return empty array for invalid CIDR', () => {
      expect(expandCIDR('not_valid')).toEqual([]);
      expect(expandCIDR('192.168.1.0')).toEqual([]);      // no mask
      expect(expandCIDR('192.168.1.0/15')).toEqual([]);    // below /16
      expect(expandCIDR('192.168.1.0/33')).toEqual([]);    // above /32
      expect(expandCIDR('999.0.0.0/24')).toEqual([]);      // invalid octet
    });

    it('should handle /16 CIDR (large range, capped at 65536)', () => {
      const ips = expandCIDR('10.0.0.0/16');
      expect(ips.length).toBeLessThanOrEqual(65536);
      expect(ips.length).toBeGreaterThan(0);
      expect(ips[0]).toBe('10.0.0.1');
    });
  });
});
