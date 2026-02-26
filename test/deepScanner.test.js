import { describe, it, expect, vi, beforeEach } from 'vitest';
import { cancelDeepScan, analyzeService, grabBanner, grabTlsCert } from '../src/main/deepScanner.js';
import net from 'net';
import tls from 'tls';

vi.mock('net', () => ({
  default: {
    Socket: class MockSocket {
      constructor() {
        this.listeners = {};
        this._connected = false;
      }
      on(event, cb) { this.listeners[event] = cb; return this; }
      setTimeout() {}
      removeAllListeners() {}
      write() {}
      connect(port, ip) {
        if (port === 80) {
          // Simulate connect -> HTTP banner
          setTimeout(() => {
            if (this.listeners.connect) this.listeners.connect();
            if (this.listeners.data) {
              this.listeners.data(Buffer.from('HTTP/1.1 200 OK\r\nServer: nginx\r\n'));
            }
          }, 5);
        } else if (port === 22) {
          // Simulate SSH connect -> SSH banner
          setTimeout(() => {
            if (this.listeners.connect) this.listeners.connect();
            if (this.listeners.data) {
              this.listeners.data(Buffer.from('SSH-2.0-OpenSSH_8.9'));
            }
          }, 5);
        } else if (port === 9999) {
          // Simulate timeout
          setTimeout(() => {
            if (this.listeners.timeout) this.listeners.timeout();
          }, 5);
        } else if (port === 8888) {
          // Simulate error
          setTimeout(() => {
            if (this.listeners.error) this.listeners.error(new Error('ECONNREFUSED'));
          }, 5);
        } else {
          setTimeout(() => {
            if (this.listeners.error) this.listeners.error(new Error('mock'));
          }, 5);
        }
      }
      destroy() {}
    }
  }
}));

vi.mock('tls', () => ({
  default: {
    connect: vi.fn((opts, cb) => {
      const sock = {
        setTimeout: vi.fn(),
        on: vi.fn((event, handler) => {
          if (event === 'error') {
            // Only trigger error for specific ports
            if (opts.port === 7777) {
              setTimeout(() => handler(new Error('TLS error')), 5);
            }
          }
          if (event === 'timeout') {
            if (opts.port === 6666) {
              setTimeout(() => handler(), 5);
            }
          }
        }),
        getPeerCertificate: vi.fn().mockReturnValue({
          subject: { CN: 'example.com' },
          issuer: { CN: 'CA Authority' },
          valid_from: '2024-01-01',
          valid_to: '2026-12-31'
        }),
        end: vi.fn(),
        destroy: vi.fn()
      };
      // Call cb on connect (for valid ports)
      if (opts.port !== 7777 && opts.port !== 6666) {
        setTimeout(() => cb(), 5);
      }
      return sock;
    })
  }
}));

vi.mock('../src/main/securityAnalyzer.js', () => ({
  checkAnonymousFtp: vi.fn().mockResolvedValue(null),
  checkSensitiveWebDirs: vi.fn().mockResolvedValue({ vulnerable: false, details: '' })
}));

describe('Deep Scanner Module', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('cancelDeepScan', () => {
    it('should safely accept cancellation for an explicit IP', () => {
      expect(() => cancelDeepScan('10.0.0.1')).not.toThrow();
    });
    it('should handle cancellation for IPs not in the active scan pool', () => {
      expect(() => cancelDeepScan('255.255.255.255')).not.toThrow();
    });
    it('should be callable multiple times for the same IP', () => {
      expect(() => { cancelDeepScan('10.0.0.1'); cancelDeepScan('10.0.0.1'); }).not.toThrow();
    });
  });

  describe('grabBanner', () => {
    it('should return banner text when port responds with data', async () => {
      const banner = await grabBanner('127.0.0.1', 80);
      expect(banner).toContain('HTTP/1.1');
    });

    it('should return SSH banner from port 22', async () => {
      const banner = await grabBanner('127.0.0.1', 22);
      expect(banner).toContain('SSH-2.0');
    });

    it('should return null on timeout', async () => {
      const result = await grabBanner('127.0.0.1', 9999);
      expect(result).toBeNull();
    });

    it('should return null on error', async () => {
      const result = await grabBanner('127.0.0.1', 8888);
      expect(result).toBeNull();
    });
  });

  describe('grabTlsCert', () => {
    it('should return certificate info from a TLS connection', async () => {
      const cert = await grabTlsCert('127.0.0.1', 443);
      expect(cert).toBeDefined();
      expect(cert.subject).toBe('example.com');
      expect(cert.issuer).toBe('CA Authority');
      expect(cert.validFrom).toBe('2024-01-01');
      expect(cert.validTo).toBe('2026-12-31');
    });

    it('should return null on TLS error', async () => {
      const cert = await grabTlsCert('127.0.0.1', 7777);
      expect(cert).toBeNull();
    });

    it('should return null on TLS timeout', async () => {
      const cert = await grabTlsCert('127.0.0.1', 6666);
      expect(cert).toBeNull();
    });
  });

  describe('analyzeService', () => {
    it('should identify TLS/SSL service from cert', () => {
      const cert = { subject: 'example.com', issuer: 'CA', validTo: '2026-12-31T23:59:59' };
      const result = analyzeService(443, null, cert);
      expect(result.serviceName).toBe('TLS/SSL Service');
      expect(result.details).toContain('example.com');
      expect(result.details).toContain('Expiration');
    });

    it('should handle TLS cert without validTo', () => {
      const cert = { subject: 'test', issuer: 'issuer' };
      const result = analyzeService(443, null, cert);
      expect(result.details).not.toContain('Expiration');
    });

    it('should identify HTTP web server from Server header', () => {
      const banner = 'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n';
      const result = analyzeService(80, banner, null);
      expect(result.serviceName).toBe('HTTP Web Server');
    });

    it('should identify SSH server from banner', () => {
      const result = analyzeService(22, 'SSH-2.0-OpenSSH_8.9p1', null);
      expect(result.serviceName).toBe('SSH Server');
    });

    it('should identify SMTP from 220 banner', () => {
      const result = analyzeService(25, '220 mail.example.com ESMTP', null);
      expect(result.serviceName).toBe('SMTP Mail Server');
    });

    it('should identify FTP server from banner', () => {
      const result = analyzeService(21, 'ProFTPD 1.3.6 Ready', null);
      expect(result.serviceName).toBe('FTP Server');
    });

    it('should identify FTP server from vsFTPd banner', () => {
      const result = analyzeService(21, 'Welcome to the vsFTPd server', null);
      expect(result.serviceName).toBe('FTP Server');
    });

    it('should detect HTTP redirect', () => {
      const banner = 'HTTP/1.1 301 Moved\r\nLocation: https://example.com\r\n';
      const result = analyzeService(80, banner, null);
      expect(result.details).toContain('Redirects to');
    });

    it('should detect unrecognized web service from HTML', () => {
      const banner = 'HTTP/1.1 200 OK\r\n\r\n<html><body>Hello</body></html>';
      const result = analyzeService(80, banner, null);
      expect(result.serviceName).toBe('Web Service (Unrecognized)');
    });

    it('should identify custom service from unknown banner', () => {
      const result = analyzeService(9999, 'CUSTOM_PROTOCOL v2.1', null);
      expect(result.serviceName).toBe('Custom Service');
    });

    // Port guessing
    it('should guess Telnet for port 23 (vulnerable)', () => {
      const result = analyzeService(23, null, null);
      expect(result.vulnerable).toBe(true);
      expect(result.severity).toBe('critical');
    });

    it('should guess DNS for port 53', () => {
      const result = analyzeService(53, null, null);
      expect(result.serviceName).toContain('DNS');
    });

    // Database ports
    it('should flag MySQL 3306', () => {
      expect(analyzeService(3306, null, null).vulnerable).toBe(true);
    });
    it('should flag SQL Server 1433', () => {
      expect(analyzeService(1433, null, null).vulnerable).toBe(true);
    });
    it('should flag MongoDB 27017', () => {
      expect(analyzeService(27017, null, null).vulnerable).toBe(true);
    });
    it('should flag Redis 6379', () => {
      expect(analyzeService(6379, null, null).vulnerable).toBe(true);
    });
    it('should flag PostgreSQL 5432', () => {
      expect(analyzeService(5432, null, null).vulnerable).toBe(true);
    });

    it('should return unknown for unrecognized port with no banner', () => {
      const result = analyzeService(12345, null, null);
      expect(result.serviceName).toBe('Unknown TCP Service');
    });
  });
});
