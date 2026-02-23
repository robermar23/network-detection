import { describe, it, expect, vi } from 'vitest';
import { checkAnonymousFtp, checkSensitiveWebDirs } from '../src/main/securityAnalyzer.js';
import net from 'net';
import http from 'http';
import https from 'https';

// Mock net
vi.mock('net', () => {
  return {
    default: {
      Socket: class MockSocket {
        constructor() {
           this.listeners = {};
        }
        on(event, cb) { this.listeners[event] = cb; }
        setTimeout() {}
        write() {}
        connect(port, ip) {
          if (this.listeners.connect) this.listeners.connect();
          if (this.listeners.data) {
            if (port === 21) {
              this.listeners.data(Buffer.from('220 FTP Server Ready\\r\\n'));
              setTimeout(() => {
                this.listeners.data(Buffer.from('331 Please specify the password.\\r\\n'));
              }, 10);
              setTimeout(() => {
                this.listeners.data(Buffer.from('230 Login successful.\\r\\n'));
              }, 20);
            } else {
              this.listeners.data(Buffer.from('220 FTP Server Ready\\r\\n'));
              setTimeout(() => {
                this.listeners.data(Buffer.from('530 Login incorrect.\\r\\n'));
              }, 10);
            }
          }
        }
        destroy() {}
      }
    }
  };
});

// Mock HTTP/HTTPS
const mockRequest = {
  on: vi.fn(),
  end: vi.fn(),
  destroy: vi.fn()
};

vi.mock('http', () => ({
  default: {
    request: vi.fn().mockImplementation((opts, cb) => {
      if (opts.path === '/.env') {
        cb({ statusCode: 200 }); // Simulate found
      } else {
        cb({ statusCode: 404 });
      }
      return mockRequest;
    })
  }
}));

vi.mock('https', () => ({
  default: {
    request: vi.fn().mockImplementation((opts, cb) => {
      if (opts.path === '/.git/config') {
        cb({ statusCode: 200 });
      } else {
        cb({ statusCode: 404 });
      }
      return mockRequest;
    })
  }
}));


describe('Security Analyzer Tests', () => {
  it('Should successfully emulate checking anonymous FTP (Success mock)', async () => {
     // port 21 is mocked to succeed login
     const res = await checkAnonymousFtp('127.0.0.1', 21);
     expect(res.vulnerable).toBe(true);
     expect(res.details).toContain('CRITICAL');
  });

  it('Should emulate HTTP directory traversal discovery', async () => {
     // Mock defaults to finding /.env unconditionally for HTTP
     const res = await checkSensitiveWebDirs('127.0.0.1', 80, false);
     expect(res.vulnerable).toBe(true);
     expect(res.details).toContain('/.env');
  });

  it('Should emulate HTTPS directory traversal discovery', async () => {
     const res = await checkSensitiveWebDirs('127.0.0.1', 443, true);
     expect(res.vulnerable).toBe(true);
     expect(res.details).toContain('/.git/config');
     expect(res.details).not.toContain('/.env');
  });
});
