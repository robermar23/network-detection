import { describe, it, expect, vi, beforeEach } from 'vitest';
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
        setTimeout(ms, cb) { 
          if(cb) setTimeout(cb, ms);
        }
        write() {}
        connect(port, ip) {
          if (port === 2122) {
             setTimeout(() => {
                if (this.listeners.error) this.listeners.error(new Error('Connection refused'));
             }, 10);
             return;
          }
          if (this.listeners.connect) this.listeners.connect();
          if (this.listeners.data) {
            if (port === 21) {
              this.listeners.data(Buffer.from('220 FTP Server Ready\r\n'));
              setTimeout(() => {
                this.listeners.data(Buffer.from('331 Please specify the password.\r\n'));
              }, 10);
              setTimeout(() => {
                this.listeners.data(Buffer.from('230 Login successful.\r\n'));
              }, 20);
            } else if (port === 2121) {
              this.listeners.data(Buffer.from('220 FTP Server Ready\r\n'));
              setTimeout(() => {
                this.listeners.data(Buffer.from('331 Please specify the password.\r\n'));
              }, 10);
              setTimeout(() => {
                this.listeners.data(Buffer.from('530 Login incorrect.\r\n'));
              }, 20);
            } else {
              this.listeners.data(Buffer.from('220 FTP Server Ready\r\n'));
              setTimeout(() => {
                this.listeners.data(Buffer.from('530 Login incorrect.\r\n'));
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
vi.mock('http', () => ({
  default: {
    request: vi.fn()
  }
}));

vi.mock('https', () => ({
  default: {
    request: vi.fn()
  }
}));

describe('Security Analyzer Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Anonymous FTP', () => {
    it('Should successfully emulate checking anonymous FTP (Success mock)', async () => {
       const res = await checkAnonymousFtp('127.0.0.1', 21);
       expect(res.vulnerable).toBe(true);
       expect(res.details).toContain('CRITICAL');
    });

    it('Should return not vulnerable for failed anonymous FTP login', async () => {
       const res = await checkAnonymousFtp('127.0.0.1', 2121);
       expect(res.vulnerable).toBe(false);
       expect(res.details).toBe('Anonymous FTP Login Rejected.');
    });

    it('Should handle FTP connection errors gracefully', async () => {
       const res = await checkAnonymousFtp('127.0.0.1', 2122);
       expect(res).toBeNull();
    });
  });

  describe('Sensitive Web Directories', () => {
    it('Should emulate HTTP directory traversal discovery', async () => {
       http.request.mockImplementation((opts, cb) => {
         if (opts.path === '/.env') cb({ statusCode: 200 });
         else cb({ statusCode: 404 });
         return { on: vi.fn(), end: vi.fn(), destroy: vi.fn() };
       });

       const res = await checkSensitiveWebDirs('127.0.0.1', 80, false);
       expect(res.vulnerable).toBe(true);
       expect(res.details).toContain('/.env');
    });

    it('Should emulate HTTPS directory traversal discovery', async () => {
       https.request.mockImplementation((opts, cb) => {
         if (opts.path === '/.git/config') cb({ statusCode: 200 });
         else cb({ statusCode: 404 });
         return { on: vi.fn(), end: vi.fn(), destroy: vi.fn() };
       });

       const res = await checkSensitiveWebDirs('127.0.0.1', 443, true);
       expect(res.vulnerable).toBe(true);
       expect(res.details).toContain('/.git/config');
       expect(res.details).not.toContain('/.env');
    });

    it('Should return not vulnerable if no sensitive directories are found', async () => {
       http.request.mockImplementation((opts, cb) => {
         cb({ statusCode: 404 });
         return { on: vi.fn(), end: vi.fn(), destroy: vi.fn() };
       });

       const res = await checkSensitiveWebDirs('127.0.0.1', 80, false);
       expect(res.vulnerable).toBe(false);
       expect(res.details).toBe('No common sensitive web files detected.');
    });

    it('Should handle web request errors gracefully', async () => {
       http.request.mockImplementation((opts, cb) => {
         return { 
           on: (event, handler) => {
             if (event === 'error') {
               setTimeout(() => handler(new Error('Network error')), 10);
             }
           }, 
           end: vi.fn(), 
           destroy: vi.fn() 
         };
       });

       const res = await checkSensitiveWebDirs('127.0.0.1', 80, false);
       expect(res.vulnerable).toBe(false);
    });
  });
});
