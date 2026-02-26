import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock electron-store before importing store.js since it runs at module level
vi.mock('electron-store', () => {
  const mockStore = {};
  return {
    default: class MockStore {
      constructor() {
        this.data = { ...mockStore };
      }
      get(key) {
        const parts = key.split('.');
        let val = this.data;
        for (const p of parts) {
          if (val == null) return undefined;
          val = val[p];
        }
        return val;
      }
      set(key, value) {
        const parts = key.split('.');
        if (parts.length === 1) {
          this.data[key] = value;
        } else {
          let obj = this.data;
          for (let i = 0; i < parts.length - 1; i++) {
            if (!obj[parts[i]]) obj[parts[i]] = {};
            obj = obj[parts[i]];
          }
          obj[parts[parts.length - 1]] = value;
        }
      }
      get store() {
        return this.data;
      }
    }
  };
});

vi.mock('child_process', () => ({
  exec: vi.fn()
}));

// We need to mock util.promisify to return a function that works with our mocked exec
vi.mock('util', () => ({
  default: {
    promisify: (fn) => (...args) => new Promise((resolve, reject) => fn(...args, (err, result) => err ? reject(err) : resolve(result)))
  },
  promisify: (fn) => (...args) => new Promise((resolve, reject) => fn(...args, (err, result) => err ? reject(err) : resolve(result)))
}));

import { getSetting, setSetting, getAllSettings, checkDependency } from '../src/main/store.js';
import { exec } from 'child_process';

describe('Store Module', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getSetting / setSetting', () => {
    it('should set and get a top-level setting', () => {
      setSetting('testKey', 'testValue');
      expect(getSetting('testKey')).toBe('testValue');
    });

    it('should set and get nested settings', () => {
      setSetting('nmap.path', '/usr/bin/nmap');
      expect(getSetting('nmap.path')).toBe('/usr/bin/nmap');
    });
  });

  describe('getAllSettings', () => {
    it('should return the entire store object', () => {
      const all = getAllSettings();
      expect(typeof all).toBe('object');
    });
  });

  describe('checkDependency', () => {
    it('should return installed: true when nmap is found', async () => {
      exec.mockImplementation((cmd, cb) => cb(null, { stdout: 'Nmap version 7.94' }));
      const result = await checkDependency('nmap');
      expect(result.installed).toBe(true);
    });

    it('should return installed: false when nmap is not found', async () => {
      exec.mockImplementation((cmd, cb) => cb(new Error('not found')));
      const result = await checkDependency('nmap');
      expect(result.installed).toBe(false);
    });

    it('should return installed: true when tshark is found', async () => {
      exec.mockImplementation((cmd, cb) => cb(null, { stdout: 'TShark (Wireshark) 4.0.3' }));
      const result = await checkDependency('tshark');
      expect(result.installed).toBe(true);
    });

    it('should return installed: false when tshark is not found', async () => {
      exec.mockImplementation((cmd, cb) => cb(new Error('not found')));
      const result = await checkDependency('tshark');
      expect(result.installed).toBe(false);
    });

    it('should throw for unknown tool names', async () => {
      await expect(checkDependency('unknown_tool')).rejects.toThrow('Unknown tool: unknown_tool');
    });
  });
});
