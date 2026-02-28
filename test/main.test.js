import { describe, it, expect, vi } from 'vitest';
import { app, BrowserWindow, ipcMain, shell, dialog } from 'electron';
import { spawn, exec } from 'child_process';
import util from 'util';
import ping from 'ping';

// Mock child_process
vi.mock('child_process', () => ({
  spawn: vi.fn().mockReturnValue({
    stdout: { on: vi.fn() },
    stderr: { on: vi.fn() },
    on: vi.fn(),
    kill: vi.fn()
  }),
  exec: vi.fn((cmd, cb) => cb(null, { stdout: 'Mock Output' })),
  execSync: vi.fn().mockReturnValue('mock sequence')
}));

// Mock util
vi.mock('util', () => ({
  promisify: vi.fn((fn) => fn),
  default: { promisify: vi.fn((fn) => fn) }
}));

// Mock ping
vi.mock('ping', () => ({
  default: {
    promise: {
      probe: vi.fn().mockResolvedValue({ alive: true, time: 10 })
    }
  },
  promise: {
    probe: vi.fn().mockResolvedValue({ alive: true, time: 10 })
  }
}));

// Mock electron completely
vi.mock('electron', () => {
  return {
    app: {
      whenReady: () => Promise.resolve(),
      on: vi.fn(),
      getPath: vi.fn().mockReturnValue('/home/docs'),
      quit: vi.fn(),
      commandLine: { appendSwitch: vi.fn() }
    },
    BrowserWindow: class BrowserWindowMock {
      constructor() {
        this.on = vi.fn();
        this.once = vi.fn();
        this.loadURL = vi.fn();
        this.loadFile = vi.fn();
        this.getBounds = vi.fn().mockReturnValue({ x: 0, y: 0, width: 800, height: 600 });
        this.webContents = {
          openDevTools: vi.fn(),
          send: vi.fn()
        };
      }
      static getAllWindows = vi.fn().mockReturnValue([]);
    },
    ipcMain: {
      handle: vi.fn(),
      on: vi.fn()
    },
    shell: {
      openExternal: vi.fn().mockResolvedValue()
    },
    dialog: {
      showSaveDialog: vi.fn().mockResolvedValue({ canceled: false, filePath: '/test/save.json' }),
      showOpenDialog: vi.fn().mockResolvedValue({ canceled: false, filePaths: ['/test/save.json'] }),
      showMessageBox: vi.fn().mockResolvedValue({ response: 0 })
    }
  };
});

// Mock electron-store (MUST BE AT TOP LEVEL)
vi.mock('electron-store', () => {
  return {
    default: class MockStore {
      constructor() {
        this.store = {};
      }
      get(key) {
        if (key === 'windowBounds') return { x: 0, y: 0, width: 1200, height: 800 };
        return null;
      }
      set() {}
      onDidChange() {}
      onDidAnyChange() {}
    }
  };
});

// Mock fs
vi.mock('fs', () => ({
  default: {
    writeFileSync: vi.fn(),
    readFileSync: vi.fn().mockReturnValue('[]'),
    existsSync: vi.fn().mockReturnValue(true),
    promises: {
      readFile: vi.fn().mockResolvedValue('')
    }
  },
  writeFileSync: vi.fn(),
  readFileSync: vi.fn().mockReturnValue('[]'),
  existsSync: vi.fn().mockReturnValue(true),
  promises: {
    readFile: vi.fn().mockResolvedValue('')
  }
}));

// Mock electron-updater
vi.mock('electron-updater', () => {
  const autoUpdater = {
    logger: null,
    checkForUpdatesAndNotify: vi.fn(),
    on: vi.fn(),
    quitAndInstall: vi.fn(),
    quitAndInstallCallback: vi.fn()
  };
  return {
    default: { autoUpdater },
    autoUpdater
  };
});

describe('IPC Payload Validation & Electron API', () => {
  it('Should validate IP payload formatting', () => {
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    expect(ipRegex.test('192.168.1.10')).toBe(true);
    expect(ipRegex.test('10.0.0.1')).toBe(true);
    expect(ipRegex.test('not_an_ip')).toBe(false);
  });

  it('Should validate port bounds', () => {
    const isValidPort = (port) => {
      const parsedPort = parseInt(port, 10);
      return !isNaN(parsedPort) && parsedPort >= 1 && parsedPort <= 65535;
    };
    expect(isValidPort('80')).toBe(true);
    expect(isValidPort('0')).toBe(false);
  });

  it('Should exercise local scan and results handlers', async () => {
     await import('../src/main/main.js');
     const handlers = {};
     ipcMain.handle.mock.calls.forEach(call => {
       handlers[call[0]] = call[1];
     });

     if (handlers['save-results']) {
       const res = await handlers['save-results']({}, [{ ip: '1.2.3.4' }]);
       expect(res.status).toBe('saved');
     }

     if (handlers['load-results']) {
       const res = await handlers['load-results']({});
       expect(res.status).toBe('loaded');
     }
  });

  it('Should handle scan and probe handlers', async () => {
     await import('../src/main/main.js');
     const handlers = {};
     ipcMain.handle.mock.calls.forEach(call => {
       handlers[call[0]] = call[1];
     });

     if (handlers['run-nmap-scan']) {
       const res = await handlers['run-nmap-scan']({}, { type: 'deep', target: '10.0.0.1' });
       expect(res.status).toBe('started');
     }

     if (handlers['ping-host']) {
       const res = await handlers['ping-host']({}, '127.0.0.1');
       expect(res).toHaveProperty('alive');
     }
  });

  it('Should handle external actions and regex validation', async () => {
     const handlers = {};
     ipcMain.handle.mock.calls.forEach(call => {
       handlers[call[0]] = call[1];
     });

     if (handlers['open-external-action']) {
       const badRes = await handlers['open-external-action']({}, { type: 'http', ip: 'invalid' });
       expect(badRes.success).toBe(false);

       const goodRes = await handlers['open-external-action']({}, { type: 'http', ip: '10.0.0.1' });
       expect(goodRes.success).toBe(true);
     }
  });
});
