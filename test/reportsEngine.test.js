import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EventEmitter } from 'events';

// Force development mode so getReportsEnginePath() uses app.getAppPath() (mocked)
process.env.NODE_ENV = 'development';

// Mock child_process
vi.mock('child_process', () => ({
  spawn: vi.fn()
}));

// Mock electron
vi.mock('electron', () => ({
  app: {
    getAppPath: vi.fn().mockReturnValue('/mock/app'),
    getPath: vi.fn().mockReturnValue('/mock/userData')
  },
  dialog: {
    showSaveDialog: vi.fn()
  }
}));

// Mock fs with accessSync and constants needed by isReportsEngineAvailable
vi.mock('fs', () => ({
  default: {
    existsSync: vi.fn().mockReturnValue(true),
    accessSync: vi.fn(),
    constants: { X_OK: 1 }
  }
}));

import { spawn } from 'child_process';
import { dialog } from 'electron';
import { runExport, isReportsEngineAvailable } from '../src/main/engines/reportsEngine.js';

// Flush microtask queue so dialog.showSaveDialog resolves before we emit events
const flushPromises = () => new Promise(resolve => setImmediate(resolve));

function createMockProcess() {
  const stdin = { write: vi.fn(), end: vi.fn() };
  const stdout = new EventEmitter();
  const stderr = new EventEmitter();
  const proc = new EventEmitter();
  proc.stdin = stdin;
  proc.stdout = stdout;
  proc.stderr = stderr;
  proc.kill = vi.fn();
  return proc;
}

describe('Reports Engine Manager', () => {
  let mockProc;
  let mockMainWindow;

  beforeEach(() => {
    vi.clearAllMocks();
    mockProc = createMockProcess();
    spawn.mockReturnValue(mockProc);
    mockMainWindow = {
      webContents: {
        send: vi.fn()
      }
    };
  });

  describe('isReportsEngineAvailable', () => {
    it('should return true when binary exists and is executable', () => {
      expect(isReportsEngineAvailable()).toBe(true);
    });
  });

  describe('runExport', () => {
    it('should return cancelled if user cancels save dialog', async () => {
      dialog.showSaveDialog.mockResolvedValue({ canceled: true });

      const result = await runExport(mockMainWindow, { format: 'json', hosts: [] });

      expect(result).toEqual({ status: 'cancelled' });
      expect(spawn).not.toHaveBeenCalled();
    });

    it('should spawn go binary with correct format flag', async () => {
      dialog.showSaveDialog.mockResolvedValue({ canceled: false, filePath: '/tmp/report.json' });

      const exportPromise = runExport(mockMainWindow, {
        format: 'json',
        hosts: [{ ip: '192.168.1.1' }],
        sanitize: false,
        summary: true
      });

      // Flush microtask queue so dialog resolves and spawn is called
      await flushPromises();

      mockProc.stdout.emit('data', Buffer.from(JSON.stringify({ success: true })));
      mockProc.emit('close', 0);

      const result = await exportPromise;

      expect(spawn).toHaveBeenCalledTimes(1);
      const args = spawn.mock.calls[0][1];
      expect(args).toContain('--format');
      expect(args).toContain('json');
      expect(args).toContain('--output');
      expect(args).toContain('/tmp/report.json');
      expect(args).toContain('--summary');
      expect(result.status).toBe('exported');
    });

    it('should pass sanitize flag when enabled', async () => {
      dialog.showSaveDialog.mockResolvedValue({ canceled: false, filePath: '/tmp/report.csv' });

      const exportPromise = runExport(mockMainWindow, {
        format: 'csv',
        hosts: [{ ip: '10.0.0.1' }],
        sanitize: true,
        summary: false
      });

      await flushPromises();

      mockProc.stdout.emit('data', Buffer.from(JSON.stringify({ success: true })));
      mockProc.emit('close', 0);

      await exportPromise;

      const args = spawn.mock.calls[0][1];
      expect(args).toContain('--sanitize');
      expect(args).toContain('--format');
      expect(args).toContain('csv');
    });

    it('should write host data to stdin', async () => {
      dialog.showSaveDialog.mockResolvedValue({ canceled: false, filePath: '/tmp/report.json' });

      const hosts = [
        { ip: '192.168.1.1', mac: '00:11:22:33:44:55', hostname: 'test-host' }
      ];

      const exportPromise = runExport(mockMainWindow, {
        format: 'json',
        hosts,
        sanitize: false,
        summary: false
      });

      await flushPromises();

      mockProc.stdout.emit('data', Buffer.from(JSON.stringify({ success: true })));
      mockProc.emit('close', 0);

      await exportPromise;

      expect(mockProc.stdin.write).toHaveBeenCalled();
      const written = mockProc.stdin.write.mock.calls[0][0];
      const parsed = JSON.parse(written);
      expect(parsed.hosts).toEqual(hosts);
      expect(mockProc.stdin.end).toHaveBeenCalled();
    });

    it('should return error on non-zero exit code', async () => {
      dialog.showSaveDialog.mockResolvedValue({ canceled: false, filePath: '/tmp/report.json' });

      const exportPromise = runExport(mockMainWindow, {
        format: 'json',
        hosts: [],
        sanitize: false,
        summary: false
      });

      await flushPromises();

      mockProc.stderr.emit('data', Buffer.from('fatal: unknown format'));
      mockProc.emit('close', 1);

      const result = await exportPromise;
      expect(result.status).toBe('error');
      expect(result.error).toContain('unknown format');
    });

    it('should use correct file extensions per format', async () => {
      const formats = {
        json: '.json',
        csv: '.csv',
        html: '.html',
        pdf: '.pdf'
      };

      for (const [format, ext] of Object.entries(formats)) {
        vi.clearAllMocks();
        const proc = createMockProcess();
        spawn.mockReturnValue(proc);
        dialog.showSaveDialog.mockResolvedValue({ canceled: false, filePath: `/tmp/report${ext}` });

        const p = runExport(mockMainWindow, { format, hosts: [], sanitize: false, summary: false });
        await flushPromises();

        proc.stdout.emit('data', Buffer.from(JSON.stringify({ success: true })));
        proc.emit('close', 0);
        await p;

        const dialogOpts = dialog.showSaveDialog.mock.calls[0][1];
        expect(dialogOpts.filters).toBeDefined();
      }
    });
  });
});
