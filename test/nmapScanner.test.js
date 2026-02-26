import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkNmapInstalled, cancelNmapScan, runNmapScan, runNcat, getNmapScripts } from '../src/main/nmapScanner.js';
import { exec, spawn, execSync } from 'child_process';
import fs from 'fs';

vi.mock('child_process', () => ({
  exec: vi.fn(),
  spawn: vi.fn(),
  execSync: vi.fn()
}));

vi.mock('fs', () => ({
  default: {
    existsSync: vi.fn(),
    readdirSync: vi.fn(),
    openSync: vi.fn(),
    readSync: vi.fn(),
    closeSync: vi.fn()
  },
  existsSync: vi.fn(),
  readdirSync: vi.fn(),
  openSync: vi.fn(),
  readSync: vi.fn(),
  closeSync: vi.fn()
}));

vi.mock('../src/main/store.js', () => ({
  getSetting: vi.fn().mockReturnValue('')
}));

describe('Nmap Scanner', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('checkNmapInstalled', () => {
    it('should resolve true when nmap is installed', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      const result = await checkNmapInstalled();
      expect(result).toBe(true);
    });

    it('should resolve false when nmap is not installed', async () => {
      exec.mockImplementation((cmd, cb) => cb(new Error('not found')));
      const result = await checkNmapInstalled();
      expect(result).toBe(false);
    });
  });

  describe('cancelNmapScan', () => {
    it('should return false when no scan exists for the given id', () => {
      const result = cancelNmapScan('192.168.1.1');
      expect(result).toBe(false);
    });
  });

  describe('runNmapScan', () => {
    it('should call onErrorCallback when nmap is not installed', async () => {
      exec.mockImplementation((cmd, cb) => cb(new Error('not found')));
      const onError = vi.fn();
      await runNmapScan('host', '192.168.1.1', vi.fn(), vi.fn(), onError);
      expect(onError).toHaveBeenCalledWith({ error: 'Nmap is not installed or not in PATH.' });
    });

    it('should call onErrorCallback for unknown scan type', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      const onError = vi.fn();
      await runNmapScan('unknown_type', '192.168.1.1', vi.fn(), vi.fn(), onError);
      expect(onError).toHaveBeenCalledWith({ error: 'Unknown Nmap scan type' });
    });

    it('should spawn nmap with correct args for host scan', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      const mockProcess = {
        stdout: { on: vi.fn() },
        stderr: { on: vi.fn() },
        on: vi.fn()
      };
      spawn.mockReturnValue(mockProcess);

      await runNmapScan('host', '192.168.1.1', vi.fn(), vi.fn(), vi.fn());
      expect(spawn).toHaveBeenCalled();
      const args = spawn.mock.calls[0][1];
      expect(args).toContain('-A');
      expect(args).toContain('192.168.1.1');
    });

    it('should spawn nmap with correct args for deep scan', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      const mockProcess = {
        stdout: { on: vi.fn() },
        stderr: { on: vi.fn() },
        on: vi.fn()
      };
      spawn.mockReturnValue(mockProcess);

      await runNmapScan('deep', '10.0.0.1', vi.fn(), vi.fn(), vi.fn());
      const args = spawn.mock.calls[0][1];
      expect(args).toContain('-p');
      expect(args).toContain('1-65535');
    });

    it('should spawn nmap with correct args for vuln scan', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      const mockProcess = {
        stdout: { on: vi.fn() },
        stderr: { on: vi.fn() },
        on: vi.fn()
      };
      spawn.mockReturnValue(mockProcess);

      await runNmapScan('vuln', '10.0.0.2', vi.fn(), vi.fn(), vi.fn());
      const args = spawn.mock.calls[0][1];
      expect(args).toContain('vuln');
    });

    it('should spawn nmap with correct args for port scan', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      const mockProcess = {
        stdout: { on: vi.fn() },
        stderr: { on: vi.fn() },
        on: vi.fn()
      };
      spawn.mockReturnValue(mockProcess);

      await runNmapScan('port', '10.0.0.1:443', vi.fn(), vi.fn(), vi.fn());
      const args = spawn.mock.calls[0][1];
      expect(args).toContain('443');
      expect(args).toContain('10.0.0.1');
    });

    it('should spawn nmap with correct args for custom scan with script args', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      const mockProcess = {
        stdout: { on: vi.fn() },
        stderr: { on: vi.fn() },
        on: vi.fn()
      };
      spawn.mockReturnValue(mockProcess);

      await runNmapScan('custom', { ip: '10.0.0.1', scriptName: 'http-title', args: 'path=/' }, vi.fn(), vi.fn(), vi.fn());
      const args = spawn.mock.calls[0][1];
      expect(args).toContain('http-title');
      expect(args).toContain('--script-args');
      expect(args).toContain('path=/');
    });

    it('should call onResultCallback when stdout data arrives', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      const mockProcess = {
        stdout: { on: vi.fn() },
        stderr: { on: vi.fn() },
        on: vi.fn()
      };
      spawn.mockReturnValue(mockProcess);

      const onResult = vi.fn();
      await runNmapScan('host', '10.0.0.1', onResult, vi.fn(), vi.fn());

      // Simulate stdout data
      const stdoutHandler = mockProcess.stdout.on.mock.calls.find(c => c[0] === 'data')[1];
      stdoutHandler(Buffer.from('Nmap scan result'));
      expect(onResult).toHaveBeenCalledWith({ chunk: 'Nmap scan result' });
    });

    it('should call onCompleteCallback on successful close', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      const mockProcess = {
        stdout: { on: vi.fn() },
        stderr: { on: vi.fn() },
        on: vi.fn()
      };
      spawn.mockReturnValue(mockProcess);

      const onComplete = vi.fn();
      await runNmapScan('host', '10.0.0.1', vi.fn(), onComplete, vi.fn());

      const closeHandler = mockProcess.on.mock.calls.find(c => c[0] === 'close')[1];
      closeHandler(0);
      expect(onComplete).toHaveBeenCalledWith(expect.objectContaining({ target: '10.0.0.1' }));
    });

    it('should call onErrorCallback on non-zero exit code', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      const mockProcess = {
        stdout: { on: vi.fn() },
        stderr: { on: vi.fn() },
        on: vi.fn()
      };
      spawn.mockReturnValue(mockProcess);

      const onError = vi.fn();
      await runNmapScan('host', '10.0.0.1', vi.fn(), vi.fn(), onError);

      const closeHandler = mockProcess.on.mock.calls.find(c => c[0] === 'close')[1];
      closeHandler(1);
      expect(onError).toHaveBeenCalledWith({ error: 'Nmap process exited with code 1' });
    });

    it('should call onErrorCallback on process spawn error', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      const mockProcess = {
        stdout: { on: vi.fn() },
        stderr: { on: vi.fn() },
        on: vi.fn()
      };
      spawn.mockReturnValue(mockProcess);

      const onError = vi.fn();
      await runNmapScan('host', '10.0.0.1', vi.fn(), vi.fn(), onError);

      const errorHandler = mockProcess.on.mock.calls.find(c => c[0] === 'error')[1];
      errorHandler(new Error('ENOENT'));
      expect(onError).toHaveBeenCalledWith({ error: 'ENOENT' });
    });
  });

  describe('runNcat', () => {
    it('should call onErrorCallback when nmap/ncat is not installed', async () => {
      exec.mockImplementation((cmd, cb) => cb(new Error('not found')));
      const onError = vi.fn();
      await runNcat({ target: '10.0.0.1', port: '80', payload: '' }, vi.fn(), vi.fn(), onError);
      expect(onError).toHaveBeenCalledWith({ error: 'Nmap (and Ncat) is not installed or not in PATH.' });
    });

    it('should spawn ncat and handle close event', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      const mockProcess = {
        stdout: { on: vi.fn() },
        stderr: { on: vi.fn() },
        stdin: { write: vi.fn() },
        on: vi.fn()
      };
      spawn.mockReturnValue(mockProcess);

      const onComplete = vi.fn();
      await runNcat({ target: '10.0.0.1', port: '80', payload: 'GET / HTTP/1.0\\n' }, vi.fn(), onComplete, vi.fn());

      expect(mockProcess.stdin.write).toHaveBeenCalled();

      const closeHandler = mockProcess.on.mock.calls.find(c => c[0] === 'close')[1];
      closeHandler(0);
      expect(onComplete).toHaveBeenCalledWith(expect.objectContaining({ success: true }));
    });
  });

  describe('getNmapScripts', () => {
    it('should return empty array when nmap is not installed', async () => {
      exec.mockImplementation((cmd, cb) => cb(new Error('not found')));
      const result = await getNmapScripts();
      expect(result).toEqual([]);
    });

    it('should discover and parse NSE scripts from directory', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      execSync.mockReturnValue('C:\\Program Files (x86)\\Nmap\\nmap.exe\n');
      
      fs.existsSync.mockImplementation((p) => {
        if (p.includes('nmap.exe') || p.includes('scripts')) return true;
        return false;
      });
      
      fs.readdirSync.mockReturnValue(['http-title.nse', 'smb-vuln.nse', 'readme.txt']);
      fs.openSync.mockReturnValue(99);
      fs.readSync.mockImplementation((fd, buffer, offset, length) => {
        const content = 'categories = {"safe", "discovery"}';
        buffer.write(content);
        return content.length;
      });
      fs.closeSync.mockReturnValue(undefined);

      const result = await getNmapScripts();
      expect(result.length).toBe(2); // Only .nse files
      expect(result[0].id).toBe('http-title');
      expect(result[0].categories).toContain('safe');
      expect(result[0].categories).toContain('discovery');
    });

    it('should handle scripts without categories', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      execSync.mockReturnValue('C:\\Program Files\\Nmap\\nmap.exe\n');

      fs.existsSync.mockReturnValue(true);
      fs.readdirSync.mockReturnValue(['custom.nse']);
      fs.openSync.mockReturnValue(1);
      fs.readSync.mockImplementation((fd, buffer) => {
        const content = '-- No categories here';
        buffer.write(content);
        return content.length;
      });
      fs.closeSync.mockReturnValue(undefined);

      const result = await getNmapScripts();
      expect(result.length).toBe(1);
      expect(result[0].categories).toEqual(['uncategorized']);
    });

    it('should return empty array when scripts directory not found', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      execSync.mockImplementation(() => { throw new Error('not found'); });
      fs.existsSync.mockReturnValue(false);

      const result = await getNmapScripts();
      expect(result).toEqual([]);
    });

    it('should handle readdirSync errors gracefully', async () => {
      exec.mockImplementation((cmd, cb) => cb(null));
      execSync.mockImplementation(() => { throw new Error('not found'); });
      fs.existsSync.mockImplementation((p) => p.includes('Program Files'));
      fs.readdirSync.mockImplementation(() => { throw new Error('EACCES'); });

      const result = await getNmapScripts();
      expect(result).toEqual([]);
    });
  });
});
