import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runNmapScan, checkNmapInstalled } from '../src/main/nmapScanner.js';
import { spawn, exec } from 'child_process';

vi.mock('child_process', () => ({
  spawn: vi.fn(),
  exec: vi.fn((cmd, cb) => cb(null, 'Nmap version 7.92')),
  execSync: vi.fn().mockReturnValue('nmap')
}));

vi.mock('../src/main/store.js', () => ({
  getSetting: vi.fn().mockImplementation((key) => {
    if (key === 'nmap.path') return 'nmap';
    return null;
  }),
  setSetting: vi.fn(),
  checkDependency: vi.fn().mockResolvedValue({ installed: true, output: 'Nmap version 7.92' })
}));

describe('Nmap Scanner', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should check if nmap is installed via exec', async () => {
    const result = await checkNmapInstalled();
    expect(result).toBe(true);
  });

  it('should run an nmap scan and handle chunks', async () => {
    const mockProcess = {
      stdout: {
        on: vi.fn((event, cb) => {
          if (event === 'data') {
            setTimeout(() => cb(Buffer.from('Nmap scan report for 10.0.0.1\n')), 10);
          }
        })
      },
      stderr: { on: vi.fn() },
      on: vi.fn((event, cb) => {
        if (event === 'close') setTimeout(() => cb(0), 20);
      }),
      kill: vi.fn()
    };
    spawn.mockReturnValue(mockProcess);

    const onChunk = vi.fn();
    const onComplete = vi.fn();
    
    await runNmapScan('deep', '10.0.0.1', onChunk, onComplete, vi.fn());
    
    await new Promise(r => setTimeout(r, 100));
    
    expect(spawn).toHaveBeenCalled();
    expect(onChunk).toHaveBeenCalled();
    expect(onComplete).toHaveBeenCalled();
  });

  it('should handle scan errors', async () => {
    const mockProcess = {
      stdout: { on: vi.fn() },
      stderr: { on: vi.fn() },
      on: vi.fn((event, cb) => {
        if (event === 'close') cb(1);
      }),
      kill: vi.fn()
    };
    spawn.mockReturnValue(mockProcess);

    const onError = vi.fn();
    await runNmapScan('invalid-type', '10.0.0.1', vi.fn(), vi.fn(), onError);
    
    expect(onError).toHaveBeenCalled();
  });

  it('should run ncat and handle payload', async () => {
    const mockProcess = {
      stdout: { on: vi.fn() },
      stderr: { on: vi.fn() },
      stdin: { write: vi.fn(), end: vi.fn() },
      on: vi.fn((event, cb) => {
        if (event === 'close') setTimeout(() => cb(0), 10);
      }),
      kill: vi.fn()
    };
    spawn.mockReturnValue(mockProcess);

    const { runNcat } = await import('../src/main/nmapScanner.js');
    const onComplete = vi.fn();
    
    await runNcat({ target: '10.0.0.1', port: '80', payload: 'GET /' }, vi.fn(), onComplete, vi.fn());
    
    expect(mockProcess.stdin.write).toHaveBeenCalledWith('GET /\n');
    await new Promise(r => setTimeout(r, 50));
    expect(onComplete).toHaveBeenCalled();
  });

  it('should discover nmap scripts', async () => {
    const fs = await import('fs');
    vi.spyOn(fs.default, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs.default, 'readdirSync').mockReturnValue(['test-script.nse']);
    vi.spyOn(fs.default, 'readFileSync').mockReturnValue('categories = {"safe", "discovery"}');
    vi.spyOn(fs.default, 'openSync').mockReturnValue(1);
    vi.spyOn(fs.default, 'readSync').mockImplementation((fd, buffer) => {
      buffer.write('categories = {"safe", "discovery"}');
      return 100;
    });
    vi.spyOn(fs.default, 'closeSync').mockImplementation(() => {});
    
    const { getNmapScripts } = await import('../src/main/nmapScanner.js');
    const scripts = await getNmapScripts();
    
    expect(scripts.length).toBeGreaterThan(0);
  });
});
