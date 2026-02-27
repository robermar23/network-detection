import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';

// Force development mode so getEnginePath() uses app.getAppPath() (mocked)
// instead of process.resourcesPath (undefined in test env)
process.env.NODE_ENV = 'development';

// Mock child_process
vi.mock('child_process', () => ({
  spawn: vi.fn()
}));

// Mock split2
vi.mock('split2', () => ({
  default: vi.fn(() => {
    const transform = new EventEmitter();
    transform.pipe = vi.fn().mockReturnThis();
    return transform;
  })
}));

// Mock electron
vi.mock('electron', () => ({
  app: {
    getAppPath: vi.fn().mockReturnValue('/mock/app'),
    getPath: vi.fn().mockReturnValue('/mock/userData')
  }
}));

// Mock fs
vi.mock('fs', () => ({
  default: {
    existsSync: vi.fn().mockReturnValue(true),
    mkdirSync: vi.fn()
  }
}));

import { spawn } from 'child_process';
import { initRustEngine, shutdownRustEngine, isRustEngineRunning, rustRpc } from '../src/main/engines/rustEngine.js';

function createMockProcess() {
  const stdin = { write: vi.fn() };
  const stdout = new EventEmitter();
  stdout.pipe = vi.fn().mockReturnValue(new EventEmitter());
  const stderr = new EventEmitter();
  const proc = new EventEmitter();
  proc.stdin = stdin;
  proc.stdout = stdout;
  proc.stderr = stderr;
  proc.kill = vi.fn();
  return proc;
}

describe('Rust Engine Manager', () => {
  let mockProc;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    mockProc = createMockProcess();
    spawn.mockReturnValue(mockProc);
  });

  afterEach(() => {
    vi.useRealTimers();
    try { shutdownRustEngine(); } catch { /* ignore */ }
  });

  describe('initRustEngine', () => {
    it('should spawn the rust engine binary', () => {
      initRustEngine();

      expect(spawn).toHaveBeenCalledTimes(1);
      const [binPath, args, opts] = spawn.mock.calls[0];
      expect(binPath).toContain('netspectre-engine');
      expect(args).toContain('--data-dir');
      expect(opts.stdio).toEqual(['pipe', 'pipe', 'pipe']);
    });

    it('should set engine as running after spawn', () => {
      initRustEngine();
      expect(isRustEngineRunning()).toBe(true);
    });
  });

  describe('shutdownRustEngine', () => {
    it('should kill the process with SIGTERM', () => {
      initRustEngine();
      shutdownRustEngine();

      expect(mockProc.kill).toHaveBeenCalledWith('SIGTERM');
    });

    it('should mark engine as not running', () => {
      initRustEngine();
      shutdownRustEngine();

      expect(isRustEngineRunning()).toBe(false);
    });
  });

  describe('isRustEngineRunning', () => {
    it('should return false before init', () => {
      expect(isRustEngineRunning()).toBe(false);
    });
  });

  describe('rustRpc', () => {
    it('should reject if engine is not running', async () => {
      shutdownRustEngine();

      await expect(rustRpc('test.method')).rejects.toEqual(
        expect.objectContaining({ message: expect.stringContaining('not running') })
      );
    });

    it('should write JSON-RPC request to stdin', () => {
      initRustEngine();

      // Fire-and-forget — catch to avoid unhandled rejection on shutdown
      rustRpc('profiles.list', { foo: 'bar' }).catch(() => {});

      expect(mockProc.stdin.write).toHaveBeenCalledTimes(1);
      const written = mockProc.stdin.write.mock.calls[0][0];
      const parsed = JSON.parse(written.trim());
      expect(parsed.jsonrpc).toBe('2.0');
      expect(parsed.method).toBe('profiles.list');
      expect(parsed.params).toEqual({ foo: 'bar' });
      expect(typeof parsed.id).toBe('number');
    });

    it('should increment request IDs', () => {
      initRustEngine();

      rustRpc('method1').catch(() => {});
      rustRpc('method2').catch(() => {});

      const id1 = JSON.parse(mockProc.stdin.write.mock.calls[0][0].trim()).id;
      const id2 = JSON.parse(mockProc.stdin.write.mock.calls[1][0].trim()).id;
      expect(id2).toBe(id1 + 1);
    });

    it('should reject on timeout', async () => {
      initRustEngine();

      const promise = rustRpc('slow.method');

      vi.advanceTimersByTime(31000);

      await expect(promise).rejects.toEqual(
        expect.objectContaining({ message: expect.stringContaining('timed out') })
      );
    });
  });

  describe('auto-restart', () => {
    it('should reject pending requests when process exits', () => {
      initRustEngine();

      const promise = rustRpc('test.method');
      mockProc.emit('close', 1);

      return expect(promise).rejects.toEqual(
        expect.objectContaining({ message: expect.stringContaining('exited unexpectedly') })
      );
    });

    it('should not restart on clean exit (code 0)', () => {
      initRustEngine();
      spawn.mockClear();

      mockProc.emit('close', 0);

      vi.advanceTimersByTime(5000);
      expect(spawn).not.toHaveBeenCalled();
    });

    it('should attempt restart on crash exit', () => {
      initRustEngine();
      spawn.mockClear();

      const newMockProc = createMockProcess();
      spawn.mockReturnValue(newMockProc);

      mockProc.emit('close', 1);

      vi.advanceTimersByTime(2500);
      expect(spawn).toHaveBeenCalledTimes(1);
    });
  });
});
