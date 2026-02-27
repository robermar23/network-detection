import { describe, it, expect, vi, beforeEach } from 'vitest';
import { startModule, stopModule, stopAll, getStatus } from '../src/main/passiveCapture.js';
import { spawn } from 'child_process';
import { EventEmitter } from 'events';
import split2 from 'split2';

vi.mock('child_process', () => ({
  spawn: vi.fn()
}));

vi.mock('split2', () => ({
  default: vi.fn(() => new EventEmitter())
}));

vi.mock('../src/main/store.js', () => ({
  getSetting: vi.fn().mockReturnValue('')
}));

function createMockProcess() {
  const stdout = new EventEmitter();
  stdout.pipe = vi.fn(() => new EventEmitter());
  const stderr = new EventEmitter();
  const proc = new EventEmitter();
  proc.stdout = stdout;
  proc.stderr = stderr;
  proc.kill = vi.fn();
  return proc;
}

describe('Passive Capture Module Manager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    stopAll();
  });

  describe('startModule', () => {
    it('should successfully start a new module and store it', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const result = startModule('testId', 'eth0', ['-Y', 'test'], vi.fn(), vi.fn(), vi.fn());
      
      expect(result).toBe(true);
      expect(spawn).toHaveBeenCalled();
      
      const args = spawn.mock.calls[0][1];
      expect(args).toEqual(expect.arrayContaining(['-i', 'eth0', '-Y', 'test']));
      expect(getStatus()).toContain('testId');
    });

    it('should refuse to start a module if its ID is already active', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      startModule('testId', 'eth0', [], vi.fn(), vi.fn(), vi.fn());
      const result2 = startModule('testId', 'eth0', [], vi.fn(), vi.fn(), vi.fn());

      expect(result2).toBe(false);
      expect(spawn).toHaveBeenCalledTimes(1);
    });

    it('should stream stdout lines to onLineParsed', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onLineParsed = vi.fn();
      startModule('testId', 'eth0', [], onLineParsed, vi.fn(), vi.fn());

      const splitStream = mockProc.stdout.pipe.mock.results[0].value;
      splitStream.emit('data', 'test output line');

      expect(onLineParsed).toHaveBeenCalledWith('test output line', mockProc);
    });

    it('should handle stderr data and pass to onError', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onError = vi.fn();
      startModule('testId', 'eth0', [], vi.fn(), onError, vi.fn());

      mockProc.stderr.emit('data', Buffer.from('fatal error'));
      expect(onError).toHaveBeenCalledWith('fatal error');
    });

    it('should ignore standard tshark noise on stderr', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onError = vi.fn();
      startModule('testId', 'eth0', [], vi.fn(), onError, vi.fn());

      mockProc.stderr.emit('data', Buffer.from('Capturing on eth0'));
      expect(onError).not.toHaveBeenCalled();
    });

    it('should clean up and call onError + onComplete if spawn emits error', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onError = vi.fn();
      const onComplete = vi.fn();
      startModule('testId', 'eth0', [], vi.fn(), onError, onComplete);

      mockProc.emit('error', new Error('ENOENT'));
      
      expect(onError).toHaveBeenCalledWith('ENOENT');
      expect(onComplete).toHaveBeenCalledWith(expect.objectContaining({ moduleId: 'testId', error: 'ENOENT' }));
      expect(getStatus()).not.toContain('testId');
    });
  });

  describe('stopModule', () => {
    it('should kill the matching process and remove it from state', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      startModule('testId', 'eth0', [], vi.fn(), vi.fn(), vi.fn());
      const result = stopModule('testId');

      expect(result).toBe(true);
      expect(mockProc.kill).toHaveBeenCalledWith('SIGINT');
      expect(getStatus()).not.toContain('testId');
    });

    it('should return false if the module is not running', () => {
      const result = stopModule('unknown');
      expect(result).toBe(false);
    });
  });

  describe('stopAll', () => {
    it('should kill all active modules and clear state', () => {
      const mockProc1 = createMockProcess();
      const mockProc2 = createMockProcess();
      spawn.mockReturnValueOnce(mockProc1).mockReturnValueOnce(mockProc2);

      startModule('test1', 'eth0', [], vi.fn(), vi.fn(), vi.fn());
      startModule('test2', 'eth0', [], vi.fn(), vi.fn(), vi.fn());
      
      const stopped = stopAll();

      expect(stopped).toEqual(['test1', 'test2']);
      expect(mockProc1.kill).toHaveBeenCalled();
      expect(mockProc2.kill).toHaveBeenCalled();
      expect(getStatus().length).toBe(0);
    });
  });
});
