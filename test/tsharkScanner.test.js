import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { startTsharkCapture, stopTsharkCapture } from '../src/main/tsharkScanner.js';
import { spawn } from 'child_process';
import { EventEmitter } from 'events';
import split2 from 'split2';

vi.mock('child_process', () => ({
  spawn: vi.fn()
}));

vi.mock('split2', () => ({
  default: vi.fn(() => {
    const ee = new (require('events').EventEmitter)();
    return ee;
  })
}));

vi.mock('../src/main/store.js', () => ({
  getSetting: vi.fn().mockReturnValue('')
}));

function createMockProcess() {
  const stdout = new EventEmitter();
  stdout.pipe = vi.fn(() => {
    const splitStream = new EventEmitter();
    return splitStream;
  });
  const stderr = new EventEmitter();
  const proc = new EventEmitter();
  proc.stdout = stdout;
  proc.stderr = stderr;
  proc.kill = vi.fn();
  return proc;
}

describe('Tshark Scanner', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset module state: ensure tsharkProcess is null by stopping any prior capture
    stopTsharkCapture();
  });

  describe('startTsharkCapture', () => {
    it('should spawn tshark with correct arguments', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      startTsharkCapture('eth0', vi.fn(), vi.fn(), vi.fn());

      expect(spawn).toHaveBeenCalled();
      const args = spawn.mock.calls[0][1];
      expect(args).toContain('-i');
      expect(args).toContain('eth0');
      expect(args).toContain('-Y');
      expect(args).toContain('vlan');
    });

    it('should call onVlanDiscovered when valid VLAN data is parsed', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onVlanDiscovered = vi.fn();
      startTsharkCapture('eth0', onVlanDiscovered, vi.fn(), vi.fn());

      // Get the split stream from pipe
      const splitStream = mockProc.stdout.pipe.mock.results[0].value;
      // Simulate VLAN data line
      splitStream.emit('data', '10\tAA:BB:CC:DD:EE:FF\t11:22:33:44:55:66');

      expect(onVlanDiscovered).toHaveBeenCalledWith({
        vlan: 10,
        srcMac: 'AA:BB:CC:DD:EE:FF',
        dstMac: '11:22:33:44:55:66'
      });
    });

    it('should handle stacked VLAN IDs', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onVlanDiscovered = vi.fn();
      startTsharkCapture('eth0', onVlanDiscovered, vi.fn(), vi.fn());

      const splitStream = mockProc.stdout.pipe.mock.results[0].value;
      splitStream.emit('data', '10,20\tAA:BB:CC:DD:EE:FF\t11:22:33:44:55:66');

      expect(onVlanDiscovered).toHaveBeenCalledTimes(2);
    });

    it('should ignore short/invalid lines', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onVlanDiscovered = vi.fn();
      startTsharkCapture('eth0', onVlanDiscovered, vi.fn(), vi.fn());

      const splitStream = mockProc.stdout.pipe.mock.results[0].value;
      splitStream.emit('data', 'short');

      expect(onVlanDiscovered).not.toHaveBeenCalled();
    });

    it('should call onError for tshark stderr messages', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onError = vi.fn();
      startTsharkCapture('eth0', vi.fn(), onError, vi.fn());

      mockProc.stderr.emit('data', Buffer.from('Fatal error'));
      expect(onError).toHaveBeenCalledWith('Fatal error');
    });

    it('should ignore standard tshark noise on stderr', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onError = vi.fn();
      startTsharkCapture('eth0', vi.fn(), onError, vi.fn());

      mockProc.stderr.emit('data', Buffer.from('Capturing on eth0'));
      expect(onError).not.toHaveBeenCalled();
    });

    it('should call onComplete on process close', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onComplete = vi.fn();
      startTsharkCapture('eth0', vi.fn(), vi.fn(), onComplete);

      mockProc.emit('close', 0);
      expect(onComplete).toHaveBeenCalledWith({ code: 0 });
    });

    it('should call onError on process error', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      const onError = vi.fn();
      startTsharkCapture('eth0', vi.fn(), onError, vi.fn());

      mockProc.emit('error', new Error('ENOENT'));
      expect(onError).toHaveBeenCalledWith('ENOENT');
    });
  });

  describe('stopTsharkCapture', () => {
    it('should return false when no capture is running', () => {
      expect(stopTsharkCapture()).toBe(false);
    });

    it('should return true and kill process when capture is running', () => {
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);

      startTsharkCapture('eth0', vi.fn(), vi.fn(), vi.fn());
      const result = stopTsharkCapture();

      expect(result).toBe(true);
      expect(mockProc.kill).toHaveBeenCalledWith('SIGINT');
    });
  });
});
