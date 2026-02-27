import { describe, it, expect, vi, beforeEach } from 'vitest';
import { exportPcap } from '../src/main/pcapExporter.js';
import { spawn } from 'child_process';
import { dialog } from 'electron';
import { EventEmitter } from 'events';

vi.mock('child_process', () => ({
  spawn: vi.fn()
}));

vi.mock('electron', () => ({
  dialog: {
    showSaveDialog: vi.fn()
  }
}));

vi.mock('../src/main/store.js', () => ({
  getSetting: vi.fn().mockReturnValue('')
}));

function createMockProcess() {
  const stderr = new EventEmitter();
  const proc = new EventEmitter();
  proc.stderr = stderr;
  return proc;
}

describe('PCAP Exporter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('exportPcap', () => {
    it('should return cancelled if user cancels dialog', async () => {
      dialog.showSaveDialog.mockResolvedValue({ canceled: true });
      
      const res = await exportPcap({}, 'eth0', '', '60', vi.fn(), vi.fn());
      
      expect(res).toEqual({ success: true, status: 'cancelled' });
      expect(spawn).not.toHaveBeenCalled();
    });

    it('should spawn tshark with correct parameters', async () => {
      dialog.showSaveDialog.mockResolvedValue({ canceled: false, filePath: '/tmp/test.pcap' });
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);
      
      const res = await exportPcap({}, 'eth0', '', '60', vi.fn(), vi.fn());
      
      expect(res).toEqual({ success: true, status: 'started' });
      expect(spawn).toHaveBeenCalled();
      const args = spawn.mock.calls[0][1];
      expect(args).toContain('-i');
      expect(args).toContain('eth0');
      expect(args).toContain('-w');
      expect(args).toContain('/tmp/test.pcap');
      expect(args).toContain('-a');
      expect(args).toContain('duration:60');
      expect(args).not.toContain('-f');
      mockProc.emit('close', 0);
    });

    it('should append host BPF filter if hostIp is provided', async () => {
      dialog.showSaveDialog.mockResolvedValue({ canceled: false, filePath: '/tmp/test.pcap' });
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);
      
      await exportPcap({}, 'eth0', '192.168.1.10', '60', vi.fn(), vi.fn());
      
      const args = spawn.mock.calls[0][1];
      expect(args).toContain('-f');
      expect(args).toContain('host 192.168.1.10');
      mockProc.emit('close', 0);
    });

    it('should refuse to start if an export is already running', async () => {
      dialog.showSaveDialog.mockResolvedValue({ canceled: false, filePath: '/tmp/test.pcap' });
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);
      
      await exportPcap({}, 'eth0', '', '60', vi.fn(), vi.fn());
      
      // Try again while first is running (promise is resolved but process is active)
      const res2 = await exportPcap({}, 'eth0', '', '60', vi.fn(), vi.fn());
      expect(res2).toEqual({ success: false, error: 'Export already running' });
      
      // Cleanup for other tests
      mockProc.emit('close', 0);
    });

    it('should report correct packet count on complete', async () => {
      dialog.showSaveDialog.mockResolvedValue({ canceled: false, filePath: '/tmp/test.pcap' });
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);
      
      const onComplete = vi.fn();
      await exportPcap({}, 'eth0', '', '60', onComplete, vi.fn());
      
      mockProc.stderr.emit('data', Buffer.from('1542 packets captured\n'));
      mockProc.emit('close', 0);
      
      expect(onComplete).toHaveBeenCalledWith({
        filePath: '/tmp/test.pcap',
        packetCount: 1542,
        duration: 60,
        status: 'complete'
      });
    });

    it('should call onError if tshark spawn fails', async () => {
      dialog.showSaveDialog.mockResolvedValue({ canceled: false, filePath: '/tmp/test.pcap' });
      const mockProc = createMockProcess();
      spawn.mockReturnValue(mockProc);
      
      const onError = vi.fn();
      await exportPcap({}, 'eth0', '', '60', vi.fn(), onError);
      
      mockProc.emit('error', new Error('EACCES'));
      
      expect(onError).toHaveBeenCalledWith('EACCES');
      mockProc.emit('close', 1);
    });
  });
});
