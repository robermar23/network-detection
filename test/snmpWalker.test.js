import { describe, it, expect, vi, beforeEach } from 'vitest';
import { snmpWalk, cancelSnmpWalk } from '../src/main/snmpWalker.js';
import snmp from 'net-snmp';

// Mock net-snmp
vi.mock('net-snmp', () => {
  return {
    default: {
      Version1: 0,
      Version2c: 1,
      Version3: 3,
      SecurityLevel: { noAuthNoPriv: 1, authNoPriv: 2, authPriv: 3 },
      AuthProtocols: { md5: 1, sha: 2 },
      PrivProtocols: { des: 1, aes: 2 },
      createSession: vi.fn(),
      createV3Session: vi.fn(),
      isVarbindError: vi.fn((vb) => vb.type === 128), // 128 is an error type in SNMP
      varbindError: vi.fn(() => 'MockError')
    }
  };
});

describe('SNMP Walker', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('snmpWalk (v1/v2c)', () => {
    it('creates session and walks given OID', () => {
      const mockSession = {
        walk: vi.fn((oid, max, cb, done) => {
          // Simulate some results
          cb([{ oid: [1,3,6,1,2,1,1,1], type: 4, value: Buffer.from('Test Router') }]);
          done();
        }),
        close: vi.fn()
      };
      
      snmp.createSession.mockReturnValue(mockSession);

      const onResult = vi.fn();
      const onProgress = vi.fn();
      const onComplete = vi.fn();
      const onError = vi.fn();

      snmpWalk('10.0.0.1', { version: 'v2c', community: 'public' }, onResult, onProgress, onComplete, onError);

      expect(snmp.createSession).toHaveBeenCalledWith('10.0.0.1', 'public', expect.any(Object));
      expect(mockSession.walk).toHaveBeenCalledWith('1.3.6.1.2.1', 20, expect.any(Function), expect.any(Function));
      
      expect(onResult).toHaveBeenCalledTimes(1);
      expect(onResult).toHaveBeenCalledWith(expect.objectContaining({ 
        targetIp: '10.0.0.1',
        oid: '1.3.6.1.2.1.1.1',
        value: 'Test Router'
      }));
      expect(onComplete).toHaveBeenCalledWith({ targetIp: '10.0.0.1', totalOids: 1 });
      expect(onError).not.toHaveBeenCalled();
    });

    it('prevents concurrent walks on the same IP', () => {
      const mockSession = { walk: vi.fn(), close: vi.fn() };
      snmp.createSession.mockReturnValue(mockSession);

      const onError1 = vi.fn();
      const onError2 = vi.fn();

      snmpWalk('10.0.0.2', { version: 'v2c' }, vi.fn(), vi.fn(), vi.fn(), onError1);
      snmpWalk('10.0.0.2', { version: 'v2c' }, vi.fn(), vi.fn(), vi.fn(), onError2);

      expect(onError1).not.toHaveBeenCalled();
      expect(onError2).toHaveBeenCalledWith(expect.objectContaining({ error: expect.stringContaining('already in progress') }));
    });
  });

  describe('snmpWalk Intelligence', () => {
    it('extracts OS and Vendor from sysDescr', () => {
      const mockSession = {
        walk: vi.fn((oid, max, cb, done) => {
          cb([{ 
            oid: [1,3,6,1,2,1,1,1,0], 
            type: 4, 
            value: Buffer.from('Hardware: x86 - Software: Windows 10') 
          }]);
          done();
        }),
        close: vi.fn()
      };
      snmp.createSession.mockReturnValue(mockSession);
      const onIntel = vi.fn();
      
      snmpWalk('10.0.0.1', {}, vi.fn(), vi.fn(), vi.fn(), vi.fn(), onIntel);
      
      expect(onIntel).toHaveBeenCalledWith(expect.objectContaining({ type: 'os', value: 'Windows 10' }));
      expect(onIntel).toHaveBeenCalledWith(expect.objectContaining({ type: 'vendor', value: 'x86' }));
    });

    it('extracts ARP discovery data', () => {
      const mockSession = {
        walk: vi.fn((oid, max, cb, done) => {
          cb([{ 
            oid: [1,3,6,1,2,1,4,22,1,2,1,192,168,1,50], 
            type: 4, 
            value: Buffer.from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) 
          }]);
          done();
        }),
        close: vi.fn()
      };
      snmp.createSession.mockReturnValue(mockSession);
      const onIntel = vi.fn();
      
      snmpWalk('10.0.0.1', {}, vi.fn(), vi.fn(), vi.fn(), vi.fn(), onIntel);
      
      expect(onIntel).toHaveBeenCalledWith(expect.objectContaining({ 
        type: 'arp-discovery', 
        discoveredIp: '192.168.1.50',
        discoveredMac: '00:11:22:33:44:55'
      }));
    });

    it('extracts process names', () => {
      const mockSession = {
        walk: vi.fn((oid, max, cb, done) => {
          cb([{ 
            oid: [1,3,6,1,2,1,25,4,2,1,2,1001], 
            type: 4, 
            value: Buffer.from('systemd') 
          }]);
          done();
        }),
        close: vi.fn()
      };
      snmp.createSession.mockReturnValue(mockSession);
      const onIntel = vi.fn();
      
      snmpWalk('10.0.0.1', {}, vi.fn(), vi.fn(), vi.fn(), vi.fn(), onIntel);
      
      expect(onIntel).toHaveBeenCalledWith(expect.objectContaining({ 
        type: 'process-discovery', 
        processName: 'systemd' 
      }));
    });
  });

  describe('snmpGet', () => {
    it('resolves with multiple OID results', async () => {
      const { snmpGet } = await import('../src/main/snmpWalker.js');
      const mockSession = {
        get: vi.fn((oids, cb) => {
          cb(null, [
            { oid: [1,3,6,1,2,1,1,5,0], value: Buffer.from('HostA'), type: 4 }
          ]);
        }),
        close: vi.fn()
      };
      snmp.createSession.mockReturnValue(mockSession);

      const results = await snmpGet('10.0.0.1', ['1.3.6.1.2.1.1.5.0'], {});
      expect(results[0].value).toBe('HostA');
      expect(mockSession.close).toHaveBeenCalled();
    });

    it('rejects on session error', async () => {
      const { snmpGet } = await import('../src/main/snmpWalker.js');
      const mockSession = {
        get: vi.fn((oids, cb) => cb(new Error('SNMP Error'))),
        close: vi.fn()
      };
      snmp.createSession.mockReturnValue(mockSession);

      await expect(snmpGet('10.0.0.1', ['1.3.6.1.2.1'], {})).rejects.toThrow('SNMP Error');
    });
  });

  describe('cancelSnmpWalk', () => {
    it('closes the session and removes from active walks', () => {
      const mockSession = { walk: vi.fn(), close: vi.fn() };
      snmp.createSession.mockReturnValue(mockSession);

      snmpWalk('10.0.0.3', { version: 'v2c' }, vi.fn(), vi.fn(), vi.fn(), vi.fn());
      
      const res = cancelSnmpWalk('10.0.0.3');
      expect(res).toBe(true);
      expect(mockSession.close).toHaveBeenCalled();
    });
  });
});
