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

  describe('snmpWalk (v3)', () => {
    it('creates v3 session with auth and priv keys', () => {
      const mockSession = { walk: vi.fn((oid, max, cb, done) => done()), close: vi.fn() };
      snmp.createV3Session.mockReturnValue(mockSession);

      snmpWalk('10.0.0.1', { 
        version: 'v3', 
        user: 'admin', 
        authKey: 'authpass', 
        authProtocol: 'sha',
        privKey: 'privpass',
        privProtocol: 'aes'
      }, vi.fn(), vi.fn(), vi.fn(), vi.fn());

      expect(snmp.createV3Session).toHaveBeenCalledWith('10.0.0.1', expect.objectContaining({
        name: 'admin',
        level: snmp.SecurityLevel.authPriv,
        authKey: 'authpass',
        privKey: 'privpass'
      }), expect.any(Object));
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

      // Ensure we can start a new walk now
      snmpWalk('10.0.0.3', { version: 'v2c' }, vi.fn(), vi.fn(), vi.fn(), vi.fn());
      expect(snmp.createSession).toHaveBeenCalledTimes(2);
    });
  });
});
