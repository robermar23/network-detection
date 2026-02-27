import { describe, it, expect, vi, beforeEach } from 'vitest';
import { startCredentialSniffing, stopCredentialSniffing } from '../src/main/credentialSniffer.js';
import * as passiveCapture from '../src/main/passiveCapture.js';

vi.mock('../src/main/passiveCapture.js', () => ({
  startModule: vi.fn(),
  stopModule: vi.fn()
}));

describe('Credential Sniffer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('startCredentialSniffing', () => {
    it('should delegate to startModule with correct arguments', () => {
      passiveCapture.startModule.mockReturnValue(true);
      
      const onFound = vi.fn();
      const onError = vi.fn();
      const onComplete = vi.fn();
      
      const result = startCredentialSniffing('eth0', onFound, onError, onComplete);
      
      expect(result).toBe(true);
      expect(passiveCapture.startModule).toHaveBeenCalledWith(
        'creds',
        'eth0',
        expect.arrayContaining(['-Y', expect.stringContaining('ftp.request.command')]),
        expect.any(Function),
        onError,
        onComplete
      );
    });

    it('should correlate FTP USER and PASS and mask password', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onFound = vi.fn();
      startCredentialSniffing('eth0', onFound, vi.fn(), vi.fn());

      // FTP USER: IP src, dst, port, ftpCmd, ftpArg, ...
      lineParser('10.0.0.2\t10.0.0.1\t21\tUSER\tadmin\t\t\t\t');
      expect(onFound).not.toHaveBeenCalled();

      // FTP PASS: 
      lineParser('10.0.0.2\t10.0.0.1\t21\tPASS\tsecret123\t\t\t\t');
      
      expect(onFound).toHaveBeenCalledTimes(1);
      expect(onFound).toHaveBeenCalledWith(expect.objectContaining({
        protocol: 'FTP',
        srcIp: '10.0.0.2',
        username: 'admin',
        password: 'secret123',
        maskedPassword: 's*******3'
      }));
    });

    it('should handle HTTP Basic Auth decoding', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onFound = vi.fn();
      startCredentialSniffing('eth0', onFound, vi.fn(), vi.fn());

      // b64 for admin:password is YWRtaW46cGFzc3dvcmQ=
      lineParser('10.0.0.2\t10.0.0.1\t80\t\t\tBasic YWRtaW46cGFzc3dvcmQ=\t\t\t');
      
      expect(onFound).toHaveBeenCalledTimes(1);
      expect(onFound).toHaveBeenCalledWith(expect.objectContaining({
        protocol: 'HTTP Basic',
        username: 'admin',
        password: 'password',
        maskedPassword: 'p******d'
      }));
    });

    it('should extract IMAP LOGIN credentials', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onFound = vi.fn();
      startCredentialSniffing('eth0', onFound, vi.fn(), vi.fn());

      lineParser('10.0.0.2\t10.0.0.1\t143\t\t\t\t\t\t001 LOGIN john "mypassword"');
      
      expect(onFound).toHaveBeenCalledTimes(1);
      expect(onFound).toHaveBeenCalledWith(expect.objectContaining({
        protocol: 'IMAP',
        username: 'john',
        password: 'mypassword',
        maskedPassword: 'm********d'
      }));
    });

    it('should not emit if USER seen without PASS', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onFound = vi.fn();
      startCredentialSniffing('eth0', onFound, vi.fn(), vi.fn());

      lineParser('10.0.0.2\t10.0.0.1\t110\t\t\t\tUSER\tadmin\t');
      expect(onFound).not.toHaveBeenCalled();
    });

    it('should handle short passwords for masking', () => {
      let lineParser;
      passiveCapture.startModule.mockImplementation((id, iface, args, parser) => {
        lineParser = parser;
        return true;
      });

      const onFound = vi.fn();
      startCredentialSniffing('eth0', onFound, vi.fn(), vi.fn());

      // b64 for root:ab is cm9vdDphYg==
      lineParser('10.0.0.2\t10.0.0.1\t80\t\t\tBasic cm9vdDphYg==\t\t\t');
      
      expect(onFound).toHaveBeenCalledTimes(1);
      expect(onFound).toHaveBeenCalledWith(expect.objectContaining({
        maskedPassword: '***'
      }));
    });
  });

  describe('stopCredentialSniffing', () => {
    it('should call stopModule', () => {
      passiveCapture.stopModule.mockReturnValue(true);
      const res = stopCredentialSniffing();
      expect(res).toBe(true);
      expect(passiveCapture.stopModule).toHaveBeenCalledWith('creds');
    });
  });
});
