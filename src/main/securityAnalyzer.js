import net from 'net';
import http from 'http';
import https from 'https';
import tls from 'tls';

const TIMEOUT_MS = 1500;

export async function checkAnonymousFtp(ip, port) {
  return new Promise((resolve) => {
    let resolved = false;
    const socket = new net.Socket();
    
    const finish = (result) => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve(result);
      }
    };

    let step = 0;
    
    socket.setTimeout(TIMEOUT_MS);
    
    socket.on('connect', () => {
      // connected, waiting for initial 220 banner...
    });
    
    socket.on('data', (data) => {
      const response = data.toString('utf-8').trim();
      
      if (step === 0 && response.startsWith('220')) {
        step = 1;
        socket.write('USER anonymous\r\n');
      } else if (step === 1 && (response.startsWith('331') || response.startsWith('230'))) {
        step = 2;
        socket.write('PASS anonymous@domain.com\r\n');
      } else if (step === 2) {
        if (response.startsWith('230')) {
          finish({ vulnerable: true, details: 'CRITICAL: Anonymous FTP Login Allowed. File system is exposed.' });
        } else {
          finish({ vulnerable: false, details: 'Anonymous FTP Login Rejected.' });
        }
      } else {
        finish(null); // Unexpected flow
      }
    });

    socket.on('error', () => finish(null));
    socket.on('timeout', () => finish(null));
    
    socket.connect(port, ip);
  });
}

function fetchHttp(ip, port, path, isTls) {
  return new Promise((resolve) => {
    const protocol = isTls ? https : http;
    const options = {
      hostname: ip,
      port: port,
      path: path,
      method: 'GET',
      timeout: TIMEOUT_MS,
      rejectUnauthorized: false // Ignore self-signed certs for forensics
    };

    const req = protocol.request(options, (res) => {
      if (res.statusCode === 200) {
        resolve(true); // Content found!
      } else {
        resolve(false);
      }
    });

    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}

export async function checkSensitiveWebDirs(ip, port, isTls) {
  const sensitivePaths = [
    '/.env',
    '/.git/config',
    '/wp-config.php.bak'
  ];

  const results = [];
  
  for (const path of sensitivePaths) {
    const isExposed = await fetchHttp(ip, port, path, isTls);
    if (isExposed) {
      results.push(path);
    }
  }

  if (results.length > 0) {
    return {
      vulnerable: true,
      details: `CRITICAL: Exposed sensitive web files found: ${results.join(', ')}`
    };
  }

  return { vulnerable: false, details: 'No common sensitive web files detected.' };
}
