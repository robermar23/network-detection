import Store from 'electron-store';
import { exec } from 'child_process';
import util from 'util';

const execPromise = util.promisify(exec);

const schema = {
  nmap: {
    type: 'object',
    properties: {
      enabled: { type: 'boolean', default: true },
      path: { type: 'string', default: '' }
    },
    default: { enabled: true, path: '' }
  },
  tshark: {
    type: 'object',
    properties: {
      enabled: { type: 'boolean', default: false },
      path: { type: 'string', default: '' }
    },
    default: { enabled: false, path: '' }
  }
};

const store = new Store({ schema });

export function getSetting(key) {
  return store.get(key);
}

export function setSetting(key, value) {
  store.set(key, value);
}

export function getAllSettings() {
  return store.store;
}

export async function checkDependency(toolName) {
  let commandsToCheck = [];

  if (toolName === 'nmap') {
    commandsToCheck = [
      { cmd: 'nmap -V', path: 'nmap' }, // Check global PATH first
      { cmd: '"C:\\Program Files (x86)\\Nmap\\nmap.exe" -V', path: 'C:\\Program Files (x86)\\Nmap\\nmap.exe' },
      { cmd: '"C:\\Program Files\\Nmap\\nmap.exe" -V', path: 'C:\\Program Files\\Nmap\\nmap.exe' }
    ];
  } else if (toolName === 'tshark') {
    commandsToCheck = [
      { cmd: 'tshark -v', path: 'tshark' }, // Check global PATH first
      { cmd: '"C:\\Program Files\\Wireshark\\tshark.exe" -v', path: 'C:\\Program Files\\Wireshark\\tshark.exe' },
      { cmd: '"C:\\Program Files (x86)\\Wireshark\\tshark.exe" -v', path: 'C:\\Program Files (x86)\\Wireshark\\tshark.exe' }
    ];
  } else {
    throw new Error(`Unknown tool: ${toolName}`);
  }

  let lastError;
  for (const { cmd, path } of commandsToCheck) {
     try {
       const { stdout } = await execPromise(cmd);
       // Save discovered path automatically to the DB so scanners can use it
       setSetting(`${toolName}.path`, path);
       return { installed: true, output: stdout.split('\n')[0].trim() };
     } catch (error) {
       lastError = error;
     }
  }

  // If all failed
  setSetting(`${toolName}.path`, '');
  return { installed: false, error: lastError?.message || 'Unknown execution error' };
}
