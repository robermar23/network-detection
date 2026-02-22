import { app, BrowserWindow, ipcMain, shell } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { spawn, exec } from 'child_process';
import { startNetworkScan, stopNetworkScan, getNetworkInterfaces } from './scanner.js';
import { runDeepScan, cancelDeepScan } from './deepScanner.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const isDev = process.env.NODE_ENV === 'development';

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#1e1e24',
      symbolColor: '#ffffff',
      height: 35
    },
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
    show: false,
    backgroundColor: '#0f0f13'
  });

  if (isDev) {
    // Load from Vite dev server
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools();
  } else {
    // Load from Production Build
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  // Graceful show to prevent white flashing
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});

// IPC Handler stubs for future Network Scanner logic
ipcMain.handle('get-interfaces', async () => {
  return getNetworkInterfaces();
});

ipcMain.handle('scan-network', async (event, subnet) => {
  console.log(`Scan requested on subnet: ${subnet}`);
  
  startNetworkScan(
    subnet,
    (hostData) => {
      if (mainWindow) mainWindow.webContents.send('host-found', hostData);
    },
    (completeMsg) => {
      if (mainWindow) mainWindow.webContents.send('scan-complete', completeMsg);
    }
  );

  return { status: 'scanning' };
});

ipcMain.handle('deep-scan-host', async (event, ip) => {
  console.log(`Deep scan requested for ${ip}`);
  
  // Run asynchronously without blocking
  runDeepScan(ip, (portData) => {
    if (mainWindow) mainWindow.webContents.send('deep-scan-result', { ip, ...portData });
  }, (progressData) => {
    if (mainWindow) mainWindow.webContents.send('deep-scan-progress', progressData);
  }).then(() => {
    if (mainWindow) mainWindow.webContents.send('deep-scan-complete', { ip });
  }).catch(err => {
    console.error(`Deep scan error on ${ip}:`, err);
  });

  return { status: 'started' };
});

ipcMain.handle('cancel-deep-scan', async (event, ip) => {
  console.log(`Deep scan cancel requested for ${ip}`);
  cancelDeepScan(ip);
  return { status: 'cancelled' };
});

ipcMain.handle('stop-scan', async (event) => {
  console.log('Stop requested');
  stopNetworkScan();
  return { status: 'stopped' };
});

ipcMain.handle('open-external-action', async (event, { type, ip, port }) => {
  console.log(`External action requested: ${type} to ${ip}:${port}`);
  try {
    if (type === 'http' || type === 'https') {
      await shell.openExternal(`${type}://${ip}${port ? ':' + port : ''}`);
    } else if (type === 'ssh') {
      if (process.platform === 'win32') {
        spawn('cmd.exe', ['/c', 'start', 'cmd.exe', '/k', `ssh root@${ip}`]);
      } else if (process.platform === 'darwin') {
        exec(`osascript -e 'tell app "Terminal" to do script "ssh root@${ip}"'`);
      } else {
        exec(`gnome-terminal -- ssh root@${ip}`);
      }
    } else if (type === 'rdp') {
      if (process.platform === 'win32') {
        spawn('mstsc.exe', [`/v:${ip}`]);
      } else {
        console.warn('RDP launch only supported natively on Windows');
      }
    }
    return { success: true };
  } catch (err) {
    console.error(`Failed to launch external command:`, err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('save-results', async (event, results) => {
  console.log('Save requested', results?.length || 0);
  try {
    const savePath = path.join(__dirname, '../../scan_results.json');
    fs.writeFileSync(savePath, JSON.stringify(results, null, 2));
    return { status: 'saved' };
  } catch (e) {
    console.error('Save failed:', e);
    return { status: 'error', error: e.message };
  }
});

ipcMain.handle('load-results', async (event) => {
  console.log('Load requested');
  try {
    const savePath = path.join(__dirname, '../../scan_results.json');
    if (fs.existsSync(savePath)) {
      const data = JSON.parse(fs.readFileSync(savePath, 'utf8'));
      return { status: 'loaded', data };
    }
    return { status: 'no_file' };
  } catch (e) {
    console.error('Load failed:', e);
    return { status: 'error', error: e.message };
  }
});

ipcMain.handle('clear-results', async (event) => {
  console.log('Clear requested');
  return { status: 'cleared' };
});

ipcMain.on('exit-app', () => {
  app.quit();
});
