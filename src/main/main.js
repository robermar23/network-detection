import { app, BrowserWindow, ipcMain, shell, dialog } from 'electron';
import pkg from 'electron-updater';
const { autoUpdater } = pkg;
import { IPC_CHANNELS } from '../shared/ipc.js';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { spawn, exec } from 'child_process';
import { startNetworkScan, stopNetworkScan, getNetworkInterfaces } from './scanner.js';
import { runDeepScan, cancelDeepScan } from './deepScanner.js';
import { checkNmapInstalled, runNmapScan, cancelNmapScan } from './nmapScanner.js';
import { createMainWindow } from './windowManager.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const isDev = process.env.NODE_ENV === 'development';

let mainWindow;

function createWindow() {
  mainWindow = createMainWindow(
    isDev, 
    (p) => path.join(__dirname, p), 
    'http://localhost:5173'
  );
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });

  // Init Auto-Updater
  autoUpdater.logger = console;
  autoUpdater.checkForUpdatesAndNotify();

  autoUpdater.on('update-available', () => {
    console.log('Update available.');
  });

  autoUpdater.on('download-progress', (progressObj) => {
    console.log(`Download speed: ${progressObj.bytesPerSecond} - Downloaded ${progressObj.percent}% (${progressObj.transferred}/${progressObj.total})`);
  });

  autoUpdater.on('update-downloaded', () => {
    console.log('Update downloaded. Prompting user to install.');
    dialog.showMessageBox({
      type: 'info',
      title: 'Update Ready',
      message: 'A new version of NetSpecter is ready. Quit and Install now?',
      buttons: ['Yes', 'Later']
    }).then((result) => {
      if (result.response === 0) {
        autoUpdater.quitAndInstall();
      }
    });
  });
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});

// IPC Handler stubs for future Network Scanner logic
ipcMain.handle(IPC_CHANNELS.GET_INTERFACES, async () => {
  return getNetworkInterfaces();
});

ipcMain.handle(IPC_CHANNELS.SCAN_NETWORK, async (event, subnet) => {
  console.log(`Scan requested on subnet: ${subnet}`);
  
  startNetworkScan(
    subnet,
    (hostData) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.HOST_FOUND, hostData);
    },
    (completeMsg) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.SCAN_COMPLETE, completeMsg);
    }
  );

  return { status: 'scanning' };
});

ipcMain.handle(IPC_CHANNELS.RUN_DEEP_SCAN, async (event, ip) => {
  console.log(`Deep scan requested for ${ip}`);
  
  // Run asynchronously without blocking
  runDeepScan(ip, (portData) => {
    if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.DEEP_SCAN_RESULT, { ip, ...portData });
  }, (progressData) => {
    if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.DEEP_SCAN_PROGRESS, progressData);
  }).then(() => {
    if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.DEEP_SCAN_COMPLETE, { ip });
  }).catch(err => {
    console.error(`Deep scan error on ${ip}:`, err);
  });

  return { status: 'started' };
});

ipcMain.handle(IPC_CHANNELS.CANCEL_DEEP_SCAN, async (event, ip) => {
  console.log(`Deep scan cancel requested for ${ip}`);
  cancelDeepScan(ip);
  return { status: 'cancelled' };
});

ipcMain.handle(IPC_CHANNELS.CHECK_NMAP, async () => {
  return await checkNmapInstalled();
});

ipcMain.handle(IPC_CHANNELS.RUN_NMAP_SCAN, async (event, { type, target }) => {
  console.log(`Nmap scan requested: ${type} on ${target}`);
  
  runNmapScan(type, target, 
    (chunkData) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.NMAP_SCAN_RESULT, { target, type, ...chunkData });
    },
    (completeData) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.NMAP_SCAN_COMPLETE, { type, ...completeData });
    },
    (errorData) => {
      if (mainWindow) mainWindow.webContents.send(IPC_CHANNELS.NMAP_SCAN_ERROR, { target, type, ...errorData });
    }
  );

  return { status: 'started' };
});

ipcMain.handle(IPC_CHANNELS.CANCEL_NMAP_SCAN, async (event, target) => {
  console.log(`Nmap scan cancel requested for ${target}`);
  const success = cancelNmapScan(target);
  return { status: success ? 'cancelled' : 'not_found' };
});

ipcMain.handle(IPC_CHANNELS.STOP_SCAN, async (event) => {
  console.log('Stop requested');
  stopNetworkScan();
  return { status: 'stopped' };
});

ipcMain.handle(IPC_CHANNELS.OPEN_EXTERNAL_ACTION, async (event, { type, ip, port, username }) => {
  console.log(`External action requested: ${type} to ${ip}:${port}`);
  
  // Detailed Security Payload Validation
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  if (!ip || !ipRegex.test(ip)) {
     console.error('INVALID IP FORMAT REJECTED');
     return { success: false, error: 'Invalid IP address format' };
  }
  
  if (port) {
     const parsedPort = parseInt(port, 10);
     if (isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
       console.error('INVALID PORT BOUNDS REJECTED');
       return { success: false, error: 'Invalid port number' };
     }
  }

  try {
    if (type === 'http' || type === 'https') {
      await shell.openExternal(`${type}://${ip}${port ? ':' + port : ''}`);
    } else if (type === 'ssh') {
      const user = (username || 'root').replace(/[^a-zA-Z0-9_\-]/g, ''); // Basic sanitization
      if (process.platform === 'win32') {
        spawn('cmd.exe', ['/c', 'start', 'cmd.exe', '/k', `ssh ${user}@${ip}`]);
      } else if (process.platform === 'darwin') {
        exec(`osascript -e 'tell app "Terminal" to do script "ssh ${user}@${ip}"'`);
      } else {
        exec(`gnome-terminal -- ssh ${user}@${ip}`);
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

ipcMain.handle(IPC_CHANNELS.SAVE_RESULTS, async (event, results) => {
  console.log('Save requested', results?.length || 0);
  try {
    const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
      title: 'Save NetSpecter Scan',
      defaultPath: path.join(app.getPath('documents'), 'scan_results.json'),
      filters: [{ name: 'JSON Files', extensions: ['json'] }]
    });

    if (canceled || !filePath) return { status: 'cancelled' };

    fs.writeFileSync(filePath, JSON.stringify(results, null, 2));
    return { status: 'saved', path: filePath };
  } catch (e) {
    console.error('Save failed:', e);
    return { status: 'error', error: e.message };
  }
});

ipcMain.handle(IPC_CHANNELS.LOAD_RESULTS, async (event) => {
  console.log('Load requested');
  try {
    const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
      title: 'Load NetSpecter Scan',
      properties: ['openFile'],
      filters: [{ name: 'JSON Files', extensions: ['json'] }]
    });

    if (canceled || filePaths.length === 0) return { status: 'cancelled' };

    const savePath = filePaths[0];
    if (fs.existsSync(savePath)) {
      const data = JSON.parse(fs.readFileSync(savePath, 'utf8'));
      return { status: 'loaded', data, path: savePath };
    }
    
    return { status: 'no_file' };
  } catch (e) {
    console.error('Load failed:', e);
    return { status: 'error', error: e.message };
  }
});

ipcMain.handle(IPC_CHANNELS.CLEAR_RESULTS, async (event) => {
  console.log('Clear requested');
  return { status: 'cleared' };
});

ipcMain.on(IPC_CHANNELS.EXIT_APP, () => {
  app.quit();
});
