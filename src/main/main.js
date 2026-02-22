import { app, BrowserWindow, ipcMain } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';

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
ipcMain.handle('scan-network', async (event, args) => {
  console.log('Scan requested');
  return { status: 'scanning' };
});

ipcMain.handle('stop-scan', async (event) => {
  console.log('Stop requested');
  return { status: 'stopped' };
});

ipcMain.handle('save-results', async (event, results) => {
  console.log('Save requested', results);
  return { status: 'saved' };
});

ipcMain.handle('load-results', async (event) => {
  console.log('Load requested');
  return { status: 'loaded', data: [] };
});

ipcMain.handle('clear-results', async (event) => {
  console.log('Clear requested');
  return { status: 'cleared' };
});

ipcMain.on('exit-app', () => {
  app.quit();
});
