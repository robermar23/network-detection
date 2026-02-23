import { app, BrowserWindow } from 'electron';
import Store from 'electron-store';
import path from 'path';

// electron-store requires app to be ready, or we instantiate it dynamically
let store;

export function createMainWindow(isDev, resolvePath, webURL) {
  if (!store) {
    store = new Store({
      name: 'window-state',
      defaults: {
        windowBounds: { width: 1200, height: 800 }
      }
    });
  }

  const { width, height, x, y } = store.get('windowBounds');

  const mainWindow = new BrowserWindow({
    width,
    height,
    x,
    y,
    minWidth: 800,
    minHeight: 600,
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#1e1e24',
      symbolColor: '#ffffff',
      height: 35
    },
    webPreferences: {
      preload: resolvePath('preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      allowRunningInsecureContent: false,
      experimentalFeatures: false
    },
    show: false,
    backgroundColor: '#0f0f13'
  });

  // Debounce save window bounds
  let debounceTimer;
  const saveBounds = () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        store.set('windowBounds', mainWindow.getBounds());
      }
    }, 500);
  };

  mainWindow.on('resize', saveBounds);
  mainWindow.on('move', saveBounds);

  if (isDev) {
    mainWindow.loadURL(webURL || 'http://localhost:5173');
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(resolvePath('../../dist/index.html'));
  }

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  return mainWindow;
}
