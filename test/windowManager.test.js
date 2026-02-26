import { describe, it, expect, vi, beforeEach } from 'vitest';

// Must mock electron BEFORE import
vi.mock('electron', () => {
  const mockInstances = [];
  
  class BrowserWindowMock {
    constructor(opts) {
      this._opts = opts;
      this._onHandlers = {};
      this._onceHandlers = {};
      this.webContents = {
        openDevTools: vi.fn()
      };
      this.loadURL = vi.fn();
      this.loadFile = vi.fn();
      this.show = vi.fn();
      this.getBounds = vi.fn().mockReturnValue({ x: 100, y: 100, width: 1200, height: 800 });
      this.isDestroyed = vi.fn().mockReturnValue(false);
      mockInstances.push(this);
    }
    on(event, cb) { 
      if (!this._onHandlers[event]) this._onHandlers[event] = [];
      this._onHandlers[event].push(cb);
    }
    once(event, cb) {
      if (!this._onceHandlers[event]) this._onceHandlers[event] = [];
      this._onceHandlers[event].push(cb);
    }
  }

  return {
    app: {
      getPath: vi.fn().mockReturnValue('/home/user')
    },
    BrowserWindow: BrowserWindowMock,
    _mockInstances: mockInstances
  };
});

// Mock electron-store
vi.mock('electron-store', () => {
  return {
    default: class MockStore {
      constructor(opts) {
        this.data = opts?.defaults || {};
      }
      get(key) {
        return this.data[key];
      }
      set(key, value) {
        this.data[key] = value;
      }
    }
  };
});

import { createMainWindow } from '../src/main/windowManager.js';
import { BrowserWindow, _mockInstances } from 'electron';

describe('Window Manager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _mockInstances.length = 0;
  });

  it('should create a BrowserWindow with correct security settings', () => {
    const resolvePath = vi.fn((p) => `/fake/path/${p}`);
    const win = createMainWindow(false, resolvePath);

    expect(_mockInstances.length).toBe(1);
    const opts = _mockInstances[0]._opts;
    expect(opts.webPreferences.contextIsolation).toBe(true);
    expect(opts.webPreferences.nodeIntegration).toBe(false);
    expect(opts.webPreferences.allowRunningInsecureContent).toBe(false);
    expect(opts.webPreferences.experimentalFeatures).toBe(false);
  });

  it('should load file in production mode', () => {
    const resolvePath = vi.fn((p) => `/fake/path/${p}`);
    const win = createMainWindow(false, resolvePath);
    expect(win.loadFile).toHaveBeenCalled();
    expect(win.loadURL).not.toHaveBeenCalled();
  });

  it('should load URL in development mode', () => {
    const resolvePath = vi.fn((p) => `/fake/path/${p}`);
    const win = createMainWindow(true, resolvePath, 'http://localhost:5173');
    expect(win.loadURL).toHaveBeenCalledWith('http://localhost:5173');
    expect(win.webContents.openDevTools).toHaveBeenCalled();
  });

  it('should use default dev URL when webURL is not provided', () => {
    const resolvePath = vi.fn((p) => `/fake/path/${p}`);
    const win = createMainWindow(true, resolvePath);
    expect(win.loadURL).toHaveBeenCalledWith('http://localhost:5173');
  });

  it('should return a window instance', () => {
    const resolvePath = vi.fn((p) => `/fake/path/${p}`);
    const win = createMainWindow(false, resolvePath);
    expect(win).toBeDefined();
    expect(typeof win.on).toBe('function');
  });

  it('should register resize and move event handlers', () => {
    const resolvePath = vi.fn((p) => `/fake/path/${p}`);
    const win = createMainWindow(false, resolvePath);
    expect(win._onHandlers['resize']).toBeDefined();
    expect(win._onHandlers['move']).toBeDefined();
  });

  it('should register ready-to-show event', () => {
    const resolvePath = vi.fn((p) => `/fake/path/${p}`);
    const win = createMainWindow(false, resolvePath);
    expect(win._onceHandlers['ready-to-show']).toBeDefined();
  });

  it('should set minimum window dimensions', () => {
    const resolvePath = vi.fn((p) => `/fake/path/${p}`);
    createMainWindow(false, resolvePath);
    const opts = _mockInstances[0]._opts;
    expect(opts.minWidth).toBe(800);
    expect(opts.minHeight).toBe(600);
  });

  it('should show window as hidden initially', () => {
    const resolvePath = vi.fn((p) => `/fake/path/${p}`);
    createMainWindow(false, resolvePath);
    const opts = _mockInstances[0]._opts;
    expect(opts.show).toBe(false);
  });
});
