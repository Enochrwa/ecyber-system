import { app, BrowserWindow, dialog } from 'electron';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isDev = !app.isPackaged;

let mainWindow;
let backendProcess;

const createWindow = () => {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    icon: path.join(__dirname, '..', 'public', 'eCyber.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.mjs'),
    },
  });

  if (isDev) {
    const indexPath = path.join(__dirname, '..', 'dist', 'index.html');
    console.log('[ElectronMain] PROD mode: Loading frontend from:', indexPath);

    if (fs.existsSync(indexPath)) {
      mainWindow.loadFile(indexPath);
    } else {
      dialog.showErrorBox(
        'Frontend Error',
        `Built frontend file not found: ${indexPath}`
      );
    }
  } else {
    
    console.log('[ElectronMain] DEV mode: Loading frontend from dev server');
    mainWindow.loadURL('http://localhost:4000');
    mainWindow.webContents.openDevTools();
  }
};

const startBackend = () => {
  const backendExeName = process.platform === 'win32' ? 'backend_server.exe' : 'backend_server';
  const prodBackendPath = path.join(process.resourcesPath, 'backend', backendExeName);
  const devBackendScript = path.join(__dirname, '..', '..', 'backend', 'loader.py');
  const devPythonInterpreter = path.join(__dirname, '..', '..', 'backend', 'venv', 'bin', 'python'); // Windows specific

  if (!isDev) {
    console.log('[ElectronMain] Looking for backend at:', prodBackendPath);

    if (fs.existsSync(prodBackendPath)) {
      console.log(`[ElectronMain] Starting packaged backend: ${prodBackendPath}`);
      backendProcess = spawn(prodBackendPath, [], { detached: false });
    } else {
      console.error(`[ElectronMain] Packaged backend not found at: ${prodBackendPath}`);
      dialog.showErrorBox('Backend Error', `Packaged backend not found. Expected at: ${prodBackendPath}`);
      return;
    }
  } else {
    if (fs.existsSync(devPythonInterpreter) && fs.existsSync(devBackendScript)) {
      console.log(`[ElectronMain] Starting backend script with: ${devPythonInterpreter} ${devBackendScript}`);
      backendProcess = spawn(devPythonInterpreter, [devBackendScript], {
    cwd: path.resolve(__dirname, '..', '..', 'backend'),
    });

    } else {
      const pyExists = fs.existsSync(devPythonInterpreter);
      const scriptExists = fs.existsSync(devBackendScript);
      console.error(`[ElectronMain] Dev backend or Python missing. Python: ${devPythonInterpreter} (exists: ${pyExists}), Script: ${devBackendScript} (exists: ${scriptExists})`);
      dialog.showErrorBox('Backend Error', `Development backend or Python not found.\nPython: ${devPythonInterpreter}\nScript: ${devBackendScript}`);
      return;
    }
  }

  if (backendProcess) {
    backendProcess.stdout.on('data', (data) => {
      console.log(`[Backend]: ${data.toString().trim()}`);
    });

    backendProcess.stderr.on('data', (data) => {
      console.error(`[Backend Error]: ${data.toString().trim()}`);
    });

    backendProcess.on('close', (code) => {
      console.log(`[ElectronMain] Backend exited with code ${code}`);
      backendProcess = null;
      if (!isDev && code !== 0) {
        dialog.showErrorBox('Backend Error', `Backend process exited with code ${code}.`);
      }
    });

    backendProcess.on('error', (err) => {
      console.error(`[ElectronMain] Backend start failed: ${err.message}`);
      dialog.showErrorBox('Backend Error', `Backend failed to start: ${err.message}`);
      backendProcess = null;
    });
  }
};

app.whenReady().then(() => {
  createWindow();
  startBackend();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('quit', () => {
  if (backendProcess) {
    console.log('[ElectronMain] Killing backend process...');
    backendProcess.kill();
  }
});
