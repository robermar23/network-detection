import { spawn } from 'child_process';
import { dialog, app } from 'electron';
import path from 'path';
import fs from 'fs';

function getReportsEnginePath() {
  const isDev = process.env.NODE_ENV === 'development';
  const ext = process.platform === 'win32' ? '.exe' : '';
  const binaryName = `netspectre-reports${ext}`;

  if (isDev) {
    return path.join(app.getAppPath(), 'engines', 'go-reports', binaryName);
  }
  return path.join(process.resourcesPath, 'engines', binaryName);
}

export function isReportsEngineAvailable() {
  const binPath = getReportsEnginePath();
  try {
    fs.accessSync(binPath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export async function runExport(mainWindow, { hosts, format, sanitize, summary, baseline }) {
  const filters = {
    json: [{ name: 'JSON Files', extensions: ['json'] }],
    csv:  [{ name: 'CSV Files', extensions: ['csv'] }],
    html: [{ name: 'HTML Files', extensions: ['html'] }],
    pdf:  [{ name: 'PDF Files', extensions: ['pdf'] }]
  };

  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    title: `Export ${format.toUpperCase()} Report`,
    defaultPath: path.join(app.getPath('documents'), `netspectre_report_${Date.now()}.${format}`),
    filters: filters[format] || [{ name: 'All Files', extensions: ['*'] }]
  });

  if (canceled || !filePath) return { status: 'cancelled' };

  return new Promise((resolve) => {
    const binPath = getReportsEnginePath();

    if (!fs.existsSync(binPath)) {
      resolve({ status: 'error', error: 'Reports engine binary not found' });
      return;
    }

    const args = [
      '--format', format,
      '--output', filePath,
      ...(sanitize ? ['--sanitize'] : []),
      ...(summary ? ['--summary'] : [])
    ];

    console.log(`[reports-engine] Spawning: ${binPath} ${args.join(' ')}`);

    const proc = spawn(binPath, args, {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Build payload for stdin
    const payload = JSON.stringify({ hosts, baseline: baseline || null });
    proc.stdin.write(payload);
    proc.stdin.end();

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    proc.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

    proc.on('close', (code) => {
      if (code === 0) {
        try {
          const result = JSON.parse(stdout);
          resolve({ status: 'exported', filePath, ...result });
        } catch {
          resolve({ status: 'exported', filePath });
        }
      } else {
        resolve({ status: 'error', error: stderr || `Process exited with code ${code}` });
      }
    });

    proc.on('error', (err) => {
      resolve({ status: 'error', error: err.message });
    });

    // Safety timeout: 60 seconds
    const timeout = setTimeout(() => {
      proc.kill();
      resolve({ status: 'error', error: 'Report generation timed out' });
    }, 60000);

    proc.on('close', () => clearTimeout(timeout));
  });
}
