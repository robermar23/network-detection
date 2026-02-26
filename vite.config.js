import { defineConfig } from 'vite';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default defineConfig({
  root: 'src/renderer',
  base: './',
  resolve: {
    alias: {
      '@main': resolve(__dirname, 'src/main'),
      '@renderer': resolve(__dirname, 'src/renderer'),
      '@shared': resolve(__dirname, 'src/shared')
    }
  },
  build: {
    outDir: '../../dist',
    emptyOutDir: true
  },
  server: {
    port: 5173
  },
  test: {
    root: '.',
    include: ['test/**/*.test.js'],
    coverage: {
      provider: 'v8',
      include: ['src/main/**/*.js', 'src/shared/**/*.js'],
      exclude: ['src/main/preload.js', 'src/main/preload.cjs', 'src/main/main.js']
    }
  }
});
