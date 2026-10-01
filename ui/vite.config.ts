import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Tauri drives the dev server, so the port is fixed and `strictPort` makes a
// port clash a loud error rather than a silent move to a port Tauri is not
// watching.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    watch: { ignored: ['**/src-tauri/**'] },
  },
  build: {
    // Matches the WebView on the supported Windows versions, and keeps the
    // bundle small — the UI is opened on demand and should start instantly.
    target: 'chrome110',
    sourcemap: false,
    outDir: 'dist',
    emptyOutDir: true,
  },
})