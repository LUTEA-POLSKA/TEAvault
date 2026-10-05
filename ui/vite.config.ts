import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

/**
 * One config, two targets.
 *
 * `vite` builds the app, `vite --mode web` serves the same sources in a browser.
 * The difference is exactly one thing — the two aliases below — because the
 * application code is identical in both. `@tauri-apps/api/core` *imports* fine in
 * a browser; only calling `invoke` throws, because `__TAURI_INTERNALS__` is
 * absent. So the browser build swaps the module rather than the application, and
 * moving a change from the browser back to the app is deleting these aliases
 * rather than porting anything.
 *
 * What the browser build cannot show, so it is not mistaken for coverage:
 * window dragging, minimise, close-to-tray, the tray icon, the real clipboard,
 * and the Argon2id unlock delay. Layout is judged inside the fixed-size frame in
 * `index.web.html`, which the dev server serves at `/` in this mode — see
 * `webEntry` below for why that is a rewrite and not just a second document.
 * `vite build` is unaffected and still uses `index.html`.
 */
/**
 * Serve `index.web.html` at `/` in the browser build.
 *
 * Vite prints `http://localhost:5180/`, and that is where a browser opens. Left
 * alone, `/` serves `index.html` — the shipped document, whose
 * Content-Security-Policy blocks the dev server's inline styles and HMR client.
 * The page then renders unstyled, which looks exactly like a broken build.
 *
 * Rewriting the request rather than printing a different URL keeps the address
 * Vite advertises the address that works, and keeps `index.web.html` as the only
 * place the frame is described. Dev-only: `vite build` never runs this.
 */
function webEntry() {
  return {
    name: 'teavault-web-entry',
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        if (req.url === '/' || req.url === '/index.html') {
          req.url = '/index.web.html'
        }
        next()
      })
    },
  }
}

const stub = (name: string) => fileURLToPath(new URL(`./web/${name}`, import.meta.url))

export default defineConfig(({ mode }) => {
  const web = mode === 'web'

  return {
    plugins: [react(), ...(web ? [webEntry()] : [])],
    clearScreen: false,
    resolve: web
      ? {
          alias: [
            { find: '@tauri-apps/api/core', replacement: stub('tauri-core-stub.ts') },
            { find: '@tauri-apps/api/window', replacement: stub('tauri-window-stub.ts') },
          ],
        }
      : undefined,
    server: {
      // 5173 is Tauri's, and 5174 is taken by TEAhost on this machine. 5180 is
      // arbitrary and free; `strictPort` keeps a clash loud rather than silently
      // moving to a port nobody is watching.
      port: web ? 5180 : 5173,
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
  }
})
