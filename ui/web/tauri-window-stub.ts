/**
 * A stand-in for `@tauri-apps/api/window`, used by the browser dev build.
 *
 * Aliased in `vite.config.ts` when `--mode web` is on. In the app this module is
 * never loaded: the real package is resolved instead, and the drag region and
 * the window buttons work for real.
 *
 * What the browser genuinely cannot show: window dragging, minimising and
 * closing. Those three are the entire surface here, so the stub is honest about
 * them rather than pretending — each one logs, so a click that appears to do
 * nothing in the browser is explained instead of mysterious.
 *
 * `data-tauri-drag-region` is a Tauri-injected behaviour, not CSS. In the
 * browser it is an inert attribute, which is why the title bar cannot be dragged
 * here and why layout has to be judged from the fixed-size frame instead.
 */

type Listener = () => void

/** A window that exists only as far as the browser is concerned. */
export interface BrowserWindow {
  label: string
  minimize(): Promise<void>
  close(): Promise<void>
  hide(): Promise<void>
  show(): Promise<void>
  setTitle(_title: string): Promise<void>
  isMaximized(): Promise<boolean>
  isFullscreen(): Promise<boolean>
  isMinimized(): Promise<boolean>
  isVisible(): Promise<boolean>
  startDragging(): Promise<void>
  on(_event: string, _listener: Listener): Promise<() => void>
  once(_event: string, _listener: Listener): Promise<() => void>
}

let counter = 0

/**
 * The same shape the real module returns, so a caller that switches on the label
 * still works.
 */
export function getCurrentWindow(): BrowserWindow {
  const label = `web-stub-${++counter}`
  return {
    label,
    async minimize() {
      console.info(`[web-stub] minimize("${label}") — no window to minimise in a browser`)
    },
    async close() {
      console.info(`[web-stub] close("${label}") — no window to close in a browser`)
    },
    async hide() {
      console.info(`[web-stub] hide("${label}") — no window to hide in a browser`)
    },
    async show() {
      console.info(`[web-stub] show("${label}") — already visible`)
    },
    async setTitle(title: string) {
      document.title = title
    },
    async isMaximized() {
      return false
    },
    async isFullscreen() {
      return false
    },
    async isMinimized() {
      return false
    },
    async isVisible() {
      return true
    },
    async startDragging() {
      console.info('[web-stub] startDragging — drag region is a Tauri behaviour, not available here')
    },
    async on() {
      // No events in a browser: resize, focus and close never fire, which is why
      // the shell's own focus listener is the only refresh trigger here.
      return () => {}
    },
    async once() {
      return () => {}
    },
  }
}

export const appWindow = getCurrentWindow()
