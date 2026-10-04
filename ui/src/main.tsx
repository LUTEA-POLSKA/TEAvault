/**
 * The entry point.
 *
 * ## Stylesheet order is decided here and nowhere else
 *
 * TEAui's stylesheet is imported first, then the font faces, then this project's
 * own overrides. That order matters: `app.css` rebinds TEAui's own custom
 * properties (`--tea-font-sans`), so it has to come after the file that defines
 * them. Importing any of these from a component instead would make the outcome
 * depend on module evaluation order.
 *
 * `@tea-ui/admin` is deliberately **not** imported. The application no longer uses
 * `AdminShell`, `Page` or the state components from it: at a fixed 940px window a
 * 256px sidebar is 27% of the available width, and its responsive drawer can
 * never fire in a window that cannot be resized. See `src/components/TitleBar.tsx`
 * for the navigation that replaced it.
 */

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import '@tea-ui/core/styles.css'

// Montserrat, self-hosted through @fontsource — no network fetch at runtime,
// which matters for a tool whose whole promise is working offline.
//
// 400 is deliberately NOT imported. Montserrat Medium (500) is the standard
// weight for this interface, so any rule asking for 400 or lighter resolves to
// the nearest available face, which is 500. Semibold and bold are imported
// because TEAui genuinely uses them for labels and headings, and a synthesised
// bold looks noticeably worse than the real one.
import '@fontsource/montserrat/latin-500.css'
import '@fontsource/montserrat/latin-600.css'
import '@fontsource/montserrat/latin-700.css'

import './styles/app.css'

import App from './App'

const root = document.getElementById('root')
if (!root) {
  // A missing mount point is a build problem, not a runtime condition worth
  // recovering from in the field.
  throw new Error('#root is missing from index.html')
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
)