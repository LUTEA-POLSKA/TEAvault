import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

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