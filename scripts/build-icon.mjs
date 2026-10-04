// Render the TEAvault mark to the raster sizes Windows and Tauri consume.
//
// The SVG in src-tauri/icons/vault.svg is the source of truth; this turns it into
// the PNG set and the multi-size .ico that both the installer and the tray read.
// Keeping the vector as the source means the 16px tray icon and the 256px
// installer icon cannot drift apart, which three hand-tuned bitmaps would
// guarantee they eventually do.
//
// Usage, from the repository root:
//
//     npm --prefix ui install
//     node scripts/build-icon.mjs
//
// @resvg/resvg-js is a devDependency of ui/ because that is where the repo keeps
// its build tooling, and the icon is one of the UI's assets. Nothing at runtime
// depends on it: the outputs are committed, and only regenerating the icon does.
//
// Requires Node 18+.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const here = path.dirname(fileURLToPath(import.meta.url))
const iconsDir = path.resolve(here, '..', 'src-tauri', 'icons')
const src = path.join(iconsDir, 'vault.svg')

/*
 * Sizes.
 *
 *   16, 20, 24   tray at 100% and 125%; legibility is decided here
 *   32, 48       taskbar at 100% and 150%
 *   64, 128      large icons and the app's own window shell
 *   256          installer and Alt-Tab at high DPI
 *
 * 20 is there because Windows selects it for medium DPI on some builds, and a
 * missing frame silently falls back to a neighbouring size, which is blurry.
 */
const SIZES = [16, 20, 24, 32, 48, 64, 128, 256]

// Resolved through ui/package.json rather than a bare specifier: this script sits
// outside ui/, so Node would not look in ui/node_modules for it.
const require = createRequire(path.resolve(here, '..', 'ui', 'package.json'))
const { Resvg } = require('@resvg/resvg-js')

function render(size) {
  const r = new Resvg(fs.readFileSync(src), {
    fitTo: { mode: 'width', value: size },
    // The mark has no text, so no font can affect it. Saying so keeps the output
    // independent of whatever fonts happen to be installed.
    font: { loadSystemFonts: false },
  })
  return r.render().asPng()
}

/** Read width out of a PNG's IHDR, to prove the renderer gave us what we asked. */
function pngWidth(buf) {
  return buf.readUInt32BE(16)
}

const frames = []
for (const size of SIZES) {
  const png = render(size)
  const got = pngWidth(png)
  if (got !== size) throw new Error(`asked for ${size}px, renderer produced ${got}px`)
  fs.writeFileSync(path.join(iconsDir, `${size}x${size}.png`), png)
  frames.push({ size, png })
  console.log(`  ${size}x${size}.png`)
}

/*
 * Tauri's bundler names a high-DPI variant of a base size `<size>@2x.png`, so the
 * 256px render also has to exist under that name. It is written from the same
 * render rather than copied, so there is no chance of the two drifting apart.
 */
fs.writeFileSync(path.join(iconsDir, '128x128@2x.png'), render(256))
console.log('  128x128@2x.png')

/*
 * Pack a .ico around the frames.
 *
 * Layout: a six byte header, one sixteen byte directory entry per frame, then the
 * frame data. Each entry's offset depends on the total size of everything before
 * it, so the offsets are filled in a second pass.
 *
 * Every entry points at PNG data. Windows Vista and later read PNG inside an .ico,
 * and that is what makes a 256px entry practical: the same frame as a BMP would
 * be 256 KiB on disk.
 */
const HEADER = 6
const ENTRY = 16
const dataStart = HEADER + ENTRY * frames.length

const header = Buffer.alloc(HEADER)
header.writeUInt16LE(0, 0) // reserved
header.writeUInt16LE(1, 2) // type 1 = icon
header.writeUInt16LE(frames.length, 4)

const dir = Buffer.alloc(ENTRY * frames.length)
frames.forEach((f, i) => {
  const o = i * ENTRY
  // Width and height are single bytes, so 256 is encoded as 0.
  dir[o] = f.size >= 256 ? 0 : f.size
  dir[o + 1] = f.size >= 256 ? 0 : f.size
  dir[o + 2] = 0 // palette size; 0 means the image is not paletted
  dir[o + 3] = 0 // reserved
  dir.writeUInt16LE(1, o + 4) // colour planes
  dir.writeUInt16LE(32, o + 6) // bits per pixel
  dir.writeUInt32LE(f.png.length, o + 8)
})

let offset = dataStart
frames.forEach((f, i) => {
  dir.writeUInt32LE(offset, i * ENTRY + 12)
  offset += f.png.length
})

const ico = Buffer.concat([header, dir, ...frames.map((f) => f.png)])
fs.writeFileSync(path.join(iconsDir, 'icon.ico'), ico)

console.log(`  icon.ico  ${ico.length} B, ${frames.length} sizes`)