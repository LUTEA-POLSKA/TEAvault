/**
 * TEAui-styled window chrome.
 *
 * The window is undecorated (`decorations: false` in `tauri.conf.json`), so the
 * title bar is ours to draw. Three reasons it is TEAui rather than the native
 * bar:
 *
 * 1. Consistency. Native chrome on a TEAui surface reads as two applications
 *    sharing a window.
 * 2. The status belongs on the bar — locked or unlocked is the single most
 *    important thing on screen, and the native bar has nowhere to put it.
 * 3. Accessibility is not lost: the drag region is a real element, the buttons
 *    are real buttons with names, and the close button is `IconButton` with an
 *    `aria-label`, not a glyph.
 *
 * `Close` hides the window rather than exiting: the daemon and the tray outlive
 * the UI, which is the whole low-idle design. Quitting is a tray action, where
 * it is deliberate.
 */

import { getCurrentWindow } from '@tauri-apps/api/window'
import { Badge, HStack, IconButton, Stack, Text } from '@tea-ui/core'

export function TitleBar({
  locked,
  autoLockIn,
  pending,
}: {
  locked: boolean
  autoLockIn: number | null
  pending: number
}) {
  const window = getCurrentWindow()

  return (
    <Stack
      direction="horizontal"
      align="center"
      /*
       * The full CSS keyword, not TEAui's shorter `between`.
       *
       * `Stack` forwards `justify` verbatim into `justifyContent`, so the value
       * has to be a real `justify-content` keyword. `"between"` is not one: it is
       * silently dropped as invalid, the declaration never applies, and the bar
       * falls back to `normal` — which packs the window buttons against the
       * title on the left. Nothing errors, so it looks like `justify` was ignored.
       */
      justify="space-between"
      gap="ui"
      // The whole bar drags the window, which is what makes an undecorated
      // window usable with a mouse.
      data-tauri-drag-region
      style={{
        height: '40px',
        padding: '0 8px 0 12px',
        borderBottom: '1px solid var(--tea-color-line, rgba(255,255,255,0.08))',
        background: 'var(--tea-color-surface, transparent)',
        userSelect: 'none',
        flexShrink: 0,
        /*
         * Stated outright rather than left to the parent's stretch. `Stack`
         * writes its own `align-items` onto this element, so its width stops
         * being a consequence of the parent and becomes something to declare.
         */
        width: '100%',
      }}
    >
      <HStack gap="ui" align="center">
        <Text size="label" weight="semibold">
          TEAvault
        </Text>
        <Badge variant="subtle" tone={locked ? 'neutral' : 'positive'}>
          {locked ? 'Locked' : 'Unlocked'}
        </Badge>
        {!locked && autoLockIn !== null && (
          <Text size="ui" tone="subtle">
            locks in {autoLockIn}s
          </Text>
        )}
        {pending > 0 && <Badge tone="caution">{pending} pending</Badge>}
      </HStack>

      <HStack gap="none" align="center">
        <IconButton
          variant="ghost"
          size="sm"
          label="Minimise"
          onClick={() => void window.minimize()}
        >
          <span aria-hidden="true">&#x2500;</span>
        </IconButton>
        {/*
          No maximise button: the window is pinned to one size
          (`resizable: false` plus min == max in `src-tauri/src/fixed_size.rs`),
          so maximising could only produce a size the window refuses. A control
          that cannot do what it says is worse than a missing one.
        */}
        <IconButton
          variant="ghost"
          size="sm"
          label="Close"
          onClick={() => {
            // Hide, not exit: the daemon and tray keep running.
            void window.hide()
          }}
        >
          <span aria-hidden="true">&#x2715;</span>
        </IconButton>
      </HStack>
    </Stack>
  )
}