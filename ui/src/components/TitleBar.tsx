/**
 * The window chrome, and the primary navigation with it.
 *
 * ## Why the navigation lives in the title bar
 *
 * The obvious component for this was TEAui's `AdminShell`: a 256px sidebar, a
 * top bar, and a drawer below 1024px. At a fixed 940px window that is the wrong
 * shape for two independent reasons.
 *
 * * A 256px sidebar is 27% of the window. The key list — the thing the user came
 *   here for, and the only screen that is used daily — would have 644px to work
 *   with, which is not enough for a row showing a name, a provider, two status
 *   badges and three actions.
 * * The responsive behaviour is dead weight. A window that cannot be resized has
 *   exactly one layout, so a breakpoint that switches between two of them can
 *   never fire.
 *
 * So the views are a tab row in the bar instead. It costs 28px of height instead
 * of 256px of width, it keeps the full width for content, and it puts navigation
 * next to the window controls where a compact utility belongs.
 *
 * ## The bar is also the status
 *
 * The lock state lives here rather than in a screen, because it is true in every
 * screen. An idle countdown is next to it for the same reason: it is the answer
 * to "how long do I have", asked constantly, and it does not deserve a page.
 */

import { useRef } from 'react'
import { getCurrentWindow } from '@tauri-apps/api/window'
import { Badge, HStack, IconButton, Text } from '@tea-ui/core'

/** The four views. There is deliberately no detail view — see `KeysPanel`. */
export type View = 'keys' | 'access' | 'activity' | 'settings'

interface Tab {
  id: View
  label: string
  /** A count rendered after the label, or nothing. */
  badge?: { text: string; tone: 'caution' | 'positive' | 'neutral' }
}

export function TitleBar({
  locked,
  initialized,
  pending,
  view,
  onView,
  onLock,
}: {
  locked: boolean
  initialized: boolean
  pending: number
  view: View
  onView: (v: View) => void
  onLock: () => void
}) {
  const window = getCurrentWindow()
  const tabsRef = useRef<HTMLDivElement | null>(null)

  const tabs: Tab[] = [
    { id: 'keys', label: 'Keys' },
    {
      id: 'access',
      label: 'Access',
      // Pending requests are the one thing that is time-sensitive, so they are
      // counted on the tab itself rather than left for the user to find on a
      // second screen.
      badge: pending > 0 ? { text: String(pending), tone: 'caution' } : undefined,
    },
    { id: 'activity', label: 'Activity' },
    { id: 'settings', label: 'Settings' },
  ]

  // Left/right/Home/End move between tabs, as they do in any tab strip. Without
  // this, a keyboard user can only reach the other views by tabbing through every
  // interactive element on the current one.
  function onKeyDown(e: React.KeyboardEvent) {
    const i = tabs.findIndex((t) => t.id === view)
    let next = i
    if (e.key === 'ArrowRight') next = (i + 1) % tabs.length
    else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length
    else if (e.key === 'Home') next = 0
    else if (e.key === 'End') next = tabs.length - 1
    else return
    e.preventDefault()
    const target = tabs[next]
    if (!target) return
    onView(target.id)
    // Move focus to the newly selected tab so the arrow keys keep working.
    requestAnimationFrame(() => {
      tabsRef.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus()
    })
  }

  return (
    <div
      /*
       * Three cells, `1fr auto 1fr`.
       *
       * The tabs sit in the `auto` cell, so the two `1fr` cells on either side are
       * always equal and the tabs are centred on the *window*. `justify:
       * space-between` cannot do this: it distributes the leftover space between
       * the items, so the centre group ends up off-centre by half the difference
       * in the widths of the outer two groups. Adding a character to the lock
       * badge would visibly shift the tabs, which is the tell that the layout is
       * measuring the wrong thing.
       */
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr auto 1fr',
        alignItems: 'center',
        height: '36px',
        padding: '0 4px 0 10px',
        borderBottom: '1px solid var(--tea-line)',
        background: 'var(--tea-surface)',
        userSelect: 'none',
        flexShrink: 0,
        width: '100%',
        boxSizing: 'border-box',
      }}
      /*
       * `data-tauri-drag-region="deep"` — and the exact value matters.
       *
       * Tauri decides on mousedown by walking the event path outward
       * (`tauri/src/window/scripts/drag.js`):
       *
       *   - a clickable element (button, link, `role="tab"`, anything with a
       *     `tabindex`) that has *no* attribute ends the walk and refuses the
       *     drag — this is what keeps the tabs and the window buttons clickable;
       *   - `"deep"` means any descendant of the marked element drags;
       *   - a bare attribute means *only a direct hit on this very element* drags.
       *
       * That last rule is what broke dragging before. With a bare attribute on the
       * three groups, pressing on the word "TEAvault" or on the lock badge found a
       * bare attribute on an ancestor but not on the pressed node, so the drag was
       * refused — only the sliver of background between the words could move the
       * window. Marking the bar `"deep"` makes the whole bar draggable, and the
       * clickable children still block themselves, which is the behaviour a
       * title bar is supposed to have.
       */
      data-tauri-drag-region="deep"
      onKeyDown={onKeyDown}
    >
      <HStack gap="ui" align="center" style={{ justifySelf: 'start', minWidth: 0 }}>
        <Text size="label" weight="semibold">
          TEAvault
        </Text>
        <Badge variant="subtle" tone={locked ? 'neutral' : 'positive'}>
          {locked ? 'Locked' : 'Unlocked'}
        </Badge>
      </HStack>

      {initialized && !locked && (
        <div
          ref={tabsRef}
          role="tablist"
          aria-label="Views"
          style={{ display: 'flex', gap: '2px', justifySelf: 'center' }}
        >
        {tabs.map((t) => {
          const active = t.id === view
          return (
            <button
              key={t.id}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => onView(t.id)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                height: '24px',
                padding: '0 12px',
                border: '1px solid transparent',
                borderRadius: '4px',
                background: active ? 'var(--tea-surface-2)' : 'transparent',
                color: 'inherit',
                font: 'inherit',
                fontSize: '12px',
                cursor: 'pointer',
              }}
            >
              {t.label}
              {t.badge && (
                <Badge variant="subtle" tone={t.badge.tone}>
                  {t.badge.text}
                </Badge>
              )}
            </button>
          )
        })}
        </div>
      )}

      <HStack gap="none" align="center" style={{ justifySelf: 'end' }}>
        {!locked && (
          <IconButton variant="ghost" size="sm" label="Lock now" onClick={onLock}>
            <span aria-hidden="true">&#x1F512;</span>
          </IconButton>
        )}
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
            // Closes the window, which ends this process. The daemon and its tray
            // are unaffected — see the crate documentation in `src-tauri/src/lib.rs`.
            void window.close();
          }}
        >
          <span aria-hidden="true">&#x2715;</span>
        </IconButton>
      </HStack>
    </div>
  )
}
