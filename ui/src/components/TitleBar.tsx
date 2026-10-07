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

import { memo, useCallback, useMemo, useRef } from 'react'
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

/** Memoized to prevent re-rendering the title bar when only content changes. */
export const TitleBar = memo(function TitleBar({
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

  const tabs = useMemo<Tab[]>(() => [
    { id: 'keys', label: 'Keys' },
    {
      id: 'access',
      label: 'Access',
      badge: pending > 0 ? { text: String(pending), tone: 'caution' } : undefined,
    },
    { id: 'activity', label: 'Activity' },
    { id: 'settings', label: 'Settings' },
  ], [pending])

  const onKeyDown = useCallback((e: React.KeyboardEvent) => {
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
    requestAnimationFrame(() => {
      tabsRef.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus()
    })
  }, [view, onView, tabs])

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr auto 1fr',
        height: '32px',
        alignItems: 'center',
        padding: '0 8px',
        gap: '8px',
        userSelect: 'none',
      }}
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
        <IconButton
          variant="ghost"
          size="sm"
          label="Close"
          onClick={() => {
            void window.close();
          }}
        >
          <span aria-hidden="true">&#x2715;</span>
        </IconButton>
      </HStack>
    </div>
  )
})
