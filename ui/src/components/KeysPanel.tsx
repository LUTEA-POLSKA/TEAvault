/**
 * The key list — the screen the user spends their time on.
 *
 * ## Why there is no detail screen
 *
 * The previous structure had a list, a *detail* view, and a separate entry
 * dialog: three surfaces to learn, and a navigation step between "pick a key" and
 * "act on it". A key's entire actionable surface is its name, provider, note,
 * visibility, and the two buttons that release or replace it — that is one
 * dialog's worth of content, not a screen's.
 *
 * So the row opens the dialog directly. The list is the whole view, and every
 * action is one click from it.
 *
 * ## Why the actions are icon buttons with labels
 *
 * Copy and delete are destructive or irreversible in different ways, and neither
 * can be discovered from a glyph alone. Each carries a visible label on the row
 * *and* an `aria-label` for the icon-only presentation at narrow widths, so
 * nothing depends on recognising an icon.
 *
 * Deleting asks for confirmation inside the dialog rather than in a browser
 * `confirm()`: a native modal steals focus unpredictably, and the user cannot see
 * which key they are about to lose while answering.
 */

import { useMemo, useState } from 'react'
import {
  Badge,
  Button,
  Callout,
  Card,
  CardBody,
  HStack,
  PasswordInput,
  SearchInput,
  Stack,
  Text,
} from '@tea-ui/core'
import { LabelledField } from './LabelledField'
import { EmptyState } from './Empty'
import type { ListEntry } from '../api'

/** The group shown for entries without a category, and the drop target for clearing one. */
const UNCATEGORIZED = 'Uncategorized'

export function KeysPanel({
  entries,
  pendingCount,
  onAdd,
  onEdit,
  onCopy,
  onDelete,
  onGoToAccess,
  onSetCategory,
}: {
  entries: ListEntry[]
  pendingCount: number
  onAdd: () => void
  onEdit: (e: ListEntry) => void
  onCopy: (e: ListEntry) => void
  onDelete: (e: ListEntry) => void
  onGoToAccess: () => void
  onSetCategory: (e: ListEntry, category: string | null) => void
}) {
  const [query, setQuery] = useState('')
  const [confirming, setConfirming] = useState<ListEntry | null>(null)
  const [draggingId, setDraggingId] = useState<string | null>(null)

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return entries
    return entries.filter(
      (e) =>
        e.name.toLowerCase().includes(q) ||
        e.provider.toLowerCase().includes(q) ||
        (e.description ?? '').toLowerCase().includes(q),
    )
  }, [entries, query])

  // Group the filtered keys by category. Uncategorized is a real group (the
  // drop target for "clear the category"), so it is always present.
  const grouped = useMemo(() => {
    const byCat = new Map<string, ListEntry[]>()
    for (const e of visible) {
      const key = e.category && e.category.trim() !== '' ? e.category : UNCATEGORIZED
      const bucket = byCat.get(key)
      if (bucket) bucket.push(e)
      else byCat.set(key, [e])
    }
    const names = [...byCat.keys()].sort((a, b) => a.localeCompare(b))
    if (!names.includes(UNCATEGORIZED)) names.push(UNCATEGORIZED)
    return names.map((name) => ({ name, items: byCat.get(name) ?? [] }))
  }, [visible])

  function dropOn(category: string | null) {
    return function handleDrop(e: React.DragEvent) {
      e.preventDefault()
      const id = e.dataTransfer.getData('text/plain')
      setDraggingId(null)
      const target = entries.find((x) => x.id === id)
      if (!target) return
      const current = target.category && target.category.trim() !== '' ? target.category : UNCATEGORIZED
      if (current === (category ?? UNCATEGORIZED)) return
      onSetCategory(target, category)
    }
  }

  if (entries.length === 0) {
    return (
      <div style={{ padding: '20px', display: 'flex', justifyContent: 'center' }}>
        <Card style={{ maxWidth: '460px' }}>
          <CardBody>
            <EmptyState
              title="No keys yet"
              description="Add the API keys your tools need. TEAvault stores them encrypted and only releases one to a program you have approved."
              action={
                <Button variant="primary" size="sm" onClick={onAdd}>
                  Add a key
                </Button>
              }
            />
          </CardBody>
        </Card>
      </div>
    )
  }

  return (
    <Stack gap="ui" style={{ padding: '12px 16px', minHeight: 0 }}>
      {pendingCount > 0 && (
        // A pending request is a program asking for a key right now. It is the
        // only thing on this screen that changes without the user acting, so it
        // gets the top slot rather than a badge they have to notice.
        <Callout tone="caution" title="Waiting for your decision">
          <HStack align="center" justify="between" gap="ui">
            <Text size="ui">
              {pendingCount} program{pendingCount === 1 ? '' : 's'} asked for access.
            </Text>
            <Button size="sm" variant="secondary" onClick={onGoToAccess}>
              Review
            </Button>
          </HStack>
        </Callout>
      )}

      <HStack align="center" gap="ui" justify="between">
        <SearchInput
          value={query}
          onValueChange={setQuery}
          placeholder="Filter by name or provider"
          label="Filter keys"
          style={{ maxWidth: '320px' }}
        />
        <Button size="sm" variant="primary" onClick={onAdd}>
          Add key
        </Button>
      </HStack>

      {confirming && (
        <Callout tone="critical" title={`Delete ${confirming.name}?`}>
          <Stack gap="ui">
            <Text size="ui">
              This removes the encrypted value and every permission granted for it. There is no
              undo and no copy anywhere else.
            </Text>
            <HStack gap="ui" justify="end">
              <Button size="sm" variant="secondary" onClick={() => setConfirming(null)}>
                Keep it
              </Button>
              <Button
                size="sm"
                variant="destructive"
                onClick={() => {
                  onDelete(confirming)
                  setConfirming(null)
                }}
              >
                Delete permanently
              </Button>
            </HStack>
          </Stack>
        </Callout>
      )}

      {visible.length === 0 ? (
        <Text size="ui" tone="muted" style={{ padding: '18px 0' }}>
          No key matches “{query}”.
        </Text>
      ) : (
        <Stack gap="md" style={{ minHeight: 0 }}>
          {grouped.map(({ name, items }) => (
            <div
              key={name}
              onDragOver={(e) => e.preventDefault()}
              onDrop={dropOn(name === UNCATEGORIZED ? null : name)}
            >
              <GroupHeader
                name={name}
                count={items.length}
                active={draggingId !== null}
              />
              {items.length > 0 ? (
                <Stack gap="none" role="list" style={{ border: '1px solid var(--tea-line)', borderRadius: '6px', overflow: 'hidden' }}>
                  {items.map((e, i) => (
                    <KeyRow
                      key={e.id}
                      entry={e}
                      first={i === 0}
                      dragging={draggingId === e.id}
                      onDragStart={() => setDraggingId(e.id)}
                      onDragEnd={() => setDraggingId(null)}
                      onEdit={onEdit}
                      onCopy={onCopy}
                      onDelete={() => setConfirming(e)}
                    />
                  ))}
                </Stack>
              ) : (
                // An empty group is still a drop target: the user can drag a key
                // here to clear its category (Uncategorized) or to start one.
                <Stack
                  gap="none"
                  style={{
                    border: `1px dashed ${draggingId !== null ? 'var(--tea-focus)' : 'var(--tea-line)'}`,
                    borderRadius: '6px',
                    padding: '10px 12px',
                  }}
                >
                  <Text size="ui" tone="muted">
                    Drop a key here to move it to “{name}”
                  </Text>
                </Stack>
              )}
            </div>
          ))}
        </Stack>
      )}
    </Stack>
  )
}

function GroupHeader({ name, count, active }: { name: string; count: number; active: boolean }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '6px 2px',
      }}
    >
      <Text size="label" weight="semibold" as="span">
        {name}
      </Text>
      <Badge
        variant="subtle"
        tone={name === UNCATEGORIZED ? 'neutral' : 'info'}
      >
        {count}
      </Badge>
      {active && (
        <Text size="ui" tone="subtle">
          drop to move here
        </Text>
      )}
    </div>
  )
}

function KeyRow({
  entry,
  first,
  dragging,
  onDragStart,
  onDragEnd,
  onEdit,
  onCopy,
  onDelete,
}: {
  entry: ListEntry
  first: boolean
  dragging: boolean
  onDragStart: () => void
  onDragEnd: () => void
  onEdit: (e: ListEntry) => void
  onCopy: (e: ListEntry) => void
  onDelete: () => void
}) {
  return (
    <div
      role="listitem"
      draggable
      onDragStart={(e) => {
        e.dataTransfer.setData('text/plain', entry.id)
        e.dataTransfer.effectAllowed = 'move'
        onDragStart()
      }}
      onDragEnd={onDragEnd}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '8px 12px',
        borderTop: first ? 'none' : '1px solid var(--tea-line)',
        background: dragging ? 'var(--tea-surface-hover)' : 'var(--tea-surface)',
        cursor: 'grab',
        opacity: dragging ? 0.5 : 1,
      }}
    >
      <div style={{ minWidth: 0, flex: 1 }}>
        <HStack gap="ui" align="center">
          <Text size="ui" weight="semibold" style={{ fontFamily: 'var(--tea-font-mono)' }}>
            {entry.name}
          </Text>
          {entry.granted ? (
            // Grants are a security state, so they are a word and not a colour.
            <Badge variant="subtle" tone="positive">
              approved
            </Badge>
          ) : (
            <Badge variant="subtle" tone="neutral">
              not shared
            </Badge>
          )}
          {entry.hidden && (
            <Badge variant="subtle" tone="caution">
              hidden
            </Badge>
          )}
        </HStack>
        <Text size="ui" tone="subtle" truncate>
          {entry.provider}
          {entry.description ? ` — ${entry.description}` : ''}
        </Text>
      </div>

      <HStack gap="xs" align="center">
        {/*
          Copy is the release of a secret, so it is a labelled button rather than
          an icon: the user should never have to know that a clipboard icon means
          "hand the key to a program".
        */}
        <Button size="sm" variant="secondary" onClick={() => onCopy(entry)}>
          Copy
        </Button>
        <Button size="sm" variant="ghost" onClick={() => onEdit(entry)}>
          Edit
        </Button>
        <Button size="sm" variant="ghost" onClick={onDelete} aria-label={`Delete ${entry.name}`}>
          Delete
        </Button>
      </HStack>
    </div>
  )
}

/** Shown while the vault is locked: the one action, and the way out if there is none. */
export function UnlockPanel({
  onUnlock,
  onWipe,
}: {
  onUnlock: (pass: string) => Promise<void>
  onWipe: () => Promise<void>
}) {
  const [pass, setPass] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await onUnlock(pass)
      setPass('')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      style={{
        flex: 1,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px',
        minHeight: 0,
        overflowY: 'auto',
      }}
    >
      <Card style={{ width: '100%', maxWidth: '400px' }}>
        <CardBody>
          <form onSubmit={submit}>
            <Stack gap="ui">
              <Text size="label" weight="semibold">
                Unlock TEAvault
              </Text>

              <LabelledField label="Master passphrase" error={error ?? undefined}>
                <PasswordInput
                  // Taller than the TEAui default. This is the field the user comes
                  // back to every time, and a 28px target for a long passphrase is
                  // needlessly fiddly on a desktop.
                  className="w-full"
                  size="lg"
                  value={pass}
                  onValueChange={setPass}
                  autoFocus
                  autoComplete="current-password"
                />
              </LabelledField>

              <Button type="submit" variant="primary" size="sm" loading={busy} disabled={!pass}>
                Unlock
              </Button>

              {/*
                The way out of a forgotten passphrase. Kept visible rather than
                buried: a user who has lost it needs to see that TEAvault offers a
                way forward, otherwise they assume the keys are gone for good.
              */}
              <ResetLink onWipe={onWipe} />
            </Stack>
          </form>
        </CardBody>
      </Card>
    </div>
  )
}

/**
 * "Forgotten it?" — expands into a confirmation.
 *
 * A reset destroys every key irrecoverably, so it is never one click. Two things
 * keep that from being annoying: the button is small and out of the way until
 * asked for, and the confirmation asks the user to *type* nothing — only to press
 * a second, clearly named button. There is deliberately no passphrase field here;
 * there would be nothing to verify against.
 */
function ResetLink({ onWipe }: { onWipe: () => Promise<void> }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)

  if (!open) {
    return (
      <Text size="ui" tone="subtle">
        <button
          type="button"
          onClick={() => setOpen(true)}
          style={{
            background: 'none',
            border: 'none',
            padding: 0,
            color: 'var(--tea-fg-muted)',
            font: 'inherit',
            textDecoration: 'underline',
            cursor: 'pointer',
          }}
        >
          Forgotten your passphrase?
        </button>
      </Text>
    )
  }

  return (
    <div
      style={{
        border: '1px solid var(--tea-critical-border)',
        borderRadius: '4px',
        padding: '12px',
      }}
    >
      <Stack gap="ui">
        <Text size="ui">
          This deletes the vault. Every key in it is gone for good — there is no
          recovery.
        </Text>
        <HStack gap="ui" justify="end">
          <Button type="button" variant="secondary" size="sm" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            type="button"
            variant="destructive"
            size="sm"
            loading={busy}
            onClick={async () => {
              setBusy(true)
              try {
                await onWipe()
              } finally {
                setBusy(false)
              }
            }}
          >
            Delete everything
          </Button>
        </HStack>
      </Stack>
    </div>
  )
}
