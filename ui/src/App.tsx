/**
 * The application shell.
 *
 * Every component rendered here comes from TEAui — `@tea-ui/core` for
 * primitives, `@tea-ui/admin` for the shell and product states. There is no
 * second component library, and no prop, token or component that TEAui does not
 * actually export. `docs/UI_NOTES.md` records the verification and the one gap.
 *
 * The security-relevant observation: **no component here decides whether
 * something may be shown.** Every screen renders what the daemon returned, and a
 * refusal is rendered as a refusal. The UI cannot widen access because it has no
 * code path that could.
 */

import { useCallback, useEffect, useMemo, useState } from 'react'

import { AdminShell, type NavItem, EmptyState, Page, PageHeader } from '@tea-ui/admin'
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Button,
  Card,
  CardBody,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
  Container,
  Field,
  FieldDescription,
  FieldLabel,
  PasswordInput,
  ScrollArea,
  SearchInput,
  Stack,
  StatusBadge,
  Text,
  toast,
  Toaster,
  VStack,
} from '@tea-ui/core'

import { api, AuditEvent, ListEntry, PendingApproval, VaultError } from './api'
import { AccessScreen } from './components/AccessScreen'
import { ApprovalDialog } from './components/ApprovalDialog'
import { AuditScreen } from './components/AuditScreen'
import { EntryDialog } from './components/EntryDialog'
import { SettingsScreen } from './components/SettingsScreen'
import { SetupScreen } from './components/SetupScreen'
import { TitleBar } from './components/TitleBar'

import '@tea-ui/core/styles.css'
import '@tea-ui/admin/styles.css'

type Screen = 'keys' | 'detail' | 'access' | 'audit' | 'settings'

export default function App() {
  const [screen, setScreen] = useState<Screen>('keys')
  const [locked, setLocked] = useState(true)
  const [initialized, setInitialized] = useState(false)
  const [autoLockIn, setAutoLockIn] = useState<number | null>(null)
  const [pending, setPending] = useState<PendingApproval[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<VaultError | null>(null)

  const [entries, setEntries] = useState<ListEntry[]>([])
  const [selected, setSelected] = useState<ListEntry | null>(null)
  const [query, setQuery] = useState('')
  const [editing, setEditing] = useState<{ mode: 'create' } | { mode: 'edit'; entry: ListEntry } | null>(null)
  const [answering, setAnswering] = useState<PendingApproval | null>(null)

  /** Report a refusal. Never swallowed, never retried automatically. */
  const fail = useCallback((e: unknown) => {
    const err =
      e instanceof VaultError
        ? e
        : new VaultError({ code: 'io', message: String(e), retryable: false })
    setError(err)
    if (err.isLocked) setLocked(true)
  }, [])

const refresh = useCallback(async () => {
    try {
      const s = await api.status()
      setInitialized(s.initialized)
      setLocked(s.locked)
      setAutoLockIn(s.auto_lock_in)

      // Only ask for pending approvals when there is a vault to have approvals
      // in. Asking a locked or non-existent vault produces a refusal, and
      // showing that refusal as a red banner above the setup screen reads as
      // "something is broken" when nothing is.
      if (s.initialized && !s.locked) {
        setPending(await api.approvals())
        setEntries((await api.list()).entries)
      } else {
        setPending([])
        setEntries([])
      }
    } catch (e) {
      fail(e)
    }
  }, [fail])

  useEffect(() => {
    void refresh()
  }, [refresh])

  /**
   * The auto-lock countdown is the only timer in this app.
   *
   * It is a display concern only: it counts down a number the daemon computed
   * from its own last-activity timestamp and decides nothing. A missed tick
   * costs a stale countdown. The daemon itself has no timers at all — see
   * `ARCHITECTURE.md` § Idle.
   */
  useEffect(() => {
    if (locked || autoLockIn === null) return
    const id = window.setInterval(() => {
      setAutoLockIn((v) => (v === null ? null : Math.max(0, v - 1)))
      if (autoLockIn <= 1) void refresh()
    }, 1000)
    return () => window.clearInterval(id)
  }, [locked, autoLockIn, refresh])

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return entries
    return entries.filter((e) =>
      [e.name, e.display_name, e.provider, ...e.capabilities].some((f) =>
        f.toLowerCase().includes(q),
      ),
    )
  }, [entries, query])

  const nav: NavItem[] = [
    { id: 'keys', label: 'API keys' },
    { id: 'detail', label: 'Detail', disabled: !selected },
    { id: 'access', label: 'Access', meta: pending.length || undefined },
    { id: 'audit', label: 'Activity' },
    { id: 'settings', label: 'Settings' },
  ]

  async function onLock() {
    setBusy(true)
    try {
      await api.lock()
      setLocked(true)
      setEntries([])
      setSelected(null)
      toast({ title: 'Vault locked', tone: 'neutral' })
    } catch (e) {
      fail(e)
    } finally {
      setBusy(false)
    }
  }

  async function onCopy(entry: ListEntry) {
    try {
      const r = await api.copyToClipboard(entry.id)
      toast({
        title: 'Copied to clipboard',
        description: `${entry.name} — ${r.masked}. Any program can read the clipboard before it clears.`,
        tone: 'caution',
      })
    } catch (e) {
      fail(e)
    }
  }

return (
    <>
      <Toaster />
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          height: '100vh',
          width: '100%',
        }}
      >
        <TitleBar locked={locked} autoLockIn={autoLockIn} pending={pending.length} />

        {!initialized ? (
          /* No vault yet: no sidebar, no navigation to screens that cannot mean
             anything, no product name in a header as well as in the title bar.
             Setup is the whole application at this point, and pretending
             otherwise is how a first run starts to feel broken. */
          <SetupScreen onCreated={refresh} onError={fail} />
        ) : (
        <div style={{ flex: 1, minHeight: 0, display: 'flex' }}>
      <AdminShell
        product="TEAvault"
        nav={nav}
        activeId={screen}
        onNavigate={(id) => setScreen(id as Screen)}
        actions={
          <Stack direction="horizontal" gap="ui">
            <Button
              variant="secondary"
              size="sm"
              loading={busy}
              disabled={locked}
              onClick={() => setEditing({ mode: 'create' })}
            >
              Add key
            </Button>
            <Button variant="primary" size="sm" disabled={locked} loading={busy} onClick={onLock}>
              Lock now
            </Button>
          </Stack>
        }
      >
        <Page>
          {error && (
            <Alert tone={error.code === 'integrity' ? 'critical' : 'caution'} role="alert">
              <AlertTitle>{titleForCode(error.code)}</AlertTitle>
              <AlertDescription>{error.message}</AlertDescription>
            </Alert>
          )}

          {locked && <UnlockPanel onUnlocked={refresh} onError={fail} />}

          {!locked && screen === 'keys' && (
            <>
              <PageHeader
                title="API keys"
                description="Metadata for every key this client may see. A key's value is never shown here — releasing it is a separate, permission-checked action."
              />
              <Stack gap="section">
                <SearchInput
                  label="Search keys"
                  placeholder="Name, provider or capability"
                  value={query}
                  onValueChange={setQuery}
                  clearable
                />

                {visible.length === 0 ? (
                  <EmptyState
                    title={query ? 'No keys match that search' : 'No API keys yet'}
                    description={
                      query
                        ? 'The search filtered everything out. Clearing it will show them again.'
                        : 'Add one to make it discoverable to your tools. Adding does not grant any application access to it.'
                    }
                    action={
                      query ? (
                        <Button variant="secondary" onClick={() => setQuery('')}>
                          Clear search
                        </Button>
                      ) : (
                        <Button variant="primary" onClick={() => setEditing({ mode: 'create' })}>
                          Add your first key
                        </Button>
                      )
                    }
                  />
                ) : (
                  <ScrollArea>
                    <VStack gap="ui">
                      {visible.map((e) => (
                        <EntryCard
                          key={e.id}
                          entry={e}
                          onOpen={() => {
                            setSelected(e)
                            setScreen('detail')
                          }}
                          onCopy={() => void onCopy(e)}
                          onDelete={async () => {
                            setBusy(true)
                            try {
                              await api.deleteEntry(e.id)
                              toast({ title: `${e.name} deleted`, tone: 'neutral' })
                              setSelected(null)
                              await refresh()
                            } catch (err) {
                              fail(err)
                            } finally {
                              setBusy(false)
                            }
                          }}
                        />
                      ))}
                    </VStack>
                  </ScrollArea>
                )}
              </Stack>
            </>
          )}

          {!locked && screen === 'detail' && (
            <DetailScreen
              entry={selected}
              onBack={() => setScreen('keys')}
              onError={fail}
              onEdit={(entry) => setEditing({ mode: 'edit', entry })}
            />
          )}

          {!locked && screen === 'access' && (
            <AccessScreen pending={pending} onRefresh={refresh} onError={fail} onAnswer={setAnswering} />
          )}

          {!locked && screen === 'audit' && <AuditScreen onError={fail} />}

          {!locked && screen === 'settings' && <SettingsScreen onError={fail} onSaved={refresh} />}
        </Page>
</AdminShell>
        </div>
        )}
      </div>

      {editing && (
        <EntryDialog
          mode={editing.mode}
          entry={editing.mode === 'edit' ? editing.entry : null}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null)
            await refresh()
          }}
          onError={fail}
        />
      )}

      {answering && (
        <ApprovalDialog
          approval={answering}
          onClose={() => setAnswering(null)}
          onResolved={async () => {
            setAnswering(null)
            await refresh()
          }}
          onError={fail}
        />
      )}
    </>
  )
}

function titleForCode(code: string): string {
  switch (code) {
    case 'locked':
    case 'vault_locked':
      return 'The vault is locked'
    case 'invalid_passphrase':
      return 'That passphrase was not accepted'
    case 'attempts_exhausted':
      return 'Too many attempts'
    case 'integrity':
      return 'Data did not verify'
    case 'needs_confirmation':
      return 'Waiting for your decision'
    case 'grant_expired':
      return 'That approval has expired'
    case 'no_grant':
    case 'operation_not_allowed':
    case 'denied_by_user':
      return 'Not allowed'
    default:
      return 'Something went wrong'
  }
}

function EntryCard({
  entry,
  onOpen,
  onCopy,
  onDelete,
}: {
  entry: ListEntry
  onOpen: () => void
  onCopy: () => void
  onDelete: () => void
}) {
  return (
    <Card>
      <CardHeader>
        <Stack direction="horizontal" align="center" justify="between" gap="ui">
          <VStack gap="none">
            {/* `level` is required: a card on a page whose heading is h1 is an h2. */}
            <CardTitle level={2}>{entry.display_name}</CardTitle>
            <Text size="ui" tone="muted">
              {entry.name}
            </Text>
          </VStack>
          <Stack direction="horizontal" gap="none" align="center">
            <StatusBadge domain="security" status={entry.granted ? 'ok' : 'warning'} />
            {entry.hidden && <Badge tone="neutral">hidden</Badge>}
          </Stack>
        </Stack>
      </CardHeader>
      <CardBody>
        <Stack gap="ui">
          <Stack direction="horizontal" gap="none" align="center">
            <Badge tone="info">{entry.provider}</Badge>
            {entry.capabilities.map((c) => (
              <Badge key={c} tone="neutral">
                {c}
              </Badge>
            ))}
          </Stack>
          {entry.description && (
            <Text size="body" tone="muted">
              {entry.description}
            </Text>
          )}
        </Stack>
      </CardBody>
      <CardFooter>
        <Stack direction="horizontal" gap="ui">
          <Button variant="outline" size="sm" onClick={onOpen}>
            Details
          </Button>
          <Button
            variant="secondary"
            size="sm"
            disabled={!entry.granted}
            title={
              entry.granted
                ? 'Copy the value to the clipboard'
                : 'This client has not been granted access to this key'
            }
            onClick={onCopy}
          >
            Copy
          </Button>
          <Button variant="ghost" size="sm" onClick={onDelete}>
            Delete
          </Button>
        </Stack>
      </CardFooter>
    </Card>
  )
}

function UnlockPanel({
  onUnlocked,
  onError,
}: {
  onUnlocked: () => Promise<void>
  onError: (e: unknown) => void
}) {
  const [passphrase, setPassphrase] = useState('')
  const [busy, setBusy] = useState(false)

  return (
    <Container size="sm" center>
      <Card>
        <CardHeader>
          <CardTitle level={2}>Unlock</CardTitle>
          <CardDescription>
            The master passphrase is never stored and never written to disk. There is no recovery
            if it is forgotten.
          </CardDescription>
        </CardHeader>
        <CardBody>
          <form
            onSubmit={async (e) => {
              e.preventDefault()
              setBusy(true)
              try {
                await api.unlock(passphrase)
                setPassphrase('')
                await onUnlocked()
              } catch (err) {
                onError(err)
              } finally {
                setBusy(false)
              }
            }}
          >
            <Stack gap="section">
              <Field required>
                <FieldLabel>Master passphrase</FieldLabel>
                <PasswordInput
                  autoComplete="current-password"
                  value={passphrase}
                  onValueChange={setPassphrase}
                  placeholder="Your master passphrase"
                />
                <FieldDescription>
                  The vault locks again after a period of inactivity, on sign-out, and on every
                  start. It is never unlocked automatically.
                </FieldDescription>
              </Field>
              <div>
                <Button type="submit" variant="primary" loading={busy} disabled={!passphrase}>
                  Unlock
                </Button>
              </div>
            </Stack>
          </form>
        </CardBody>
      </Card>
    </Container>
  )
}

function DetailScreen({
  entry,
  onBack,
  onError,
  onEdit,
}: {
  entry: ListEntry | null
  onBack: () => void
  onError: (e: unknown) => void
  onEdit: (entry: ListEntry) => void
}) {
  const [events, setEvents] = useState<AuditEvent[]>([])

  useEffect(() => {
    if (!entry) return
    void (async () => {
      try {
        // Derived from the audit log by entry name. The log holds no key values,
        // so nothing sensitive can reach this view through it.
        const all = await api.auditRecent(200)
        setEvents(all.filter((e) => JSON.stringify(e.event).includes(entry.name)).slice(0, 20))
      } catch (e) {
        onError(e)
      }
    })()
  }, [entry, onError])

  if (!entry) {
    return (
      <EmptyState
        title="No key selected"
        description="Pick one from the list."
        action={<Button onClick={onBack}>Back to all keys</Button>}
      />
    )
  }

  return (
    <VStack gap="section">
      <PageHeader
        title={entry.display_name}
        description={entry.name}
        breadcrumb={
          <Button variant="ghost" size="sm" onClick={onBack}>
            All keys
          </Button>
        }
        actions={
          <Stack direction="horizontal" gap="ui">
            <Button variant="outline" onClick={() => onEdit(entry)}>
              Edit
            </Button>
            <Button
              variant="secondary"
              disabled={!entry.granted}
              onClick={async () => {
                try {
                  const r = await api.copyToClipboard(entry.id)
                  toast({ title: 'Copied', description: r.masked, tone: 'caution' })
                } catch (e) {
                  onError(e)
                }
              }}
            >
              Copy value
            </Button>
          </Stack>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle level={2}>Metadata</CardTitle>
        </CardHeader>
        <CardBody>
          <VStack gap="ui" align="start">
            <DetailRow label="Provider" value={entry.provider} />
            <DetailRow label="Description" value={entry.description ?? '—'} />
            <DetailRow
              label="Capabilities"
              value={entry.capabilities.length ? entry.capabilities.join(', ') : '—'}
            />
            <DetailRow
              label="Available"
              value={
                entry.available
                  ? 'The vault is open. This does not mean the key is valid — TEAvault never contacts a provider to find out.'
                  : 'No'
              }
            />
            <DetailRow
              label="Access"
              value={
                entry.granted
                  ? 'This client may request the value.'
                  : 'This client may not request the value.'
              }
            />
            <DetailRow
              label="Discoverable"
              value={
                entry.hidden
                  ? 'Hidden — listed only for clients that already hold a grant.'
                  : 'Listed to any local client that can connect. The value still needs a grant.'
              }
            />
          </VStack>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle level={2}>Recent activity</CardTitle>
          <CardDescription>Security events for this key. Values are never recorded.</CardDescription>
        </CardHeader>
        <CardBody>
          {events.length === 0 ? (
            <Text size="body" tone="muted">
              Nothing recorded yet.
            </Text>
          ) : (
            <VStack gap="none" align="start">
              {events.map((e) => (
                <Text key={e.seq} size="ui" tone="muted">
                  {new Date(e.at).toLocaleString()} — {describeEvent(e)}
                </Text>
              ))}
            </VStack>
          )}
        </CardBody>
      </Card>
    </VStack>
  )
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <Stack direction="horizontal" gap="section" align="baseline">
      <Text size="ui" tone="muted">
        {label}
      </Text>
      <Text size="body">{value}</Text>
    </Stack>
  )
}

function describeEvent(e: AuditEvent): string {
  const kind = String(e.event.event ?? 'event')
  switch (kind) {
    case 'secret_released':
      return 'the value was released to an approved client'
    case 'secret_refused':
      return `a release was refused (${String(e.event.reason ?? '')})`
    case 'approval_requested':
      return 'an approval was requested'
    case 'approval_granted':
      return 'an approval was granted'
    case 'approval_denied':
      return 'an approval was denied'
    case 'key_copied':
      return 'the value was copied to the clipboard'
    default:
      return kind.replace(/_/g, ' ')
  }
}