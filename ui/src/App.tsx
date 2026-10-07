/**
 * The application shell.
 *
 * ## The shape of this product, and the shape of this window
 *
 * TEAvault is a 940x620 window that sits beside a text editor while something
 * else is running. It is not an application that is minimised; it is one that is
 * closed and reopened, so nothing here is designed to be kept on screen:
 *
 * * **Four views, one of which matters.** Keys is where the time goes. Access is
 *   where the decisions happen. Activity and Settings are reference. There is no
 *   dashboard, no metric row and no overview, because there is no question a
 *   summary of numbers would answer better than the list itself.
 * * **No route, no router, no history.** A tab state that survives a restart is
 *   not a feature; it is a window that opens on the wrong screen.
 * * **One dialog at a time, and it is modal for a reason.** Creating a key,
 *   changing the passphrase and restoring a backup all ask for something the user
 *   has to think about.
 *
 * ## Resource behaviour
 *
 * No polling. `refresh` runs on mount, after a mutation, and on a window-focus
 * event, and that is the whole refresh story. A timer would wake the WebView every
 * second to learn nothing — and the countdown in the title bar is computed
 * locally from the value the daemon last reported, precisely so that it can tick
 * without a round trip.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Alert, Button, HStack, Stack, Text, toast } from '@tea-ui/core'

import { api } from './api'
import { VaultError } from './api'
import type {
  AuditEvent,
  GrantModeWire,
  KnownClient,
  ListEntry,
  PendingApproval,
  Row,
  Settings,
  Status,
} from './api'
import { AccessPanel } from './components/AccessPanel'
import { ActivityPanel } from './components/ActivityPanel'
import { CopiedNote, EntryDialog, type EntryInput } from './components/EntryDialog'
import { KeysPanel, UnlockPanel } from './components/KeysPanel'
import { SettingsPanel } from './components/SettingsPanel'
import { SetupScreen } from './components/SetupScreen'
import { TitleBar, type View } from './components/TitleBar'

const PROVIDERS = ['OpenAI', 'Anthropic', 'Google', 'Azure', 'GitHub', 'AWS', 'Other']

export default function App() {
  const [view, setView] = useState<View>('keys')
  const [status, setStatus] = useState<Status | null>(null)
  const [entries, setEntries] = useState<ListEntry[]>([])
  const [pending, setPending] = useState<PendingApproval[]>([])
  const [rows, setRows] = useState<Row[]>([])
  const [known, setKnown] = useState<KnownClient[]>([])
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [settings, setSettings] = useState<Settings | null>(null)
  const [error, setError] = useState<VaultError | null>(null)
  const [busy, setBusy] = useState(false)
  const [editing, setEditing] = useState<ListEntry | null | 'new'>(null)
  const [copied, setCopied] = useState<{ masked: string; clearedIn: number | null } | null>(null)

const reportedAt = useRef<number>(0)

  const report = useCallback((e: unknown) => {
    const err = e instanceof VaultError ? e : new VaultError({ code: 'io', message: String(e), retryable: false })
    setError(err)
  }, [])

  const initialized = !setup && status !== null

  const refresh = useCallback(async () => {
    const s = await api.status()
    setStatus(s)

    // Only ask for things that are answerable. Asking `list` and `approvals` on a
    // locked or uninitialised vault produces a refusal, and rendering that refusal
    // as a red banner above the unlock form reads as "something is broken" when
    // in fact everything is behaving correctly.
    if (s.initialized && !s.locked) {
      const [list, approvals, access, clients] = await Promise.all([
        api.list(),
        api.approvals(),
        api.accessOverview(),
        api.knownClients(),
      ])
      setEntries(list.entries)
      setPending(approvals)
      setRows(access)
      setKnown(clients)
    } else {
      setEntries([])
      setPending([])
      setRows([])
      setKnown([])
    }

    if (s.initialized && view === 'activity') {
      setEvents(await api.auditRecent(200))
    }
    if (s.initialized && view === 'settings' && !settings) {
      setSettings(await api.getSettings())
    }

reportedAt.current = Date.now()
  }, [view, settings])

  useEffect(() => {
    void refresh().catch(report)
    // Re-read when the window regains focus. The daemon is a separate process and
    // the user may have locked it from the tray while this window was behind
    // something else, so the local state can be stale.
    const onFocus = () => void refresh().catch(report)
    window.addEventListener('focus', onFocus)
    return () => window.removeEventListener('focus', onFocus)
  }, [refresh, report])

// The clipboard countdown is local for the same reason, and it clears the note
  // rather than polling the daemon to find out whether the value is gone.
  useEffect(() => {
    if (!copied || copied.clearedIn === null) return
    if (copied.clearedIn <= 0) {
      setCopied(null)
      return
    }
    const id = setTimeout(() => {
      setCopied((c) => (c ? { ...c, clearedIn: (c.clearedIn ?? 1) - 1 } : null))
    }, 1000)
    return () => clearTimeout(id)
  }, [copied])

  async function guard<T>(label: string, f: () => Promise<T>): Promise<T | null> {
    setBusy(true)
    setError(null)
    try {
      return await f()
    } catch (e) {
      report(e)
      return null
    } finally {
      setBusy(false)
      void label
    }
  }

  const locked = status?.locked ?? true
  const pendingCount = pending.length

  const errorText = useMemo(() => {
    if (!error) return null
    return {
      code: error.code,
// A vault that got locked elsewhere is not an error worth shouting about —
      // the unlock panel is already the answer.
      hidden: error.code === 'vault_locked' || error.code === 'needs_confirmation',
      message: titleFor(error.code),
      detail: error.message,
    }
  }, [error])

  if (!status) {
    return (
      <div style={{ height: '100vh', display: 'grid', placeItems: 'center' }}>
        <Stack gap="ui" align="center">
          <Text size="ui" tone="muted">
            Connecting to the TEAvault background process…
          </Text>
          {errorText && (
            <Alert tone="critical" role="alert">
              <Text size="ui">{errorText.detail}</Text>
            </Alert>
          )}
          <Button size="sm" variant="secondary" onClick={() => void refresh().catch(report)}>
            Try again
          </Button>
        </Stack>
      </div>
    )
  }

  if (!initialized) {
    return (
      <Shell locked initialized pending={0} view={view} onView={setView} onLock={() => {}}>
        <SetupScreen
          onCreated={async (passphrase) => {
            await guard('created', async () => {
              await api.init(passphrase)
              await refresh()
            })
          }}
        />
      </Shell>
    )
  }

  return (
    <Shell
locked={locked}
      initialized
      pending={pendingCount}
      view={view}
      onView={(v) => {
        setView(v)
        // Per-view data is fetched on demand, not eagerly on every state change.
        if (v === 'activity') void api.auditRecent(200).then(setEvents).catch(report)
        if (v === 'settings' && !settings) void api.getSettings().then(setSettings).catch(report)
      }}
      onLock={() => void guard('locked', async () => { await api.lock(); await refresh() })}
    >
      {locked ? (
<UnlockPanel
          onUnlock={async (passphrase) => {
            await guard('unlocked', async () => {
              await api.unlock(passphrase)
              await refresh()
            })
          }}
          onWipe={async () => {
            // After a wipe the vault does not exist, so `refresh` lands on the
            // setup screen. Nothing else needs clearing: the passphrase only ever
            // lived inside the panel, which unmounts, and every view reads from the
            // daemon rather than from state the wipe could leave stale.
            await guard('wiped', async () => {
              await api.wipe()
              await refresh()
            })
          }}
        />
      ) : (
        <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
          {errorText && !errorText.hidden && (
            <div style={{ padding: '10px 16px 0' }}>
              <Alert tone="critical" role="alert">
                <HStack align="center" justify="between" gap="ui">
                  <Text size="ui">
                    {errorText.message} — {errorText.detail}
                  </Text>
                  <Button size="sm" variant="ghost" onClick={() => setError(null)}>
                    Dismiss
                  </Button>
                </HStack>
              </Alert>
            </div>
          )}

          {copied && (
            <div style={{ padding: '10px 16px 0' }}>
              <CopiedNote masked={copied.masked} clearedIn={copied.clearedIn} />
            </div>
          )}

          <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
            {view === 'keys' && (
              <KeysPanel
                entries={entries}
                pendingCount={pendingCount}
                onAdd={() => setEditing('new')}
                onEdit={setEditing}
                onCopy={async (e) => {
                  const r = await guard('copied', async () => {
                    const out = await api.copyToClipboard(e.name)
                    await refresh()
                    return out
                  })
                  if (r) {
                    setCopied({
                      masked: r.masked,
                      clearedIn: settings?.clipboard_clear_seconds
                        ? settings.clipboard_clear_seconds
                        : null,
                    })
                    toast({
                      title: 'Copied to the clipboard',
                      description: `${e.name} — it clears itself after ${settings?.clipboard_clear_seconds ?? 0}s. Any program running as you can read the clipboard in the meantime.`,
                      tone: 'caution',
                    })
                  }
                }}
                onDelete={async (e) => {
                  const r = await guard('deleted', async () => {
                    await api.deleteEntry(e.name)
                    await refresh()
                  })
                  if (r !== null) toast({ title: `${e.name} deleted` })
                }}
                onGoToAccess={() => setView('access')}
                onSetCategory={async (e, category) => {
                  const done = await guard('moved', async () => {
                    await api.updateEntry(e.id, {
                      display_name: e.display_name,
                      provider: e.provider,
                      description: e.description,
                      hidden: e.hidden,
                      capabilities: e.capabilities,
                      category,
                    })
                    await refresh()
                  })
                  if (done !== null) {
                    toast({
                      title: category ? `Moved to ${category}` : 'Removed from its category',
                    })
                  }
                }}
              />
            )}

            {view === 'access' && (
              <AccessPanel
                pending={pending}
                rows={rows}
                known={known}
                onAnswer={async (p, mode: GrantModeWire) => {
                  const r = await guard('answered', async () => {
                    await api.resolveApproval(p.request_id, p.entry_name, mode)
                    await refresh()
                  })
                  if (r !== null) {
                    toast({
                      title:
                        mode === 'deny'
                          ? 'Denied'
                          : mode === 'allow_once'
                            ? 'Allowed once'
                            : 'Always allowed',
                      description:
                        mode === 'always_allow'
                          ? `${p.client_label} can read ${p.entry_name} until you revoke it.`
                          : undefined,
                    })
                  }
                }}
                onRevoke={async (grantId) => {
                  await guard('revoked', async () => {
                    await api.revokeGrant(grantId)
                    await refresh()
                  })
                }}
                onRevokeClient={async (fp) => {
                  await guard('revoked', async () => {
                    await api.revokeClient(fp)
                    await refresh()
                  })
                }}
              />
            )}

            {view === 'activity' && <ActivityPanel events={events} />}

            {view === 'settings' &&
              (settings ? (
                <SettingsPanel
                  settings={settings}
                  onSave={async (s) => {
                    const applied = await guard('saved', async () => {
                      const out = await api.setSettings(s)
                      await refresh()
                      return out
                    })
                    if (applied) setSettings(applied)
                  }}
                  onChangePassphrase={async (current, next) => {
                    await guard('changed', async () => {
                      await api.changePassphrase(current, next)
                    })
                  }}
onBackup={async (file, passphrase) => {
                    await guard('backed up', async () => {
                      const out = await api.backupExport(file, passphrase)
                      toast({ title: 'Backup written', description: out.path })
                    })
                  }}
                  onRestore={async (file, passphrase, overwrite) => {
                    await guard('restored', async () => {
                      const r = await api.backupImport(file, passphrase, overwrite)
                      await refresh()
                      toast({
                        title: 'Backup restored',
                        description: `${r.added} added, ${r.skipped} kept, ${r.replaced} replaced.`,
                      })
                    })
                  }}
                />
              ) : (
                <div style={{ padding: '20px' }}>
                  <Text size="ui" tone="muted">
                    Loading settings…
                  </Text>
                </div>
              ))}
          </div>
        </div>
      )}

      {editing && (
        <EntryDialog
          entry={editing === 'new' ? null : editing}
          providers={PROVIDERS}
          categories={[...new Set(entries.map((e) => e.category).filter((c): c is string => typeof c === 'string' && c.length > 0))].sort()}
          onClose={() => setEditing(null)}
          onError={report}
          onSave={async (input: EntryInput) => {
            const saved = await guard('saved', async () => {
              if (input.id) {
                await api.updateEntry(input.id, {
                  display_name: input.display_name,
                  provider: input.provider,
                  description: input.description,
                  hidden: input.hidden,
                  secret: input.secret ?? undefined,
                  category: input.category ?? undefined,
                })
              } else {
                await api.createEntry({
                  name: input.name,
                  display_name: input.display_name,
                  provider: input.provider,
                  description: input.description,
                  hidden: input.hidden,
                  secret: input.secret ?? '',
                  capabilities: input.capabilities,
                  category: input.category ?? undefined,
                })
              }
              await refresh()
            })
            if (saved !== null) {
              setEditing(null)
              toast({ title: input.id ? 'Key updated' : `${input.name} added` })
            }
          }}
        />
      )}

      {busy && null}
    </Shell>
  )
}

/**
 * The frame: title bar with navigation, then the content.
 *
 * Split out so the first-run and locked states get the same bar as the main views
 * — a layout that changes when the vault is locked makes the window feel like a
 * different application each time it opens.
 */
function Shell({
  locked,
  initialized,
  pending,
  view,
  onView,
  onLock,
  children,
}: {
  locked: boolean
  initialized: boolean
  pending: number
  view: View
  onView: (v: View) => void
  onLock: () => void
  children: React.ReactNode
}) {
return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        width: '100%',
        // The window is a fixed size, so there is nothing to scroll to
        // horizontally. Allowing it anyway would let a wide child grow the
        // document, and every centred element on the page would then centre
        // against the overflow width rather than the window — which is a
        // confusing thing to debug and an obvious-looking one once seen.
        overflow: 'hidden',
      }}
    >
      <TitleBar
        locked={locked}
        initialized={initialized}
        pending={pending}
        view={view}
        onView={onView}
        onLock={onLock}
      />
      <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
        {children}
      </div>
    </div>
  )
}

function titleFor(code: string): string {
  switch (code) {
    case 'locked':
    case 'vault_locked':
      return 'The vault is locked'
    case 'invalid_passphrase':
      return 'That passphrase was not accepted'
    case 'attempts_exhausted':
      return 'Too many attempts'
    case 'integrity':
      return 'Stored data did not verify'
    case 'needs_confirmation':
      return 'Waiting for your decision'
    case 'denied_by_user':
      return 'Access was denied'
    case 'expired':
      return 'That permission has expired'
    case 'operation_not_allowed':
      return 'Not permitted'
    case 'io':
      return 'Could not reach the background process'
    default:
      return 'Something went wrong'
  }
}
