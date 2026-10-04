/**
 * What happened, recently.
 *
 * This is a reference screen, not a dashboard. There is one table, newest first,
 * and no charts, no counters and no trend line — a credential vault has no
 * metrics worth graphing, and a big number at the top of this screen would only
 * compete with the entries themselves.
 *
 * The limit is deliberately small. The audit log on disk keeps far more; this
 * shows the part a user is likely to look at, and says so rather than implying the
 * list is complete.
 */

import { Badge, Card, CardBody, Stack, Text } from '@tea-ui/core'
import { EmptyState } from './Empty'
import type { AuditEvent } from '../api'

export function ActivityPanel({ events }: { events: AuditEvent[] }) {
  if (events.length === 0) {
    return (
      <div style={{ padding: '20px', display: 'flex', justifyContent: 'center' }}>
        <Card style={{ maxWidth: '460px' }}>
          <CardBody>
            <EmptyState
              title="Nothing recorded yet"
              description="Unlocks, key changes, permission decisions and every refusal are written here as they happen."
            />
          </CardBody>
        </Card>
      </div>
    )
  }

  return (
    <Stack gap="ui" style={{ padding: '12px 16px', minHeight: 0 }}>
      <Text size="ui" tone="muted">
        The most recent {events.length} events. The full history is kept on disk in an append-only,
        hash-chained log.
      </Text>
      <Card>
        <CardBody>
          <Stack gap="none" role="list">
            {events.map((e, i) => (
              <div
                key={`${e.seq}-${i}`}
                role="listitem"
                style={{
                  display: 'flex',
                  alignItems: 'baseline',
                  gap: '10px',
                  padding: '6px 0',
                  borderTop: i === 0 ? 'none' : '1px solid var(--tea-line)',
                }}
              >
                <Text
                  size="ui"
                  tone="subtle"
                  style={{ width: '150px', flexShrink: 0, fontFamily: 'var(--tea-font-mono)' }}
                >
                  {formatTime(e.at)}
                </Text>
                <Text size="ui" style={{ flex: 1 }}>
                  {describe(e.kind?.event)}
                </Text>
                {e.client && (
                  <Badge variant="subtle" tone="neutral">
                    {e.client}
                  </Badge>
                )}
              </div>
            ))}
          </Stack>
        </CardBody>
      </Card>
    </Stack>
  )
}

function formatTime(at: string): string {
  const d = new Date(at)
  if (Number.isNaN(d.getTime())) return at
  return d.toLocaleString(undefined, {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/**
 * Turn an event name into a sentence.
 *
 * The wire format carries `snake_case` identifiers. A table of identifiers is
 * accurate and unreadable, and this screen exists to be read.
 *
 * Total by design: an unrecognised or missing name falls back to the raw string
 * with underscores spaced out, never to a throw. This function runs inside a
 * render, so anything it throws takes the whole window down, and a log that grows
 * a new event type is exactly when that must not happen. The earlier version
 * ended in `event.replace(...)` and blanked the screen on an unknown name.
 */
function describe(event: string | undefined): string {
  if (typeof event !== 'string' || event === '') return 'Unknown event'
  const known = subject[event]
  if (known) return known
  return event.replace(/_/g, ' ')
}

const subject: Record<string, string> = {
    vault_created: 'Vault created',
    vault_unlocked: 'Vault unlocked',
    vault_locked: 'Vault locked',
    unlock_failed: 'Wrong master passphrase',
    unlock_lockout: 'Too many wrong passphrases — locked out briefly',
    passphrase_changed: 'Master passphrase changed',
    metadata_listed: 'Listed the available keys',
    metadata_read: 'Looked up one key',
    secret_released: 'Released a key value to an approved program',
    secret_refused: 'Refused a key request',
    approval_requested: 'A program asked for a key',
    approval_granted: 'Request approved',
    approval_denied: 'Request denied',
    grant_created: 'Permission created',
    grant_revoked: 'Permission revoked',
    grants_revoked_for_client: 'All permissions for one program revoked',
    key_created: 'Key added',
    key_updated: 'Key changed',
    key_deleted: 'Key deleted',
    key_copied: 'Key copied to the clipboard',
    clipboard_cleared: 'Clipboard cleared',
    backup_exported: 'Encrypted backup written',
    backup_imported: 'Backup imported',
    settings_changed: 'Settings changed',
    security_control_refused: 'A security control refused a request',
}
