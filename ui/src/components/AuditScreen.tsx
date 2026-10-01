/**
 * The activity log.
 *
 * Read-only by design. Nothing here can edit or delete an entry, because the
 * point of a log is that the UI cannot quietly tidy it. The chain verification
 * result comes from the core, not from this screen — if the chain is broken the
 * daemon refuses to serve the log at all rather than showing something it cannot
 * vouch for.
 */

import { useCallback, useEffect, useState } from 'react'

import { EmptyState, PageHeader } from '@tea-ui/admin'
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Stack,
  Text,
  VStack,
} from '@tea-ui/core'

import { api, AuditEvent } from '../api'

export function AuditScreen({ onError }: { onError: (e: unknown) => void }) {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setEvents(await api.auditRecent(200))
    } catch (e) {
      onError(e)
    } finally {
      setLoading(false)
    }
  }, [onError])

  useEffect(() => {
    void load()
  }, [load])

  return (
    <VStack gap="section">
      <PageHeader
        title="Activity"
        description="Security-relevant events: unlocks, requests, approvals, refusals, and changes to keys."
        actions={
          <Button variant="outline" size="sm" onClick={() => void load()}>
            Refresh
          </Button>
        }
      />

      <Alert tone="neutral" role="status">
        <AlertTitle>No secrets are recorded here</AlertTitle>
        <AlertDescription>
          Events carry identifiers and short descriptions only. Key values, passphrases and derived
          keys are never written to the log, and the log is hash-chained so a deletion or an edit
          is detectable.
        </AlertDescription>
      </Alert>

      {loading ? (
        <Text size="body" tone="muted">
          Loading…
        </Text>
      ) : events.length === 0 ? (
        <EmptyState
          title="Nothing has happened yet"
          description="Once you unlock the vault or a program asks for a key, those events appear here."
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle level={2}>{events.length} most recent events</CardTitle>
          </CardHeader>
          <CardBody>
            <VStack gap="none" align="start">
              {events.map((e) => (
                <Stack key={e.seq} direction="horizontal" gap="ui" align="baseline">
                  <Text size="ui" tone="subtle">
                    #{e.seq}
                  </Text>
                  <Text size="ui" tone="muted">
                    {new Date(e.at).toLocaleTimeString()}
                  </Text>
                  <Badge tone={toneFor(String(e.event.event))}>{describe(e)}</Badge>
                  {e.client && (
                    <Text size="ui" tone="subtle">
                      from {shortClient(e.client)}
                    </Text>
                  )}
                </Stack>
              ))}
            </VStack>
          </CardBody>
        </Card>
      )}
    </VStack>
  )
}

function describe(e: AuditEvent): string {
  const kind = String(e.event.event ?? 'event')
  switch (kind) {
    case 'vault_created':
      return 'vault created'
    case 'vault_unlocked':
      return 'vault unlocked'
    case 'vault_locked':
      return 'vault locked'
    case 'unlock_failed':
      return 'unlock refused'
    case 'unlock_lockout':
      return 'lockout after repeated failures'
    case 'passphrase_changed':
      return 'master passphrase changed'
    case 'metadata_listed':
      return 'metadata listed'
    case 'secret_released':
      return 'key released to an approved client'
    case 'secret_refused':
      return 'release refused'
    case 'approval_requested':
      return 'approval requested'
    case 'approval_granted':
      return 'approval granted'
    case 'approval_denied':
      return 'approval denied'
    case 'grant_created':
      return 'permission created'
    case 'grant_revoked':
      return 'permission revoked'
    case 'grants_revoked_for_client':
      return 'permissions revoked for a client'
    case 'key_created':
      return 'key added'
    case 'key_updated':
      return 'key changed'
    case 'key_deleted':
      return 'key deleted'
    case 'key_copied':
      return 'key copied to clipboard'
    case 'clipboard_cleared':
      return 'clipboard cleared'
    case 'backup_exported':
      return 'encrypted backup written'
    case 'backup_imported':
      return 'backup imported'
    case 'settings_changed':
      return 'settings changed'
    case 'bad_request':
      return 'malformed request refused'
    case 'security_control_refused':
      return 'security control refused a request'
    default:
      return kind.replace(/_/g, ' ')
  }
}

function toneFor(kind: string) {
  if (kind.includes('refused') || kind.includes('failed') || kind.includes('lockout') || kind === 'bad_request') {
    return 'critical' as const
  }
  if (kind.includes('released') || kind.includes('granted')) return 'caution' as const
  if (kind.includes('denied') || kind.includes('revoked') || kind.includes('deleted')) {
    return 'neutral' as const
  }
  return 'neutral' as const
}

/** The fingerprint is `name|path`; only the name is worth the width here. */
function shortClient(fingerprint: string): string {
  const [name] = fingerprint.split('|')
  return name || 'unknown'
}