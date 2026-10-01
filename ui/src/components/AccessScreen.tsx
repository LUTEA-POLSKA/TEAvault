/**
 * Access management.
 *
 * Shows pending requests first — those are the ones where the clock is running
 * for the requesting program — then the standing grants, with revocation on
 * each. Revocation is deliberately prominent: an approval nobody can take back
 * is not an approval.
 */

import { useCallback, useEffect, useState } from 'react'

import { EmptyState, PageHeader } from '@tea-ui/admin'
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Button,
  Callout,
  Card,
  CardBody,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
  Stack,
  Text,
  VStack,
} from '@tea-ui/core'

import { AccessRow, api, Grant, PendingApproval } from '../api'

export function AccessScreen({
  pending,
  onRefresh,
  onError,
  onAnswer,
}: {
  pending: PendingApproval[]
  onRefresh: () => Promise<void>
  onError: (e: unknown) => void
  onAnswer: (p: PendingApproval) => void
}) {
  const [rows, setRows] = useState<AccessRow[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setRows(await api.accessOverview())
    } catch (e) {
      onError(e)
    } finally {
      setLoading(false)
    }
  }, [onError])

  useEffect(() => {
    void load()
  }, [load])

  const withGrants = rows.filter(([, grants]) => grants.length > 0)

  return (
    <VStack gap="section">
      <PageHeader
        title="Access"
        description="Who may request which key, and how long that permission lasts. Every decision here is recorded."
      />

      {pending.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle level={2}>Waiting for your decision</CardTitle>
            <CardDescription>
              A program asked for a key and was refused until you answer.
            </CardDescription>
          </CardHeader>
          <CardBody>
            <VStack gap="ui" align="start">
              {pending.map((p) => (
                <Stack key={p.request_id} direction="horizontal" gap="ui" align="center">
                  <VStack gap="none" align="start">
                    <Text size="body">
                      {p.client_label} wants {p.entry_name}
                    </Text>
                    <Text size="ui" tone="muted">
                      {p.client_path}
                      {p.client_elevated ? ' · runs as administrator' : ''}
                    </Text>
                  </VStack>
                  <Button variant="primary" size="sm" onClick={() => onAnswer(p)}>
                    Review
                  </Button>
                </Stack>
              ))}
            </VStack>
          </CardBody>
        </Card>
      )}

      {loading ? (
        <Text size="body" tone="muted">
          Loading…
        </Text>
      ) : withGrants.length === 0 ? (
        <EmptyState
          title="No permissions have been granted"
          description="Nothing has asked for a key, and nothing is allowed to take one. When a program requests a key it will appear here for you to decide."
        />
      ) : (
        withGrants.map(([meta, grants]) => (
          <Card key={meta.id}>
            <CardHeader>
              <CardTitle level={2}>{meta.display_name}</CardTitle>
              <CardDescription>
                {meta.name} · {meta.provider}
              </CardDescription>
            </CardHeader>
            <CardBody>
              <VStack gap="ui" align="start">
                {grants.map((g) => (
                  <Stack key={g.id} direction="horizontal" gap="ui" align="center">
                    <VStack gap="none" align="start">
                      <Text size="body">{g.client_label}</Text>
                      <Text size="ui" tone="muted">
                        {modeLabel(g)} · granted {new Date(g.granted_at).toLocaleString()}
                      </Text>
                      {g.project_dir && (
                        <Text size="ui" tone="subtle">
                          Project directory reported by the client: {g.project_dir} (unverified)
                        </Text>
                      )}
                    </VStack>
                    <Badge tone={g.mode.mode === 'deny' ? 'critical' : 'neutral'}>
                      {g.mode.mode === 'deny' ? 'denied' : g.mode.mode === 'allow_once' ? 'once' : 'standing'}
                    </Badge>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={async () => {
                        try {
                          await api.revokeGrant(g.id)
                          await load()
                          await onRefresh()
                        } catch (e) {
                          onError(e)
                        }
                      }}
                    >
                      Revoke
                    </Button>
                  </Stack>
                ))}
              </VStack>
            </CardBody>
            <CardFooter>
              <Callout tone="neutral" title="Revoking is immediate">
                A revoked client is refused the next time it asks, and any standing permission for
                this key is gone. Existing one-shot approvals are spent.
              </Callout>
            </CardFooter>
          </Card>
        ))
      )}

      <Alert tone="info" role="status">
        <AlertTitle>Approvals are per key, not per application</AlertTitle>
        <AlertDescription>
          Granting one program access to one key says nothing about any other key, and nothing about
          any other program.
        </AlertDescription>
      </Alert>
    </VStack>
  )
}

function modeLabel(g: Grant): string {
  switch (g.mode.mode) {
    case 'allow_once':
      return g.consumed ? 'allowed once, already spent' : 'allowed once'
    case 'always_allow':
      return g.mode.expires_at
        ? `until ${new Date(g.mode.expires_at * 1000).toLocaleString()}`
        : 'no expiry'
    case 'deny':
      return 'denied'
    default:
      return 'unknown'
  }
}