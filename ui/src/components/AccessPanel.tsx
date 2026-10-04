/**
 * Who may read what, and the decisions waiting on the user.
 *
 * ## Why the pending requests come first and are inline
 *
 * A request is the only thing on this screen that is live: a program is blocked
 * right now, waiting for an answer, and the answer is often obvious from the
 * program name and the key it wants. Putting it behind a tab, a dialog and a
 * confirm button adds three steps to a decision that should take one.
 *
 * So an unanswered request is a full-width card at the top with its decision
 * buttons on it. Everything else — the standing permissions — is reference
 * material below it, and the user scrolls to it when there is nothing pending.
 *
 * ## What a request shows
 *
 * The program, its path, whether it is running elevated, the key, and the purpose
 * the program itself gave. The path and the elevation flag are the parts that
 * distinguish "the CLI I asked for" from "something that happens to be called
 * `node.exe`", so they are shown rather than summarised.
 */

import { useState } from 'react'
import {
  Badge,
  Button,
  Callout,
  Card,
  CardBody,
  CardHeader,
  HStack,
  Stack,
  Text,
} from '@tea-ui/core'
import { CardTitle, EmptyState } from './Empty'
import type { Grant, GrantModeWire, KnownClient, PendingApproval, Row } from '../api'

export function AccessPanel({
  pending,
  rows,
  known,
  onAnswer,
  onRevoke,
  onRevokeClient,
}: {
  pending: PendingApproval[]
  rows: Row[]
  known: KnownClient[]
  onAnswer: (p: PendingApproval, mode: GrantModeWire) => void
  onRevoke: (grantId: string) => void
  onRevokeClient: (fingerprint: string) => void
}) {
  const [expanded, setExpanded] = useState<string | null>(null)
  const standalone = rows.filter((r) => r.grants.length === 0)

  return (
    <Stack gap="ui" style={{ padding: '12px 16px', minHeight: 0, overflowY: 'auto' }}>
      {pending.length === 0 ? (
        <Text size="ui" tone="muted">
          Nothing is waiting for a decision.
        </Text>
      ) : (
        pending.map((p) => (
          <RequestCard key={p.request_id} request={p} onAnswer={onAnswer} />
        ))
      )}

      <Card>
        <CardHeader>
          <CardTitle>Programs with access</CardTitle>
        </CardHeader>
        <CardBody>
          {rows.length === 0 && standalone.length === 0 ? (
            <EmptyState
              title="No permissions yet"
              description="A program asks for a key the first time it needs one. You decide here whether it gets it."
            />
          ) : (
            <Stack gap="xs" role="list">
              {rows.map((row) => {
                const open = expanded === row.entry.id
                return (
                  <div
                    key={row.entry.id}
                    role="listitem"
                    style={{
                      border: '1px solid var(--tea-line)',
                      borderRadius: '5px',
                    }}
                  >
                    <button
                      type="button"
                      aria-expanded={open}
                      onClick={() => setExpanded(open ? null : row.entry.id)}
                      style={{
                        all: 'unset',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        width: '100%',
                        boxSizing: 'border-box',
                        padding: '7px 10px',
                        cursor: 'pointer',
                      }}
                    >
                      <Text size="ui" weight="semibold" style={{ flex: 1 }}>
                        {row.entry.name}
                      </Text>
                      {row.grants.length === 0 ? (
                        <Badge variant="subtle" tone="neutral">
                          nobody
                        </Badge>
                      ) : (
                        <Badge variant="subtle" tone="positive">
                          {row.grants.length}{' '}
                          {row.grants.length === 1 ? 'program' : 'programs'}
                        </Badge>
                      )}
                      <Text size="ui" tone="subtle" aria-hidden="true">
                        {open ? '▾' : '▸'}
                      </Text>
                    </button>

                    {open && row.grants.length > 0 && (
                      <Stack gap="xs" style={{ padding: '0 10px 8px' }}>
                        {row.grants.map((g) => (
                          <HStack
                            key={g.id}
                            align="center"
                            justify="between"
                            gap="ui"
                            style={{
                              paddingTop: '6px',
                              borderTop: '1px solid var(--tea-line)',
                            }}
                          >
                            <Stack gap="none" style={{ minWidth: 0 }}>
                              <Text size="ui">{g.client_label}</Text>
                              <Text size="ui" tone="subtle" truncate>
                                {describeGrant(g)}
                              </Text>
                            </Stack>
                            <HStack gap="xs">
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => onRevokeClient(g.client_fingerprint)}
                              >
                                Revoke all
                              </Button>
                              <Button size="sm" variant="ghost" onClick={() => onRevoke(g.id)}>
                                Revoke
                              </Button>
                            </HStack>
                          </HStack>
                        ))}
                      </Stack>
                    )}
                  </div>
                )
              })}
            </Stack>
          )}
        </CardBody>
      </Card>

      {known.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Programs that have connected</CardTitle>
          </CardHeader>
          <CardBody>
            <Text size="ui" tone="muted">
              A permission can only be created for one of these. TEAvault never grants access to a
              program it has not actually seen ask.
            </Text>
            <Stack gap="xs" style={{ marginTop: '8px' }}>
              {known.map((c) => (
                <HStack key={c.fingerprint} align="center" justify="between" gap="ui">
                  <Text size="ui" style={{ fontFamily: 'var(--tea-font-mono)' }}>
                    {c.label}
                  </Text>
                  <Text size="ui" tone="subtle">
                    connected
                  </Text>
                </HStack>
              ))}
            </Stack>
          </CardBody>
        </Card>
      )}
    </Stack>
  )
}

function RequestCard({
  request,
  onAnswer,
}: {
  request: PendingApproval
  onAnswer: (p: PendingApproval, mode: GrantModeWire) => void
}) {
  return (
    <Card style={{ borderColor: 'var(--tea-caution)' }}>
      <CardHeader>
        <CardTitle>
          {request.client_label} wants {request.entry_name}
        </CardTitle>
      </CardHeader>
      <CardBody>
        <Stack gap="ui">
          <Stack gap="xs">
            <HStack gap="ui" align="center">
              <Text size="ui" weight="semibold">
                Program
              </Text>
              <Text size="ui" tone="muted" style={{ fontFamily: 'var(--tea-font-mono)', wordBreak: 'break-all' }}>
                {request.client_path}
              </Text>
              {request.client_elevated && (
                // Elevation is a security fact the user cannot see from the path, so
                // it is stated rather than left for them to work out.
                <Badge variant="subtle" tone="caution">
                  running as administrator
                </Badge>
              )}
            </HStack>
            <HStack gap="ui" align="center">
              <Text size="ui" weight="semibold">
                Wants
              </Text>
              <Text size="ui">the key value itself, so it can call the provider</Text>
            </HStack>
            {request.declared_purpose && (
              <HStack gap="ui" align="baseline">
                <Text size="ui" weight="semibold">
                  Says it needs it to
                </Text>
                <Text size="ui" tone="muted">
                  “{request.declared_purpose}”
                </Text>
              </HStack>
            )}
            {/*
              Quoted, because it is the program's own text. A request claiming
              "approved by the user" must not be able to render as if TEAvault
              said it.
            */}
            <Text size="ui" tone="subtle">
              Anything in quotes above was written by the program, not by you.
            </Text>
          </Stack>

          <HStack gap="ui" align="center" justify="between">
            <HStack gap="ui">
              <Button
                size="sm"
                variant="primary"
                onClick={() => onAnswer(request, 'allow_once')}
              >
                Allow once
              </Button>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => onAnswer(request, 'always_allow')}
              >
                Always allow
              </Button>
            </HStack>
            <Button size="sm" variant="ghost" onClick={() => onAnswer(request, 'deny')}>
              Deny
            </Button>
          </HStack>
          <Text size="ui" tone="subtle">
            “Always allow” stays in effect until you revoke it. A deny is remembered too, so the
            program stops asking.
          </Text>
        </Stack>
      </CardBody>
    </Card>
  )
}

/**
 * A grant's mode arrives as the tagged union the daemon stores, not as a label.
 * The wire form is the single source of truth, so this reads it rather than
 * depending on a display string that could be phrased differently.
 */
function describeGrant(g: Grant): string {
  if (g.consumed) return 'allowed once, already used'
  if (g.mode.mode === 'deny') return 'denied'
  if (g.mode.mode === 'always_allow') {
    return g.mode.expires_at
      ? `always allowed, expires ${new Date(g.mode.expires_at * 1000).toLocaleString()}`
      : 'always allowed, no expiry'
  }
  return 'allowed once'
}

/** A refusal worth saying out loud at the top of a panel. */
export function AccessError({ message }: { message: string }) {
  return (
    <Callout tone="caution" title="Could not load access information">
      <Text size="ui">{message}</Text>
    </Callout>
  )
}
