/**
 * The approval dialog.
 *
 * This is the most security-relevant screen in the product, and its design
 * constraint is narrow: **show enough that the user can recognise what is being
 * asked for, and show nothing about the secret.**
 *
 * Two things follow from that:
 *
 * 1. Every field below is unverified except the ones the kernel reported. The
 *    process path comes from `GetNamedPipeClientProcessId`; the purpose string is
 *    whatever the client typed, so it is quoted and attributed. Nothing here
 *    claims to be verified when it is not.
 * 2. The key's value is not available to this component. `PendingApproval` has
 *    no field for one, so the dialog cannot show it even by accident.
 *
 * The default focus is Deny, and Allow-once is offered alongside Always because
 * a standing grant for a tool that runs constantly is a much larger decision
 * than a single use.
 */

import { useState } from 'react'

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Button,
  Callout,
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Stack,
  Text,
} from '@tea-ui/core'

import { api, PendingApproval } from '../api'

export function ApprovalDialog({
  approval,
  onClose,
  onResolved,
  onError,
}: {
  approval: PendingApproval
  onClose: () => void
  onResolved: () => Promise<void>
  onError: (e: unknown) => void
}) {
  const [busy, setBusy] = useState(false)

  async function decide(mode: 'allow_once' | 'always_allow' | 'deny') {
    setBusy(true)
    try {
      await api.resolveApproval(approval.request_id, approval.entry_id, mode)
      onClose()
      await onResolved()
    } catch (e) {
      onError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent size="lg" closeLabel="Dismiss">
        <DialogHeader>
          <DialogTitle>A tool is asking for an API key</DialogTitle>
          <DialogDescription>
            Nothing has been released yet. Choose what {approval.client_label} may do with it.
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          <Stack gap="section">
            <Stack gap="none">
              <Field label="Application" value={approval.client_label} />
              <Field label="Process path" value={approval.client_path} />
              <Field
                label="Process ID"
                value={`${approval.client_pid}`}
                note="Reported by Windows. The process may have exited by now."
              />
              <Field
                label="Elevated"
                value={approval.client_elevated ? 'Yes — runs as administrator' : 'No'}
              />
              <Field label="Requested key" value={approval.entry_name} />
              <Field
                label="Stated purpose"
                value={
                  approval.declared_purpose
                    ? `“${approval.declared_purpose}” — written by the requesting program, not verified`
                    : 'Not stated'
                }
              />
              <Field label="Requested at" value={new Date(approval.requested_at).toLocaleString()} />
            </Stack>

            <Callout tone="caution" title="What you are choosing">
              Allow once releases the value for this single request. Always allow keeps working
              until you revoke it. Deny blocks this program for this key, and a deny wins over any
              earlier approval.
            </Callout>

            {approval.client_elevated && (
              <Alert tone="critical" role="alert">
                <AlertTitle>This process runs as administrator</AlertTitle>
                <AlertDescription>
                  That is unusual for a tool asking for an API key. Make sure you recognise it.
                </AlertDescription>
              </Alert>
            )}

            <Stack direction="horizontal" gap="none">
              <Badge tone="neutral">This dialog never shows the key</Badge>
            </Stack>
          </Stack>
        </DialogBody>

        <DialogFooter>
          <Stack direction="horizontal" gap="ui" justify="end">
            {/* Deny first in the DOM order, and it is what a reflexive Enter
                would hit if the buttons were in visual order. */}
            <Button variant="destructive" loading={busy} onClick={() => void decide('deny')}>
              Deny
            </Button>
            <Button variant="secondary" loading={busy} onClick={() => void decide('allow_once')}>
              Allow once
            </Button>
            <Button variant="primary" loading={busy} onClick={() => void decide('always_allow')}>
              Always allow
            </Button>
          </Stack>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function Field({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <Stack direction="horizontal" gap="section" align="baseline">
      <Text size="ui" tone="muted">
        {label}
      </Text>
      <Text size="body">
        {value}
        {note && (
          <>
            {' '}
            <Text size="ui" tone="subtle">
              ({note})
            </Text>
          </>
        )}
      </Text>
    </Stack>
  )
}