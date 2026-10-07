/**
 * Creating the vault.
 *
 * This is the first thing anyone sees, so it has one job: get a passphrase chosen
 * that the user will still know later. The warning about there being no recovery
 * is therefore the largest element on the screen, not a footnote — it is the
 * single fact that makes this decision consequential, and burying it under a
 * form would be the worst possible place for it.
 *
 * Length is checked as the user types, and the button stays disabled until the
 * requirement is met, so the failure mode is never a rejected submit with a
 * message that has to be read after the fact.
 */

import { useState } from 'react'
import {
  Alert,
  Button,
  Callout,
  Card,
  CardBody,
  HStack,
  Stack,
  Text,
} from '@tea-ui/core'
import { PasswordField } from './PasswordField'

export function SetupScreen({
  onCreated,
}: {
  onCreated: (passphrase: string) => Promise<void>
}) {
  const [pass, setPass] = useState('')
  const [repeat, setRepeat] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const MIN = 12
  const longEnough = pass.length >= MIN
  const matches = pass.length > 0 && pass === repeat

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!longEnough || !matches) return
    setBusy(true)
    setError(null)
    try {
      await onCreated(pass)
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
      <Card style={{ width: '100%', maxWidth: '520px' }}>
        <CardBody>
          <form onSubmit={submit}>
            <Stack gap="ui">
              <Text size="label" weight="semibold">
                Create your vault
              </Text>

              {/*
                The one fact that cannot be discovered later, so it is a callout
                rather than a footnote. But it is a callout, not an essay: the
                sentence says what is true and stops.
              */}
              <Callout tone="critical" title="There is no way to recover this">
                <Text size="ui">
                  If you lose the passphrase, the keys are gone. Write it down first.
                </Text>
              </Callout>

              {error && (
                <Alert tone="critical" role="alert">
                  {error}
                </Alert>
              )}

              <PasswordField
                label="Master passphrase"
                description={`At least ${MIN} characters. A sentence beats a short string.`}
                error={pass.length > 0 && !longEnough ? `At least ${MIN} characters.` : undefined}
                value={pass}
                onValueChange={setPass}
                autoFocus
                autoComplete="new-password"
                className="w-full"
              />

              <PasswordField
                label="Repeat it"
                error={repeat.length > 0 && !matches ? 'The two do not match.' : undefined}
                value={repeat}
                onValueChange={setRepeat}
                autoComplete="new-password"
                className="w-full"
              />

              <HStack align="center" justify="end" gap="ui">
                <Text size="ui" tone="subtle">
                  {pass.length} / {MIN}
                </Text>
                <Button
                  type="submit"
                  variant="primary"
                  size="sm"
                  loading={busy}
                  disabled={!longEnough || !matches}
                >
                  Create the vault
                </Button>
              </HStack>
            </Stack>
          </form>
        </CardBody>
      </Card>
    </div>
  )
}
