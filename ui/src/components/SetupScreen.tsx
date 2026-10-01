/**
 * First-run setup: create the vault, from inside the app.
 *
 * Setup living outside the product is a setup step most people never do, so
 * creating the vault is an ordinary screen rather than a terminal incantation.
 * The CLI still exists — an agent or a script has no UI — but the GUI is now a
 * complete path.
 *
 * This screen says the thing that cannot be said later: **there is no
 * recovery.** It is stated before the field is filled in, not discovered after
 * the passphrase is forgotten, and the button stays disabled until a
 * passphrase has actually been typed twice.
 */

import { useState } from 'react'

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
  Callout,
  Card,
  CardBody,
  CardDescription,
  CardFooter,
  CardHeader,
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
  Heading,
  PasswordInput,
  Stack,
  Text,
} from '@tea-ui/core'

import { api, VaultError } from '../api'

/** Matches the core's minimum, which is the floor that actually matters. */
const MIN_LENGTH = 12

export function SetupScreen({
  onCreated,
  onError,
}: {
  onCreated: () => Promise<void>
  onError: (e: unknown) => void
}) {
  const [passphrase, setPassphrase] = useState('')
  const [repeat, setRepeat] = useState('')
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<string | null>(null)

  const tooShort = passphrase.length > 0 && passphrase.length < MIN_LENGTH
  const mismatch = repeat.length > 0 && repeat !== passphrase
  const ready = passphrase.length >= MIN_LENGTH && repeat === passphrase

  async function create() {
    setBusy(true)
    setProblem(null)
    try {
      await api.init(passphrase)
      setPassphrase('')
      setRepeat('')
      await onCreated()
    } catch (e) {
      if (e instanceof VaultError) setProblem(e.message)
      else onError(e)
    } finally {
      setBusy(false)
    }
  }

return (
    /* Layout only: TEAui's `Container` centres with `margin-inline: auto`, which
       does nothing inside a flex parent that has no explicit width. This is a
       centring wrapper, not a TEAui component reimplemented — the Card, Alert,
       Callout, Field and Button below are all TEAui. */
    <div
      style={{
        flex: 1,
        minHeight: 0,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px',
        overflowY: 'auto',
      }}
    >
      <div style={{ width: '100%', maxWidth: '520px' }}>
        <Stack gap="section">
        <Card>
          <CardHeader>
            <Heading level={2}>Create your vault</Heading>
            <CardDescription>
              One master passphrase protects everything. TEAvault derives a key from it with
              Argon2id and never stores the passphrase itself.
            </CardDescription>
          </CardHeader>

          <CardBody>
            <Stack gap="section">
              <Alert tone="critical" role="alert">
                <AlertTitle>There is no recovery</AlertTitle>
                <AlertDescription>
                  No backdoor, no master key, no reset. If you lose this passphrase the keys are
                  gone — permanently. Store it somewhere safe now, before you add anything to
                  the vault.
                </AlertDescription>
              </Alert>

              {problem && (
                <Alert tone="caution" role="alert">
                  <AlertTitle>Not created</AlertTitle>
                  <AlertDescription>{problem}</AlertDescription>
                </Alert>
              )}

              <form
                onSubmit={(e) => {
                  e.preventDefault()
                  if (ready && !busy) void create()
                }}
              >
                <Stack gap="section">
                  <Field required invalid={tooShort || !!problem}>
                    <FieldLabel>Master passphrase</FieldLabel>
                    <PasswordInput
                      autoComplete="new-password"
                      value={passphrase}
                      onValueChange={setPassphrase}
                      placeholder="At least 12 characters"
                    />
                    <FieldDescription>
                      A sentence you will remember beats a short string you will not. Length is
                      enforced here and again by the core.
                    </FieldDescription>
                    {tooShort && <FieldError>At least {MIN_LENGTH} characters.</FieldError>}
                  </Field>

                  <Field required invalid={mismatch}>
                    <FieldLabel>Repeat it</FieldLabel>
                    <PasswordInput
                      autoComplete="new-password"
                      value={repeat}
                      onValueChange={setRepeat}
                      placeholder="Type it again"
                    />
                    {mismatch && <FieldError>The two do not match.</FieldError>}
                  </Field>

                  <Callout tone="info" title="What this does not protect against">
                    Anyone who can use your Windows account while the vault is unlocked. TEAvault
                    gates every program individually, but it cannot stop something running as you
                    from waiting for you to approve a prompt.
                  </Callout>

                  <Button
                    type="submit"
                    variant="primary"
                    loading={busy}
                    disabled={!ready}
                    size="lg"
                  >
                    Create vault
                  </Button>
                </Stack>
              </form>
            </Stack>
          </CardBody>

          <CardFooter>
            <Text size="ui" tone="muted">
              Prefer the command line? <code>teavault init</code> does the same thing.
            </Text>
          </CardFooter>
        </Card>
      </Stack>
      </div>
    </div>
  )
}