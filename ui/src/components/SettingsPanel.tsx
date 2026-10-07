/**
 * Settings, the passphrase, and backups.
 *
 * ## What is here and what is not
 *
 * Only settings the code actually acts on. The previous version offered "Start
 * with Windows" and a periodic-backup interval, both of which no code anywhere
 * read — a switch that does nothing is worse than a missing one, because the user
 * reasonably believes their choice was applied. A test in `settings.rs` now fails
 * if a field is added without an implementation.
 *
 * ## Destructive things live together and are marked
 *
 * Changing the passphrase and restoring a backup are the two irreversible
 * operations in the product. They sit at the bottom, in their own cards, with a
 * description that states the consequence before the button rather than after.
 */

import { useState } from 'react'
import {
  Alert,
  Button,
  Callout,
  Card,
  CardBody,
  CardDescription,
  CardHeader,
  HStack,
  Input,
  Stack,
  Switch,
  Text,
} from '@tea-ui/core'
import type { Settings } from '../api'
import { CardTitle } from './Empty'
import { LabelledField } from './LabelledField'
import { OptionSelect } from './OptionSelect'
import { PasswordField } from './PasswordField'

const CLIPBOARD_CHOICES = [
  { value: '0', label: 'Never' },
  { value: '15', label: '15 seconds' },
  { value: '30', label: '30 seconds' },
  { value: '60', label: '1 minute' },
  { value: '300', label: '5 minutes' },
]

export function SettingsPanel({
  settings,
  onSave,
  onChangePassphrase,
  onBackup,
  onRestore,
}: {
  settings: Settings
  onSave: (s: Settings) => Promise<void>
  onChangePassphrase: (current: string, next: string) => Promise<void>
  onBackup: (file: string, passphrase: string) => Promise<void>
  onRestore: (file: string, passphrase: string, overwrite: boolean) => Promise<void>
}) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<string | null>(null)

  async function run(label: string, f: () => Promise<void>) {
    setBusy(true)
    setError(null)
    setDone(null)
    try {
      await f()
      setDone(label)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Stack gap="ui" style={{ padding: '12px 16px', minHeight: 0, overflowY: 'auto' }}>
      {error && (
        <Alert tone="critical" role="alert">
          {error}
        </Alert>
      )}
      {done && (
        <Alert tone="positive" role="status">
          {done}
        </Alert>
      )}

      <Card>
        <CardHeader>
<CardTitle>Clipboard</CardTitle>
          <CardDescription>
            How long a copied key stays on the clipboard. Clearing is conditional: TEAvault only
            wipes the clipboard if it still holds the value it put there, so copying something else
            in the meantime is safe.
          </CardDescription>
        </CardHeader>
        <CardBody>
          <Stack gap="ui">
            <LabelledField
              label="Clear the clipboard after"
              description="How long a copied key stays on the clipboard. `Never` leaves it there until you copy something else."
            >
              <div>
                <OptionSelect
                  value={String(settings.clipboard_clear_seconds)}
                  onValueChange={(v) =>
                    void onSave({ ...settings, clipboard_clear_seconds: Number(v) })
                  }
                  label={(v) =>
                    CLIPBOARD_CHOICES.find((c) => c.value === v)?.label ?? 'Never'
                  }
                  options={CLIPBOARD_CHOICES}
                />
              </div>
            </LabelledField>
          </Stack>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Master passphrase</CardTitle>
          <CardDescription>
            Changing it re-wraps the key that protects your keys. Nothing is re-encrypted, so your
            keys are never briefly unprotected, and the change takes effect immediately.
          </CardDescription>
        </CardHeader>
        <CardBody>
          <Stack gap="ui">
            <PasswordField
              label="Current passphrase"
              value={current}
              onValueChange={setCurrent}
              autoComplete="current-password"
              className="w-full"
            />
            <PasswordField
              label="New passphrase"
              description={`At least ${settings.min_passphrase_chars} characters.`}
              value={next}
              onValueChange={setNext}
              autoComplete="new-password"
              className="w-full"
            />
            <HStack justify="end">
              <Button
                size="sm"
                variant="secondary"
                loading={busy}
                disabled={!current || next.length < settings.min_passphrase_chars}
                onClick={() =>
                  void run('The master passphrase was changed.', async () => {
                    await onChangePassphrase(current, next)
                    setCurrent('')
                    setNext('')
                  })
                }
              >
                Change passphrase
              </Button>
            </HStack>
          </Stack>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Backup</CardTitle>
          <CardDescription>
            A backup is encrypted under its own passphrase. It is never a plaintext copy, and it
            cannot be opened without that passphrase.
          </CardDescription>
</CardHeader>
        <CardBody>
          <Stack gap="ui">
            <ExportBlock busy={busy} onBackup={onBackup} />
            <RestoreBlock busy={busy} onRestore={onRestore} />
          </Stack>
        </CardBody>
      </Card>

      <Callout tone="caution" title="What TEAvault does not protect against">
        <Text size="ui">
          Anything already running as you can read this window, and anything running as you can wait
          for you to approve a request. TEAvault gates each program separately and records every
          decision — but it is not a defence against malware on your own account.
        </Text>
      </Callout>
    </Stack>
  )
}

function ExportBlock({
  busy,
  onBackup,
}: {
  busy: boolean
  onBackup: (file: string, passphrase: string) => Promise<void>
}) {
  const [file, setFile] = useState('')
  const [passphrase, setPassphrase] = useState('')

  return (
    <Stack gap="ui">
      <Text size="ui" tone="muted">
        The backup gets its own passphrase, not the vault one. Lose it and the file cannot be
        opened, so keep it somewhere separate.
      </Text>
      <LabelledField label="Backup file">
        <Input
          value={file}
          onChange={(e) => setFile(e.target.value)}
          placeholder="C:\backups\teavault.teavault"
          className="w-full font-mono"
        />
      </LabelledField>
      <PasswordField
              label="Backup passphrase"
              value={passphrase}
              onValueChange={setPassphrase}
              autoComplete="off"
              className="w-full"
            />
      <HStack justify="end">
        <Button
          size="sm"
          variant="secondary"
          loading={busy}
          disabled={!file || passphrase.length < 8}
          onClick={() => void onBackup(file, passphrase)}
        >
          Write a backup
        </Button>
      </HStack>
    </Stack>
  )
}

function RestoreBlock({
  busy,
  onRestore,
}: {
  busy: boolean
  onRestore: (file: string, passphrase: string, overwrite: boolean) => Promise<void>
}) {
  const [file, setFile] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [overwrite, setOverwrite] = useState(false)

  return (
    <Stack gap="ui">
      <Text size="ui" tone="muted">
        The backup is checked in full before anything is written, so a wrong passphrase or a
        damaged file cannot leave a half-restored vault.
      </Text>
      <LabelledField label="Backup file">
        <Input
          value={file}
          onChange={(e) => setFile(e.target.value)}
          placeholder="C:\backups\teavault.teavault"
          className="w-full font-mono"
        />
      </LabelledField>
      <PasswordField
        label="Backup passphrase"
        value={passphrase}
        onValueChange={setPassphrase}
        autoComplete="off"
        className="w-full"
      />
      <div>
        <Switch
          checked={overwrite}
          onCheckedChange={setOverwrite}
          label="Replace keys that already exist"
        />
        <Text size="ui" tone="subtle" style={{ display: 'block', marginTop: '2px' }}>
          Off by default. With it off, a key that already exists is kept and the incoming one is
          skipped, so restoring cannot quietly replace something you have since changed.
        </Text>
      </div>
      <HStack justify="end">
        <Button
          size="sm"
          variant="secondary"
          loading={busy}
          disabled={!file || !passphrase}
          onClick={() => void onRestore(file, passphrase, overwrite)}
        >
          Restore
        </Button>
      </HStack>
    </Stack>
  )
}
