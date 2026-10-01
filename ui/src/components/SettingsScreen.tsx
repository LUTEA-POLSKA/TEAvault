/**
 * Settings, backup and restore.
 *
 * Settings are validated by the core before they are applied, and a rejected
 * change leaves the old values in place — this screen never assumes a save
 * worked without asking.
 *
 * The clipboard timeout is presented with its consequence spelled out, because
 * "0 seconds" reads like a performance setting and is actually a decision to
 * leave API keys on the clipboard indefinitely.
 */

import { useCallback, useEffect, useState } from 'react'

import { PageHeader } from '@tea-ui/admin'
import { open, save } from '@tauri-apps/plugin-dialog'
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
  CardTitle,
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  NumberInput,
  PasswordInput,
  Stack,
  Switch,
  Text,
  VStack,
  toast,
} from '@tea-ui/core'

import { api, ImportReport, Settings, VaultError } from '../api'

export function SettingsScreen({
  onError,
  onSaved,
}: {
  onError: (e: unknown) => void
  onSaved: () => Promise<void>
}) {
  const [settings, setSettings] = useState<Settings | null>(null)
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      setSettings(await api.getSettings())
    } catch (e) {
      onError(e)
    }
  }, [onError])

  useEffect(() => {
    void load()
  }, [load])

  if (!settings) {
    return <Text size="body" tone="muted">Loading…</Text>
  }

  const autoLockSeconds =
    settings.auto_lock.mode === 'after_seconds' ? settings.auto_lock.after_seconds : null

  async function apply(next: Settings) {
    setBusy(true)
    setProblem(null)
    try {
      setSettings(await api.setSettings(next))
      toast({ title: 'Settings saved', tone: 'positive' })
      await onSaved()
    } catch (e) {
      if (e instanceof VaultError) setProblem(e.message)
      else onError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <VStack gap="section">
      <PageHeader title="Settings" description="None of these can weaken the encryption." />

      {problem && (
        <Alert tone="caution" role="alert">
          <AlertTitle>Not applied</AlertTitle>
          <AlertDescription>{problem}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle level={2}>Locking</CardTitle>
          <CardDescription>
            The vault always locks on sign-out, on quit, and on every start. These settings add a
            timer on top.
          </CardDescription>
        </CardHeader>
        <CardBody>
          <Stack gap="section">
            <Field>
              <Switch
                checked={autoLockSeconds === null}
                onCheckedChange={(never) =>
                  apply({
                    ...settings!,
                    auto_lock: never ? { mode: 'never' } : { mode: 'after_seconds', after_seconds: 300 },
                  })
                }
                label="Never lock automatically"
              />
              <FieldDescription>
                Manual locking, sign-out and quit still work. Turning this off does not make the
                vault stay unlocked across a restart — nothing does.
              </FieldDescription>
            </Field>

            {autoLockSeconds !== null && (
              <Field>
                <FieldLabel>Lock after (seconds)</FieldLabel>
                <NumberInput
                  value={autoLockSeconds}
                  onValueChange={(v) =>
                    setSettings({ ...settings, auto_lock: { mode: 'after_seconds', after_seconds: Number(v) } })
                  }
                  min={10}
                  max={86400}
                />
                <FieldDescription>At least 10 seconds. Below that the vault locks faster than a person can react.</FieldDescription>
              </Field>
            )}

            {autoLockSeconds !== null && (
              <div>
                <Button
                  variant="primary"
                  size="sm"
                  loading={busy}
                  onClick={() => void apply(settings!)}
                >
                  Apply locking settings
                </Button>
              </div>
            )}
          </Stack>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle level={2}>Clipboard</CardTitle>
        </CardHeader>
        <CardBody>
          <Field>
            <FieldLabel>Clear a copied key after (seconds)</FieldLabel>
            <NumberInput
              value={settings.clipboard_clear_seconds}
              onValueChange={(v) => setSettings({ ...settings, clipboard_clear_seconds: Number(v) })}
              min={0}
              max={3600}
            />
            <FieldDescription>
              Zero means the clipboard is never cleared. Clearing only happens if the clipboard
              still holds what TEAvault put there — a password you copied from another program in
              the meantime is never overwritten.
            </FieldDescription>
          </Field>
        </CardBody>
        <CardFooter>
          <Stack gap="ui">
            <Button
              variant="primary"
              size="sm"
              loading={busy}
              onClick={() => void apply(settings!)}
            >
              Apply clipboard settings
            </Button>
            {settings.clipboard_clear_seconds === 0 && (
              <Callout tone="caution" title="Keys will stay on the clipboard">
                Any program can read the clipboard, and Windows clipboard history may keep a copy
                after it is cleared.
              </Callout>
            )}
          </Stack>
        </CardFooter>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle level={2}>Behaviour</CardTitle>
        </CardHeader>
        <CardBody>
          <FieldGroup legend="General">
            <Field>
              <Switch
                checked={settings.close_window_hides}
                onCheckedChange={(v) => void apply({ ...settings, close_window_hides: v })}
                label="Closing the window hides it instead of quitting"
              />
              <FieldDescription>
                The background process and tray stay available, which is what makes the UI cheap to
                open and close.
              </FieldDescription>
            </Field>
            <Field>
              <Switch
                checked={settings.autostart}
                onCheckedChange={(v) => void apply({ ...settings, autostart: v })}
                label="Start with Windows"
              />
              <FieldDescription>
                Starts locked. TEAvault never unlocks itself at login.
              </FieldDescription>
            </Field>
          </FieldGroup>
        </CardBody>
      </Card>

      <BackupCard onError={onError} onSaved={onSaved} />
    </VStack>
  )
}

function BackupCard({
  onError,
  onSaved,
}: {
  onError: (e: unknown) => void
  onSaved: () => Promise<void>
}) {
  const [passphrase, setPassphrase] = useState('')
  const [overwrite, setOverwrite] = useState(false)
  const [busy, setBusy] = useState(false)
  const [report, setReport] = useState<ImportReport | null>(null)

  async function exportBackup() {
    const path = await save({
      title: 'Save encrypted backup',
      defaultPath: 'teavault-backup.teavault',
      filters: [{ name: 'TEAvault backup', extensions: ['teavault'] }],
    })
    if (!path) return
    if (!passphrase) {
      onError(new VaultError({ code: 'invalid', message: 'A passphrase is required to seal the backup.', retryable: false }))
      return
    }
    setBusy(true)
    try {
      await api.backupExport(path, passphrase)
      setPassphrase('')
      toast({ title: 'Encrypted backup written', description: path, tone: 'positive' })
    } catch (e) {
      onError(e)
    } finally {
      setBusy(false)
    }
  }

  async function importBackup() {
    const path = await open({
      title: 'Open encrypted backup',
      multiple: false,
      filters: [{ name: 'TEAvault backup', extensions: ['teavault'] }],
    })
    if (typeof path !== 'string') return
    if (!passphrase) {
      onError(new VaultError({ code: 'invalid', message: 'A passphrase is required to open the backup.', retryable: false }))
      return
    }
    setBusy(true)
    try {
      const r = await api.backupImport(path, passphrase, overwrite)
      setReport(r)
      setPassphrase('')
      await onSaved()
    } catch (e) {
      onError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle level={2}>Backup and restore</CardTitle>
        <CardDescription>
          Backups are always encrypted, and always need the passphrase to open. There is no
          plaintext export.
        </CardDescription>
      </CardHeader>
      <CardBody>
        <Stack gap="section">
          <Field>
            <FieldLabel>Backup passphrase</FieldLabel>
            <PasswordInput
              autoComplete="off"
              value={passphrase}
              onValueChange={setPassphrase}
              placeholder="Passphrase for the backup file"
            />
            <FieldDescription>
              This seals the backup file. It is separate from your master passphrase, so a leaked
              backup is not a leaked vault.
            </FieldDescription>
          </Field>

          <Field>
            <Switch
              checked={overwrite}
              onCheckedChange={setOverwrite}
              label="Replace existing keys when importing"
            />
            <FieldDescription>
              Off by default: an import that finds a key you already have keeps yours and skips
              the incoming one.
            </FieldDescription>
          </Field>

          {report && (
            <Alert tone="info" role="status">
              <AlertTitle>Import finished</AlertTitle>
              <AlertDescription>
                {report.added} added, {report.replaced} replaced, {report.skipped} skipped because
                you already had them, {report.grants} permissions carried over.
              </AlertDescription>
            </Alert>
          )}
        </Stack>
      </CardBody>
      <CardFooter>
        <Stack direction="horizontal" gap="ui">
          <Button variant="primary" loading={busy} onClick={() => void exportBackup()}>
            Export encrypted backup
          </Button>
          <Button variant="outline" loading={busy} onClick={() => void importBackup()}>
            Import backup
          </Button>
        </Stack>
      </CardFooter>
    </Card>
  )
}