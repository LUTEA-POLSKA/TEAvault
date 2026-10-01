/**
 * Create or edit an entry.
 *
 * The secret field uses `PasswordInput`, so the value is masked by default even
 * while typing — a screen share of this dialog does not show the key.
 *
 * On edit, the secret field is left empty and only sent when the user types
 * something, so editing a description cannot silently overwrite a stored key.
 */

import { useState } from 'react'

import {
  Button,
  Checkbox,
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
  Input,
  PasswordInput,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Stack,
  Textarea,
  toast,
} from '@tea-ui/core'

import { api, ListEntry, PROVIDERS, SUGGESTED_CAPABILITIES, VaultError } from '../api'

export function EntryDialog({
  mode,
  entry,
  onClose,
  onSaved,
  onError,
}: {
  mode: 'create' | 'edit'
  entry: ListEntry | null
  onClose: () => void
  onSaved: () => Promise<void>
  onError: (e: unknown) => void
}) {
  const [name, setName] = useState(entry?.name ?? '')
  const [displayName, setDisplayName] = useState(entry?.display_name ?? '')
  const [provider, setProvider] = useState(entry?.provider ?? 'OpenAI')
  const [description, setDescription] = useState(entry?.description ?? '')
  const [capabilities, setCapabilities] = useState<string[]>(entry?.capabilities ?? [])
  const [hidden, setHidden] = useState(entry?.hidden ?? false)
  const [secret, setSecret] = useState('')
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<string | null>(null)

  function toggleCapability(c: string) {
    setCapabilities((prev) => (prev.includes(c) ? prev.filter((x) => x !== c) : [...prev, c]))
  }

  async function save() {
    setBusy(true)
    setProblem(null)
    try {
      if (mode === 'create') {
        if (!secret) {
          setProblem('A key value is required.')
          return
        }
        await api.createEntry({
          name,
          displayName,
          provider,
          description: description || undefined,
          capabilities,
          hidden,
          secret,
        })
        toast({ title: `${name} added`, tone: 'positive' })
      } else {
        if (!entry) return
        await api.updateEntry({
          entry: entry.id,
          displayName,
          provider,
          description: description || undefined,
          capabilities,
          hidden,
          // Only sent when typed, so editing a description cannot wipe the key.
          secret: secret || undefined,
        })
        toast({ title: `${name} updated`, tone: 'positive' })
      }
      setSecret('')
      onClose()
      await onSaved()
    } catch (e) {
      if (e instanceof VaultError) setProblem(e.message)
      else onError(e)
    } finally {
      setBusy(false)
    }
  }

  const suggestions = SUGGESTED_CAPABILITIES[provider] ?? []

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent size="lg" closeLabel="Cancel">
        <DialogHeader>
          <DialogTitle>{mode === 'create' ? 'Add an API key' : `Edit ${entry?.name}`}</DialogTitle>
          <DialogDescription>
            Provider and capability labels are your own description of the key. TEAvault never
            contacts a provider to check it, because that would send the secret somewhere it does
            not control.
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          <Stack gap="section">
            <Field required invalid={!!problem}>
              <FieldLabel>Variable name</FieldLabel>
              <Input
                value={name}
                onChange={(e) => setName(e.currentTarget.value)}
                placeholder="OPENAI_API_KEY"
                disabled={mode === 'edit'}
                autoComplete="off"
                spellCheck={false}
              />
              <FieldDescription>
                Uppercase letters, digits and underscores, like an environment variable.
              </FieldDescription>
              <FieldError>{problem}</FieldError>
            </Field>

            <Field required>
              <FieldLabel>Display name</FieldLabel>
              <Input
                value={displayName}
                onChange={(e) => setDisplayName(e.currentTarget.value)}
                placeholder="OpenAI — production"
              />
            </Field>

            <Field>
              <FieldLabel>Provider</FieldLabel>
              <Select value={provider} onValueChange={(v) => setProvider(v)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PROVIDERS.map((p) => (
                    <SelectItem key={p} value={p}>
                      {p}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>

            <Field>
              <FieldLabel>Description</FieldLabel>
              <Textarea
                rows={3}
                value={description}
                onChange={(e) => setDescription(e.currentTarget.value)}
                placeholder="What this key is for, and anything a future reader should know."
              />
            </Field>

            <Field>
              <FieldLabel>Capabilities</FieldLabel>
              <Stack direction="horizontal" gap="none">
                {[...new Set([...suggestions, ...capabilities])].map((c) => (
                  <Checkbox
                    key={c}
                    checked={capabilities.includes(c)}
                    onCheckedChange={() => toggleCapability(c)}
                    label={c}
                  />
                ))}
              </Stack>
              <FieldDescription>Free-form tags. They describe the key; they do not restrict it.</FieldDescription>
            </Field>

            <Field>
              <Checkbox
                checked={hidden}
                onCheckedChange={setHidden}
                label="Hide until approved"
              />
              <FieldDescription>
                Off: any local client can see that this key exists, though releasing it still needs
                your approval. On: it does not appear in listings at all until you have approved a
                client for it.
              </FieldDescription>
            </Field>

            <Field required={mode === 'create'}>
              <FieldLabel>{mode === 'create' ? 'Key value' : 'Replace key value'}</FieldLabel>
              <PasswordInput
                autoComplete="off"
                value={secret}
                onValueChange={setSecret}
                placeholder={mode === 'create' ? 'Paste the key' : 'Leave empty to keep the current value'}
                spellCheck={false}
              />
              <FieldDescription>
                {mode === 'create'
                  ? 'Stored encrypted. The field is masked so a screen share does not reveal it.'
                  : 'Only sent when you type something, so editing other fields cannot overwrite the key.'}
              </FieldDescription>
            </Field>
          </Stack>
        </DialogBody>

        <DialogFooter>
          <Stack direction="horizontal" gap="ui" justify="end">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button
              variant="primary"
              loading={busy}
              disabled={!name || !displayName || (mode === 'create' && !secret)}
              onClick={() => void save()}
            >
              {mode === 'create' ? 'Add key' : 'Save changes'}
            </Button>
          </Stack>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}