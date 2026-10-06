/**
 * Create or change a key.
 *
 * ## The secret is a textarea, not a password field
 *
 * API keys are long, contain no asterisks to suggest length, and are pasted from
 * a provider's dashboard. A single-line password input hides what was pasted and
 * makes a truncated paste undetectable. The field is a clear textarea — this is
 * the owner typing their own key into their own vault, and obscuring it helps
 * nobody. Nothing reaches another program until a grant says so.
 *
 * ## The variable name comes first
 *
 * It is the identifier: the display name, provider and note are annotations on it.
 * Leading with the annotations buries the one field the user has to get exactly
 * right, and it is the field every program will refer to.
 *
 * ## Every control is TEAui's
 *
 * The first version of this dialog hand-styled raw `<input>` elements against
 * guessed CSS variables (`--tea-color-line`, which TEAui 1.0 does not define).
 * The result was an invisible field — no border, no background, and no error
 * until someone looked at the computed style. TEAui's own `Input` carries the
 * correct classes, so the styling is not a thing this file has to get right.
 */

import { useMemo, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  CardBody,
  HStack,
  Input,
  Stack,
  Switch,
  Text,
  Textarea,
} from '@tea-ui/core'
import type { ListEntry } from '../api'
import { suggestCategory } from '../utils/category'
import { LabelledField } from './LabelledField'
import { Modal } from './Modal'

const INPUT_CLASS = 'w-full'

export function EntryDialog({
  entry,
  providers,
  categories,
  onClose,
  onSave,
  onError,
}: {
  entry: ListEntry | null
  providers: string[]
  categories: string[]
  onClose: () => void
  onSave: (input: EntryInput) => Promise<void>
  onError: (e: unknown) => void
}) {
  const [name, setName] = useState(entry?.name ?? '')
  const [displayName, setDisplayName] = useState(entry?.display_name ?? '')
  const [provider, setProvider] = useState(entry?.provider ?? (providers[0] ?? 'OpenAI'))
  const [description, setDescription] = useState(entry?.description ?? '')
  const [secret, setSecret] = useState('')
  const [hidden, setHidden] = useState(entry?.hidden ?? false)
  const [category, setCategory] = useState(entry?.category ?? '')
  const [capabilities, setCapabilities] = useState('')
  const [busy, setBusy] = useState(false)
  const [localError, setLocalError] = useState<string | null>(null)

  const editing = entry !== null
  const nameValid = /^[A-Za-z_][A-Za-z0-9_]*$/.test(name)

  // Advisory only: shown when the category is empty and the name suggests one.
  // Applying it just fills the field; it never overrides a manual choice.
  const suggested = useMemo(() => {
    if (category.trim() !== '') return null
    return suggestCategory(name || (entry?.name ?? ''))
  }, [category, name, entry?.name])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!nameValid) {
      setLocalError(
        'The variable name may contain letters, digits and underscores, and must not start with a digit.',
      )
      return
    }
    if (!editing && secret.trim() === '') {
      setLocalError('A key needs a value.')
      return
    }
    setBusy(true)
    setLocalError(null)
    try {
      await onSave({
        id: entry?.id ?? null,
        name,
        display_name: displayName.trim() || name,
        provider: provider.trim(),
        description: description.trim() || null,
        hidden,
        secret: secret.trim() || null,
        capabilities: capabilities
          .split(',')
          .map((c) => c.trim())
          .filter((c) => c.length > 0),
        category: category.trim() || null,
      })
    } catch (err) {
      onError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={editing ? `Edit ${entry!.name}` : 'Add a key'}
      description={
        editing
          ? 'The value stays as it is unless you replace it below.'
          : 'The value is encrypted with your master passphrase before it touches the disk.'
      }
      size="lg"
      footer={
        <>
          <Button type="button" size="sm" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" size="sm" variant="primary" loading={busy} form="entry-form">
            {editing ? 'Save changes' : 'Add key'}
          </Button>
        </>
      }
    >
      <form id="entry-form" onSubmit={submit}>
        <Stack gap="ui">
          {localError && <Alert tone="critical" role="alert">{localError}</Alert>}

          <LabelledField
            label="Variable name"
            description="Uppercase, digits and underscores. This is how a program will refer to it."
            required
          >
            <Input
              className={`${INPUT_CLASS} font-mono`}
              value={name}
              onChange={(e) => setName(e.target.value.toUpperCase())}
              disabled={editing}
              autoFocus
              required
              placeholder="OPENAI_API_KEY"
            />
          </LabelledField>

          <div className="grid grid-cols-2 gap-3">
            <LabelledField label="Label" description="Optional, for you.">
              <Input
                className={INPUT_CLASS}
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Personal key"
              />
            </LabelledField>

            <LabelledField
              label="Provider"
              description={
                // Free text rather than a fixed list: providers are not an enum,
                // and a closed dropdown would refuse to store a key for a
                // service nobody thought of.
                `Suggestions: ${providers.slice(0, 3).join(', ')}`
              }
            >
              <Input
                className={INPUT_CLASS}
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
                list="teavault-providers"
              />
            </LabelledField>
            {/* Suggestions for the provider field, kept out of the field itself. */}
            <datalist id="teavault-providers">
              {providers.map((p) => (
                <option key={p} value={p} />
              ))}
            </datalist>
          </div>

          <LabelledField
            label="Note"
            description="Optional. Shown next to the key, never sent anywhere."
          >
            <Input
              className={INPUT_CLASS}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="What it is for"
            />
          </LabelledField>

          <div>
            {category.trim() === '' && suggested && (
              <HStack gap="ui" align="center" className="mb-1" aria-live="polite">
                <Text size="ui" tone="subtle">
                  Suggested from the name: {suggested}
                </Text>
                <Button
                  size="sm"
                  variant="ghost"
                  type="button"
                  onClick={() => setCategory(suggested)}
                >
                  Apply
                </Button>
              </HStack>
            )}
            <LabelledField
              label="Category"
              description="Optional. Groups keys on the list, e.g. llm, ci. Free text — you can type your own."
            >
              <Input
                className={INPUT_CLASS}
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                list="teavault-categories"
                placeholder="llm"
              />
            </LabelledField>
            {/* Existing categories, so the user picks rather than retypes. */}
            <datalist id="teavault-categories">
              {categories.map((c) => (
                <option key={c} value={c} />
              ))}
            </datalist>
          </div>

          <LabelledField
            label={editing ? 'Replace the value' : 'Key value'}
            description={
              editing
                ? 'Leave empty to keep the current value. Filling this in overwrites it, and the old value cannot be recovered.'
                : 'Pasted from the provider. Stored encrypted; never shown in full again once you leave this dialog.'
            }
            required={!editing}
          >
            <Textarea
              className={`${INPUT_CLASS} font-mono text-xs`}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              rows={2}
              required={!editing}
            />
          </LabelledField>

          <LabelledField
            label="Capabilities"
            description="What this key can do. Comma-separated, e.g. llm, embeddings."
          >
            <Input
              className={INPUT_CLASS}
              value={capabilities}
              onChange={(e) => setCapabilities(e.target.value)}
              placeholder="llm, embeddings"
            />
          </LabelledField>

          <div>
            <Switch checked={hidden} onCheckedChange={setHidden} label="Hidden until approved" />
            <Text size="ui" tone="subtle" className="block">
              A hidden key is not listed to any program. It appears only after you approve a
              request for it.
            </Text>
          </div>
        </Stack>
      </form>
    </Modal>
  )
}

export interface EntryInput {
  id: string | null
  name: string
  display_name: string
  provider: string
  description: string | null
  hidden: boolean
  secret: string | null
  capabilities: string[]
  category?: string | null
}

/** The note shown after a copy, with the countdown the user asked about. */
export function CopiedNote({ masked, clearedIn }: { masked: string; clearedIn: number | null }) {
  return (
    <Card>
      <CardBody>
        <HStack align="center" justify="between" gap="ui">
          <Text size="ui">
            Copied <code>{masked}</code> to the clipboard.
          </Text>
          {clearedIn !== null && (
            <Text size="ui" tone="subtle">
              clears in {clearedIn}s
            </Text>
          )}
        </HStack>
      </CardBody>
    </Card>
  )
}