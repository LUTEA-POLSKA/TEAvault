/**
 * A labelled password field that works correctly with TEAui's `PasswordInput`.
 *
 * The generic `LabelledField` uses `cloneElement` to hand the control its
 * generated `id` and `aria-*` props. `PasswordInput` is a complex component
 * with internal state (`useControllableState`) that renders its own
 * `InputGroup` + `IconButton` for the eye toggle.
 *
 * Cloning it causes React to mismanage the internal toggle, so the eye icon
 * appears twice when typing. This component does the wiring itself — no
 * cloning needed — and always uses a large size for comfortable typing of
 * long passphrases.
 */

import { type ReactNode } from 'react'
import {
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
  PasswordInput,
  useFieldControlProps,
} from '@tea-ui/core'

export function PasswordField({
  label,
  description,
  error,
  required,
  value,
  onValueChange,
  autoComplete,
  autoFocus,
  className,
}: {
  label: string
  description?: ReactNode
  error?: string
  required?: boolean
  value: string
  onValueChange: (v: string) => void
  autoComplete?: string
  autoFocus?: boolean
  className?: string
}) {
  const control = useFieldControlProps()

  return (
    <Field invalid={Boolean(error)} required={required}>
      <FieldLabel>{label}</FieldLabel>
      <PasswordInput
        {...control}
        className={className}
        size="lg"
        value={value}
        onValueChange={onValueChange}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        aria-invalid={error ? true : undefined}
      />
      {description && <FieldDescription>{description}</FieldDescription>}
      {error && <FieldError>{error}</FieldError>}
    </Field>
  )
}