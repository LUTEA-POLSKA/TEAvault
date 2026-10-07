/**
 * A labelled form control, wired the way TEAui intends.
 *
 * TEAui 1.0 splits a field into `Field` (the container and its state),
 * `FieldLabel`, `FieldDescription`, `FieldError`, and a `useFieldControlProps`
 * hook that hands the control its generated `id` and the `aria-describedby` /
 * `aria-labelledby` references. The audit note in TEAui's own source is explicit
 * that a `description`/`error` element is only linked once it is actually on
 * screen, because a dangling `aria-describedby` is a validation error and is
 * silently dropped by some screen readers.
 *
 * This component composes those parts, cloning the child with the generated
 * props so every control gets wired to its label and any description or error
 * text. It works with `Input`, `Select`, `OptionSelect`, etc. — anything that
 * accepts `aria-*` and `id` props.
 *
 * For `PasswordInput` use `PasswordField` instead: cloning a password input
 * corrupts its internal toggle button and causes two eye icons to render.
 *
 * Nothing here is reimplemented: every element is TEAui's own component.
 */

import { cloneElement, type ReactElement, type ReactNode } from 'react'
import {
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
  useFieldControlProps,
} from '@tea-ui/core'

export function LabelledField({
  label,
  description,
  error,
  required,
  children,
}: {
  label: string
  description?: ReactNode
  error?: string
  required?: boolean
  /** The single control this field wraps. */
  children: ReactElement
}) {
  const control = useFieldControlProps()

  return (
    <Field invalid={Boolean(error)} required={required}>
      <FieldLabel>{label}</FieldLabel>
      {cloneElement(children, {
        ...control,
        'aria-invalid': error ? true : undefined,
      })}
      {description && <FieldDescription>{description}</FieldDescription>}
      {error && <FieldError>{error}</FieldError>}
    </Field>
  )
}
