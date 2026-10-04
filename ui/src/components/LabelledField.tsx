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
 * That means `<Field label=… description=…>` — the shape the old UI used — does
 * not exist. Composing the parts by hand in every form would put the wiring at
 * the mercy of whoever wrote the form next, so it is composed once here, from the
 * real components, and the control is cloned with the real props.
 *
 * Nothing is reimplemented: every element below is TEAui's.
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
