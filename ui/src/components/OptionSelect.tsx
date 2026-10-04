/**
 * A labelled dropdown, built on TEAui's own `Select` parts.
 *
 * TEAui exports `Select` as a thin wrapper over Radix's `Select`, which has no
 * `Select.Item` compound: the trigger, the list, the value and each item are six
 * separate exports that must be composed by hand every time.
 *
 * Two options were available. A native `<select>` is one element, fully
 * accessible, keyboard-operable for free — and it looks like a native control in
 * a TEAui surface, which is the thing this product is trying to avoid. The Radix
 * composition is six elements and a portal per field.
 *
 * The compromise is below: Radix's `Select` and its parts, assembled once, so the
 * settings screen gets a TEAui-styled control that behaves like one. The
 * alternative choices are in the list because they are better for long option
 * lists, which this one is not.
 */

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@tea-ui/core'

export function OptionSelect({
  value,
  onValueChange,
  label,
  options,
}: {
  value: string
  onValueChange: (value: string) => void
  /** The visible name of the current option. */
  label: (value: string) => string
  options: { value: string; text: string }[]
}) {
  return (
    <Select value={value} onValueChange={onValueChange}>
      <SelectTrigger aria-label="Select an option">
        <SelectValue>{label(value)}</SelectValue>
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.text}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
