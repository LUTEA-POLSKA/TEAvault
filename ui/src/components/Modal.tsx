/**
 * A modal form.
 *
 * Built from TEAui's `Dialog` parts rather than from a single convenience
 * component, because `AlertDialog` is a thin re-export of Radix's *alert*
 * dialog — it has no `title`, no `description` and no `onCancel`, so passing them
 * is a type error rather than a silent no-op. Using it as a generic modal is
 * exactly the kind of invented API this project is not allowed to have.
 *
 * The parts are assembled here so that every modal in TEAvault has the same
 * structure, the same width and the same focus behaviour, and so that fixing one
 * fixes all of them.
 */

import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@tea-ui/core'
import type { ReactNode } from 'react'

export function Modal({
  open,
  title,
  description,
  onClose,
  children,
  footer,
  size = 'md',
}: {
  open: boolean
  title: string
  description?: string
  onClose: () => void
  children: ReactNode
  footer: ReactNode
  size?: 'sm' | 'md' | 'lg' | 'xl'
}) {
  if (!open) return null
  return (
    <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
      <DialogContent size={size} showCloseButton closeLabel="Close">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        <DialogBody>{children}</DialogBody>
        <DialogFooter>{footer}</DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
