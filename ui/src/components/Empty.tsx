/**
 * "There is nothing here yet", with the one action that would change that.
 *
 * TEAui exports `EmptyState` from `@tea-ui/admin`, not from `@tea-ui/core`. It is
 * twelve lines of markup, and taking it from the admin package would pull a
 * whole application shell into a component that only needs a paragraph — so it
 * lives here instead.
 */
import { Stack, Text } from '@tea-ui/core'

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string
  description: string
  action?: React.ReactNode
}) {
  return (
    <Stack gap="xs" align="center" style={{ padding: '20px 12px', textAlign: 'center' }}>
      <Text size="ui" weight="semibold">
        {title}
      </Text>
      <Text size="ui" tone="muted" style={{ maxWidth: '380px' }}>
        {description}
      </Text>
      {action}
    </Stack>
  )
}

/** `CardTitle` in TEAui 1.0 requires a heading `level`; this is the common case. */
export function CardTitle({ children }: { children: React.ReactNode }) {
  return (
    <Text size="ui" weight="semibold" asChild={false}>
      <span role="heading" aria-level={2}>{children}</span>
    </Text>
  )
}