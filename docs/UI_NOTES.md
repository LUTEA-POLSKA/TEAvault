# UI notes

TEAui is the only UI component library in TEAvault. This file records how that
was verified, what is used, and the one gap.

## How the TEAui integration was established

TEAui is published to npm as the scoped `@tea-ui/*` family:

| package | version | role |
|---|---|---|
| `@tea-ui/core` | 1.0.0 | primitives: layout, typography, inputs, feedback, overlays, navigation |
| `@tea-ui/admin` | 1.0.0 | shell, navigation, data display, product states |
| `@tea-ui/icons` | 1.0.0 | the icon set |
| `@tea-ui/tokens` | 1.0.0 | design tokens: colour, spacing, radii, motion, density, themes |
| `@tea-ui/utils` | 1.0.0 | `cn`, `cva`, `slot`, `assertNever` |
| `@tea-ui/ux-standards` | 1.0.0 | the written UX rules, as data |
| `@tea-ui/templates` | 0.1.0 | page-level templates (not used — see below) |

All MIT. Installed from the registry like any other dependency; **the TEAui
repository is not modified, forked, vendored or copied from.**

**The API was read from the installed packages, not guessed.** Every component,
prop and variant used here was verified against the shipped `.d.ts` files, and the
frontend is typechecked against those real types:

```sh
npm --prefix ui run typecheck
```

That typecheck caught several invented props during development — `direction="row"`
where TEAui takes `"horizontal"`, `variant=` on `Alert` where it takes `tone=`,
a missing `level` on `CardTitle`. Worth stating plainly: guessing an API would
have produced a UI that compiled against fiction.

## What is used

**From `@tea-ui/admin`** — `AdminShell`, `Page`, `PageHeader`, `EmptyState`.

**From `@tea-ui/core`** — `Alert`/`AlertTitle`/`AlertDescription`, `Badge`,
`Button`, `Callout`, `Card` + `CardHeader`/`CardTitle`/`CardDescription`/
`CardBody`/`CardFooter`, `Checkbox`, `Container`, `Dialog` + parts,
`EmptyState`, `Field`/`FieldLabel`/`FieldDescription`/`FieldError`/`FieldGroup`,
`Input`, `NumberInput`, `PasswordInput`, `ScrollArea`, `SearchInput`,
`Select` + parts, `Stack`/`VStack`, `StatusBadge`, `Switch`, `Text`, `Textarea`,
`toast`/`Toaster`.

**Direct dependencies check:** `ui/package.json` declares only TEAui packages,
React, and Tauri's own bindings. No shadcn/ui, Radix, MUI, Ant Design, Chakra,
Mantine or anything else.

`radix-ui` and `tailwind-merge` appear in `ui/package-lock.json` as **transitive
dependencies of TEAui itself**, declared in `@tea-ui/admin`'s own manifest.
TEAvault adds no component library of its own. Verifiable with:

```sh
npm --prefix ui ls --depth=1
```

## The gap, and what was done about it

**TEAui has no data-table component.** There is no `Table`, `DataTable` or
`ResourceList`. The key list is therefore composed from primitives TEAui *does*
export: `Card` + `CardHeader`/`CardTitle`/`CardBody`/`CardFooter`, `Stack`,
`Badge`, `StatusBadge`, `ScrollArea`.

This is composition of existing TEAui components, not a reimplementation of a
TEAui one — no TEAui component was reimplemented, extended or shadowed. If TEAui
ships a data-table pattern later, the list should move to it.

`@tea-ui/patterns` is worth a note: it is a **metadata registry only**. Its
`PATTERNS` export is a list of `{id, solves, avoidWhen, composes, contract}`
records describing interactions like "resource list with filters". No composition
components exist yet. It was read for the contract wording and used to inform the
list's behaviour; nothing was imported from it at runtime.

`@tea-ui/templates` (0.1.0) was not used. It assembles page-level templates from
the admin layer, which would couple TEAvault's screens to TEAui's page
assumptions; the screens here are built from the primitive and admin components
directly. Noted as a deliberate choice rather than an oversight.

## Where plain CSS is used, and why

Only for layout that TEAui has no opinion about, and in exactly one place:

- `ui/src/components/ApprovalDialog.tsx` — a two-column label/value row inside
  the dialog. TEAui has no description-list primitive for this, and
  `DefinitionList` would impose its own semantics on what is really a
  key/value readout.

Everything else uses TEAui's own styling mechanisms: `data-theme` and
`data-density` on the root element, TEAui's token CSS imported once in
`App.tsx`, and TEAui components for every visual element. No custom tokens, no
invented props, no reimplementation.

## Accessibility

Not bolted on — TEAui's components carry it, and the screens are built from them
so it is inherited rather than reimplemented:

- `Field` owns the id space and wires `FieldLabel`/`FieldDescription`/`FieldError`
  through `aria-describedby`, so a control cannot be mislabelled.
- `PasswordInput` toggles with `aria-pressed` and a name that states the effect.
- `EmptyState` from the admin package: every empty state says what is empty, why,
  and what to do next.
- The approval dialog puts **Deny first in the DOM order**, so a reflexive Enter
  cannot grant access.
- `AdminShell` provides a skip link as the first focusable element.

**Not verified:** no automated axe run and no screen-reader pass was performed.
That is a gap, and it is listed in `STATUS.md` rather than glossed over.

## The security-relevant UI properties

These are design decisions, not styling:

1. **The UI cannot widen access.** Every screen renders what the daemon returned.
   There is no code path in `ui/src` that decides whether something may be shown.
2. **The approval dialog cannot show a secret.** `PendingApproval` has no field
   for a key value, so there is nowhere for one to have been put.
3. **Unverified things look unverified.** The requested purpose is quoted and
   attributed to the client; the PID is labelled as reported; an elevated process
   gets a `critical` alert.
4. **The key field is masked while typing**, so a screen share of the entry dialog
   does not reveal the key.
5. **Refusals render as refusals.** The `VaultError` code is branched on to choose
   the heading; nothing catches an error and retries or substitutes a default.