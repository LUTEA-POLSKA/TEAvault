/**
 * A stateful stand-in for the daemon, for the browser dev build.
 *
 * Aliased in as `@tauri-apps/api/core` when `vite --mode web` runs, so `api.ts`
 * keeps calling `invoke` and nothing in the application changes. In the app this
 * file is never bundled: the real module is resolved instead.
 *
 * ## What it is for
 *
 * Judging the interface. Every screen has to be reachable by clicking, which
 * means the states that matter — nothing saved yet, a key listed, an access
 * request waiting for a decision, a refused request — have to be *producible*,
 * not just described. So this holds real state in memory and enforces the parts
 * of the model the interface depends on:
 *
 * * locked operations refuse while locked,
 * * `request` without a grant raises an approval and refuses with
 *   `needs_confirmation`, exactly as the dispatcher does,
 * * an `allow_once` grant is spent by the request that used it.
 *
 * ## What it is not
 *
 * It is not the specification. The wire types are imported from `../src/api`
 * — the only source of truth for the IPC contract. Only `WireSettings` is
 * declared here because it is private to `api.ts`. If the wire shapes ever
 * disagree with `crates/teavault-core/tests/boundary.rs`, that test is right and
 * this file is a bug.
 *
 * Refusals are thrown as plain objects with `code`/`message`/`retryable`,
 * because that is the shape `api.ts`'s `normalise` turns into a `VaultError`.
 */
import type {
  ApiKeyMetadata,
  Grant,
  GrantView,
  PendingApproval,
  AuditEvent,
  ListEntry,
  InfoResult,
} from '../src/api'

/** The identity the stub pretends requests come from. */
const CLIENT = {
  fingerprint: 'a1b2c3d4e5f60718',
  label: 'claude-code',
  path: 'C:\\tools\\node\\claude-code.exe',
  pid: 24_318,
  elevated: false,
}

/** Fixed so a reload does not produce a different-looking log every time. */
const EPOCH = '2026-10-05T09:00:00Z'

function stamp(offsetSeconds: number): string {
  const base = Date.parse(EPOCH)
  return new Date(base + offsetSeconds * 1000).toISOString().replace(/\.\d+Z$/, 'Z')
}

function refuse(code: string, message: string, retryable = false): never {
  throw { code, message, retryable }
}

// -------------------------------------------------------------------- state

/** Private wire settings — not exported from api.ts, so declared locally. */
interface WireSettings {
  clipboard_clear_seconds: number
  min_passphrase_chars: number
  created_at: string
  updated_at: string
}

interface State {
  initialized: boolean
  locked: boolean
  entries: ApiKeyMetadata[]
  /** The plaintext, kept here because this is a fixture and not a vault. */
  secrets: Map<string, string>
  grants: Grant[]
  approvals: PendingApproval[]
  audit: AuditEvent[]
  clients: Array<[string, string]>
  settings: WireSettings
  counter: number
}

/**
 * Starts initialised, unlocked and **empty**.
 *
 * Empty on purpose: the first screen a new user sees is the one with nothing on
 * it, so it is the one worth being able to look at. Creating a key is two
 * clicks away.
 */
function freshState(): State {
  return {
    initialized: true,
    locked: false,
    entries: [],
    secrets: new Map(),
    grants: [],
    approvals: [],
    audit: [
      {
        seq: 1,
        at: stamp(0),
        kind: { event: 'vault_created' },
        prev_chain: '0'.repeat(64),
        mac: '0'.repeat(64),
      },
      {
        seq: 2,
        at: stamp(1),
        kind: { event: 'vault_unlocked' },
        prev_chain: '0'.repeat(64),
        mac: '0'.repeat(64),
      },
    ],
    clients: [[CLIENT.fingerprint, CLIENT.label]],
    settings: {
      clipboard_clear_seconds: 30,
      min_passphrase_chars: 12,
      created_at: EPOCH,
      updated_at: EPOCH,
    },
    counter: 0,
  }
}

let state = freshState()

/** Reset from the console, e.g. to get the empty state back. */
export function resetFakeDaemon(): void {
  state = freshState()
}

/** Exposed so a test can seed or inspect without going through `invoke`. */
export function __fakeDaemonState(): State {
  return state
}

function nextId(prefix: string): string {
  state.counter += 1
  return `${prefix}_${state.counter.toString().padStart(4, '0')}`
}

function record(event: string, extra: Record<string, string> = {}, client?: string): void {
  const seq = state.audit.length + 1
  state.audit.push({
    seq,
    at: stamp(seq * 7),
    kind: { event, ...extra },
    ...(client ? { client } : {}),
    prev_chain: '0'.repeat(64),
    mac: '0'.repeat(64),
  })
}

function requireUnlocked(): void {
  if (!state.initialized) refuse('not_initialized', 'no vault yet')
  if (state.locked) refuse('vault_locked', 'the vault is locked')
}

function findEntry(needle: string): ApiKeyMetadata {
  const hit = state.entries.find((e) => e.id === needle || e.name === needle)
  if (!hit) refuse('not_found', `no entry named ${needle}`)
  return hit
}

/** The grant that permits release right now, or `undefined`. */
function liveGrant(entryId: string): Grant | undefined {
  return state.grants.find(
    (g) =>
      g.entry_id === entryId &&
      g.client_fingerprint === CLIENT.fingerprint &&
      g.mode.mode !== 'deny' &&
      !(g.mode.mode === 'allow_once' && g.consumed),
  )
}

function toListEntry(e: ApiKeyMetadata): ListEntry {
  return {
    name: e.name,
    id: e.id,
    provider: e.provider,
    available: true,
    capabilities: e.capabilities,
    display_name: e.display_name,
    ...(e.description ? { description: e.description } : {}),
    ...(e.category ? { category: e.category } : {}),
    granted: liveGrant(e.id) !== undefined,
    hidden: e.visibility === 'hidden',
  }
}

function toGrantView(g: Grant): GrantView {
  return {
    mode: g.mode.mode,
    granted_at: g.granted_at,
    expires_at: g.mode.mode === 'always_allow' ? g.mode.expires_at : null,
    consumed: g.consumed,
    mine: g.client_fingerprint === CLIENT.fingerprint,
  }
}

// ----------------------------------------------------------------- commands

type Args = Record<string, unknown>

function str(a: Args, k: string): string {
  const v = a[k]
  if (typeof v !== 'string') refuse('invalid', `${k} must be a string`)
  return v
}

function optStr(a: Args, k: string): string | undefined {
  const v = a[k]
  if (v === undefined || v === null) return undefined
  if (typeof v !== 'string') refuse('invalid', `${k} must be a string`)
  return v
}

function bool(a: Args, k: string): boolean {
  return a[k] === true
}

function strList(a: Args, k: string): string[] {
  const v = a[k]
  if (!Array.isArray(v) || v.some((x) => typeof x !== 'string')) {
    refuse('invalid', `${k} must be a list of strings`)
  }
  return v as string[]
}

function grantMode(wire: string, expiresAt?: number) {
  if (wire === 'allow_once') return { mode: 'allow_once' } as const
  if (wire === 'deny') return { mode: 'deny' } as const
  if (wire === 'always_allow') {
    return { mode: 'always_allow', expires_at: expiresAt ?? null } as const
  }
  refuse('invalid', `unknown grant mode ${wire}`)
}

const handlers: Record<string, (args: Args) => unknown> = {
  status: () => ({
    initialized: state.initialized,
    locked: state.locked,
    entry_count: state.entries.length,
    pending_approvals: state.approvals.length,
    protocol: 1,
    kdf: 'argon2id m=19456 t=2 p=1',
  }),

  init: (args) => {
    const passphrase = str(args, 'passphrase')
    if (passphrase.length < state.settings.min_passphrase_chars) {
      refuse('invalid', `passphrase must be at least ${state.settings.min_passphrase_chars} characters`)
    }
    if (state.initialized) refuse('already_initialized', 'a vault already exists')
    state.initialized = true
    state.locked = false
    record('vault_created')
    return { created: true }
  },

  unlock: () => {
    state.locked = false
    record('vault_unlocked')
    return { locked: false }
  },

  lock: () => {
    state.locked = true
    record('vault_locked')
    return { locked: true }
  },

  wipe: () => {
    state = freshState()
    return { wiped: true }
  },

  list: (args) => {
    requireUnlocked()
    const provider = optStr(args, 'provider')
    const entries = state.entries
      .filter((e) => !provider || e.provider === provider)
      .filter((e) => e.visibility === 'discoverable' || liveGrant(e.id) !== undefined)
      .map(toListEntry)
    record('metadata_listed', {}, CLIENT.fingerprint)
    return { entries }
  },

  info: (args) => {
    requireUnlocked()
    const entry = findEntry(str(args, 'entry'))
    record('metadata_read', { entry_id: entry.id, name: entry.name }, CLIENT.fingerprint)
    const base = toListEntry(entry)
    return {
      name: base.name,
      id: base.id,
      provider: base.provider,
      display_name: base.display_name,
      ...(base.description ? { description: base.description } : {}),
      capabilities: base.capabilities,
      available: base.available,
      granted: base.granted,
      hidden: base.hidden,
      created_at: entry.created_at,
      updated_at: entry.updated_at,
      grants: state.grants.filter((g) => g.entry_id === entry.id).map(toGrantView),
    } satisfies InfoResult
  },

  /**
   * The interesting one. Without a grant this raises an approval and refuses,
   * which is what makes the approval dialog reachable by clicking.
   */
  request: (args) => {
    requireUnlocked()
    const entry = findEntry(str(args, 'entry'))
    const purpose = optStr(args, 'purpose')
    const grant = liveGrant(entry.id)

    if (!grant) {
      const already = state.approvals.find(
        (p) => p.entry_id === entry.id && p.client_fingerprint === CLIENT.fingerprint,
      )
      if (!already) {
        const approval: PendingApproval = {
          request_id: nextId('req'),
          client_fingerprint: CLIENT.fingerprint,
          client_label: CLIENT.label,
          client_path: CLIENT.path,
          client_pid: CLIENT.pid,
          client_elevated: CLIENT.elevated,
          entry_id: entry.id,
          entry_name: entry.name,
          ...(purpose ? { declared_purpose: purpose } : {}),
          requested_at: stamp(state.audit.length * 7),
        }
        state.approvals.push(approval)
        record('approval_requested', { request_id: approval.request_id, entry_id: entry.id }, CLIENT.fingerprint)
      }
      record('secret_refused', { reason: 'no_grant' }, CLIENT.fingerprint)
      refuse('needs_confirmation', 'this program needs your approval')
    }

    if (grant.mode.mode === 'allow_once') grant.consumed = true
    record('secret_released', { grant_id: grant.id, entry_id: entry.id }, CLIENT.fingerprint)
    return { name: entry.name, value: state.secrets.get(entry.id) ?? 'sk-not-stored' }
  },

  approvals: () => {
    requireUnlocked()
    return state.approvals
  },

  resolve_approval: (args) => {
    requireUnlocked()
    const requestId = str(args, 'requestId')
    const mode = str(args, 'mode')
    const idx = state.approvals.findIndex((p) => p.request_id === requestId)
    if (idx < 0) refuse('not_found', `no pending request ${requestId}`)
    const approval = state.approvals[idx]!
    state.approvals.splice(idx, 1)

    state.grants.push({
      id: nextId('grant'),
      client_fingerprint: approval.client_fingerprint,
      client_label: approval.client_label,
      entry_id: approval.entry_id,
      ...(approval.declared_purpose ? { declared_purpose: approval.declared_purpose } : {}),
      mode: grantMode(mode),
      granted_at: stamp(state.audit.length * 7),
      consumed: false,
    })
    record(
      mode === 'deny' ? 'denied_by_owner' : 'approval_granted',
      { request_id: requestId, entry_id: approval.entry_id },
    )
    return { resolved: true }
  },

  create_entry: (args) => {
    requireUnlocked()
    const name = str(args, 'name')
    if (state.entries.some((e) => e.name === name)) {
      refuse('invalid', `${name} already exists`)
    }
    const now = stamp(state.audit.length * 7)
    const meta: ApiKeyMetadata = {
      id: nextId('key'),
      name,
      display_name: optStr(args, 'display_name') ?? name,
      provider: str(args, 'provider'),
      ...(optStr(args, 'description') ? { description: optStr(args, 'description') } : {}),
      capabilities: args.capabilities === undefined ? [] : strList(args, 'capabilities'),
      ...(optStr(args, 'category') ? { category: optStr(args, 'category') } : {}),
      created_at: now,
      updated_at: now,
      visibility: bool(args, 'hidden') ? 'hidden' : 'discoverable',
    }
    state.entries.push(meta)
    state.secrets.set(meta.id, `sk-web-stub-${meta.id}`)
    record('key_created', { entry_id: meta.id, name })
    return meta
  },

  update_entry: (args) => {
    requireUnlocked()
    const meta = findEntry(str(args, 'entry'))
    const display = optStr(args, 'display_name')
    const provider = optStr(args, 'provider')
    const description = optStr(args, 'description')
    const capabilities = args.capabilities === undefined ? undefined : strList(args, 'capabilities')

    if (display !== undefined) meta.display_name = display
    if (provider !== undefined) meta.provider = provider
    if (description !== undefined) meta.description = description
    if (capabilities !== undefined) meta.capabilities = capabilities
    if (args.category !== undefined) {
      const c = optStr(args, 'category')
      if (c === undefined || c === '') delete meta.category
      else meta.category = c
    }
    if (args.hidden !== undefined) {
      meta.visibility = bool(args, 'hidden') ? 'hidden' : 'discoverable'
    }
    meta.updated_at = stamp(state.audit.length * 7)

    const secret = optStr(args, 'secret')
    if (secret !== undefined) state.secrets.set(meta.id, secret)

    record('key_updated', { entry_id: meta.id, name: meta.name })
    return meta
  },

  delete_entry: (args) => {
    requireUnlocked()
    const meta = findEntry(str(args, 'entry'))
    state.entries = state.entries.filter((e) => e.id !== meta.id)
    state.secrets.delete(meta.id)
    state.grants = state.grants.filter((g) => g.entry_id !== meta.id)
    record('key_deleted', { entry_id: meta.id, name: meta.name })
    return { deleted: true }
  },

  copy_to_clipboard: (args) => {
    requireUnlocked()
    const meta = findEntry(str(args, 'entry'))
    record('key_copied', { entry_id: meta.id })
    // A masked form, which is what the real vault returns.
    return { masked: 'sk-…' }
  },

  access_overview: () => {
    requireUnlocked()
    return state.entries.map((e): [ApiKeyMetadata, Grant[]] => [
      e,
      state.grants.filter((g) => g.entry_id === e.id),
    ])
  },

  known_clients: () => {
    requireUnlocked()
    return state.clients
  },

  grant: (args) => {
    requireUnlocked()
    const meta = findEntry(str(args, 'entry'))
    const fingerprint = str(args, 'clientFingerprint')
    const mode = str(args, 'mode')
    const expiresAt = args.expiresAt
    const id = nextId('grant')
    state.grants.push({
      id,
      client_fingerprint: fingerprint,
      client_label: optStr(args, 'clientLabel') ?? fingerprint.slice(0, 8),
      entry_id: meta.id,
      mode: grantMode(mode, typeof expiresAt === 'number' ? expiresAt : undefined),
      granted_at: stamp(state.audit.length * 7),
      consumed: false,
    })
    if (!state.clients.some(([f]) => f === fingerprint)) {
      state.clients.push([fingerprint, fingerprint.slice(0, 8)])
    }
    record('grant_created', { grant_id: id, entry_id: meta.id })
    return { grant_id: id }
  },

  revoke_grant: (args) => {
    requireUnlocked()
    const id = str(args, 'grantId')
    const before = state.grants.length
    state.grants = state.grants.filter((g) => g.id !== id)
    if (state.grants.length === before) refuse('not_found', `no grant ${id}`)
    record('grant_revoked', { grant_id: id })
    return { revoked: true }
  },

  revoke_client: (args) => {
    requireUnlocked()
    const fingerprint = str(args, 'clientFingerprint')
    const before = state.grants.length
    state.grants = state.grants.filter((g) => g.client_fingerprint !== fingerprint)
    const n = before - state.grants.length
    if (n > 0) record('grants_revoked_for_client', { count: String(n) })
    return { revoked: n }
  },

  get_settings: () => ({ ...state.settings }),

  set_settings: (args) => {
    requireUnlocked()
    const next = args.settings as Partial<WireSettings> | undefined
    if (!next) refuse('invalid', 'settings are required')
    if (
      next.clipboard_clear_seconds !== undefined &&
      (next.clipboard_clear_seconds < 0 || next.clipboard_clear_seconds > 3600)
    ) {
      refuse('invalid', 'clipboard_clear_seconds must be between 0 and 3600')
    }
    state.settings = { ...state.settings, ...next, updated_at: stamp(state.audit.length * 7) }
    record('settings_changed', { setting: 'clipboard_clear_seconds' })
    return { ...state.settings }
  },

  audit_recent: (args) => {
    const limit = typeof args.limit === 'number' ? args.limit : 50
    return state.audit.slice(-limit).reverse()
  },

  change_passphrase: (args) => {
    requireUnlocked()
    const next = str(args, 'new')
    if (next.length < state.settings.min_passphrase_chars) {
      refuse('invalid', `passphrase must be at least ${state.settings.min_passphrase_chars} characters`)
    }
    record('passphrase_changed')
    return { changed: true }
  },

  backup_export: (args) => {
    requireUnlocked()
    const path = str(args, 'path')
    record('backup_exported', { path })
    return { path }
  },

  backup_import: (args) => {
    requireUnlocked()
    const merged = bool(args, 'overwrite')
    const before = state.entries.length
    if (!merged) {
      // Nothing to merge from: a fixture cannot read a real file, so the report
      // is the honest one for a fresh vault.
      record('backup_imported', { entries: '0', merged: 'false' })
      return { added: 0, skipped: before, replaced: 0, grants: 0, merged: false }
    }
    record('backup_imported', { entries: '0', merged: 'true' })
    return { added: 0, skipped: 0, replaced: 0, grants: 0, merged: true }
  },
}

/** The shape `@tauri-apps/api/core` exports. */
export async function invoke<T>(command: string, args?: Args): Promise<T> {
  const handler = handlers[command]
  if (!handler) {
    // Loud on purpose: a command the UI calls that this fixture does not know is
    // a gap in the fixture, and silently returning `undefined` would turn that
    // into a confusing render bug instead.
    throw {
      code: 'malformed',
      message: `the web stub has no handler for "${command}"`,
      retryable: false,
    }
  }
  // A beat of latency, so a loading state is visible rather than theoretical.
  await new Promise((resolve) => setTimeout(resolve, 40))
  return handler(args ?? {}) as T
}
