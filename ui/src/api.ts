/**
 * The typed bridge to the Rust shell.
 *
 * Every call here is a forward: the shell sends a request to the daemon and
 * returns the daemon's answer. This module deliberately has no cache, no retry
 * and no fallback — a refusal is an answer, and swallowing it or trying again
 * would be exactly the behaviour the security model forbids.
 *
 * The types mirror `teavault-core`'s IPC types. They are declared here rather
 * than generated so the dependency stays one-directional; the contract is
 * pinned by the integration tests in `crates/teavault-core/tests/boundary.rs`.
 */

import { invoke } from '@tauri-apps/api/core'

/** Stable refusal codes. Branch on these, never on the message text. */
export type ErrorCode =
  | 'not_initialized'
  | 'already_initialized'
  | 'locked'
  | 'invalid_passphrase'
  | 'attempts_exhausted'
  | 'integrity'
  | 'unsupported_format'
  | 'not_found'
  | 'invalid'
  | 'needs_confirmation'
  | 'no_grant'
  | 'grant_expired'
  | 'denied_by_user'
  | 'vault_locked'
  | 'operation_not_allowed'
  | 'invalid_request'
  | 'io'
  | 'malformed'

/** A refusal from the daemon. */
export class VaultError extends Error {
  readonly code: ErrorCode | string
  readonly requestId?: string
  readonly retryAfterSecs?: number
  readonly retryable: boolean

  constructor(e: {
    code: string
    message: string
    request_id?: string
    retry_after_secs?: number
    retryable: boolean
  }) {
    super(e.message)
    this.name = 'VaultError'
    this.code = e.code
    this.retryable = e.retryable
    if (e.request_id) this.requestId = e.request_id
    if (e.retry_after_secs !== undefined) this.retryAfterSecs = e.retry_after_secs
  }

  /** Whether the fix is "unlock first", as opposed to "you are not allowed". */
  get isLocked(): boolean {
    return this.code === 'locked' || this.code === 'vault_locked'
  }

  /** Whether the owner has to decide something. */
  get needsApproval(): boolean {
    return this.code === 'needs_confirmation'
  }
}

/** Turn whatever the IPC layer threw into a `VaultError`. */
function normalise(e: unknown): VaultError {
  if (e instanceof VaultError) return e
  if (e && typeof e === 'object' && 'code' in e && 'message' in e) {
    return new VaultError(e as never)
  }
  return new VaultError({
    code: 'io',
    message: e instanceof Error ? e.message : String(e),
    retryable: false,
  })
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args)
  } catch (e) {
    throw normalise(e)
  }
}

// ------------------------------------------------------------------ shapes

export interface Status {
  initialized: boolean
  locked: boolean
  entry_count: number
  pending_approvals: number
protocol: number
  kdf: string
}

export interface ListEntry {
  name: string
  id: string
  provider: string
  /** The vault is open. NOT a claim that the key works. */
  available: boolean
  capabilities: string[]
  display_name: string
  description?: string
  granted: boolean
  hidden: boolean
}

export interface GrantView {
  mode: string
  granted_at: string
  expires_at: number | null
  consumed: boolean
  mine: boolean
}

export interface InfoResult {
  name: string
  id: string
  provider: string
  display_name: string
  description?: string
  capabilities: string[]
  available: boolean
  granted: boolean
  hidden: boolean
  created_at: string
  updated_at: string
  grants: GrantView[]
}

/**
 * A pending access request.
 *
 * Deliberately has no field for the key's value — the approval dialog cannot
 * show a secret because there is nowhere for one to have been put.
 */
export interface PendingApproval {
  request_id: string
  client_fingerprint: string
  client_label: string
  client_path: string
  client_pid: number
  client_elevated: boolean
  entry_id: string
  entry_name: string
  declared_purpose?: string
  requested_at: string
}

export type AccessRow = [ApiKeyMetadata, Grant[]]

export interface ApiKeyMetadata {
  id: string
  name: string
  display_name: string
  provider: string
  description?: string
  capabilities: string[]
  created_at: string
  updated_at: string
  visibility: 'discoverable' | 'hidden'
}

export interface Grant {
  id: string
  client_fingerprint: string
  client_label: string
  entry_id: string
  declared_purpose?: string
  mode: { mode: 'allow_once' } | { mode: 'always_allow'; expires_at: number | null } | { mode: 'deny' }
  granted_at: string
  consumed: boolean
}

/** Settings exactly as the daemon stores them. */
interface WireSettings {
  clipboard_clear_seconds: number
  min_passphrase_chars: number
  created_at: string
  updated_at: string
}

/** Settings as a control wants them. */
export interface Settings {
  clipboard_clear_seconds: number
  min_passphrase_chars: number
  created_at: string
  updated_at: string
}

/** A client the daemon has seen connect. */
export interface KnownClient {
  fingerprint: string
  label: string
}

/** One key together with the permissions that apply to it. */
export interface Row {
  entry: ApiKeyMetadata
  grants: Grant[]
}

export type GrantModeWire = 'allow_once' | 'always_allow' | 'deny'

function fromWire(w: WireSettings): Settings {
  return {
    clipboard_clear_seconds: w.clipboard_clear_seconds,
    min_passphrase_chars: w.min_passphrase_chars,
    created_at: w.created_at,
    updated_at: w.updated_at,
  }
}

function toWire(s: Settings): WireSettings {
  return {
    clipboard_clear_seconds: s.clipboard_clear_seconds,
    min_passphrase_chars: s.min_passphrase_chars,
    created_at: s.created_at,
    updated_at: s.updated_at,
  }
}

/** The access overview arrives as tuples; the UI wants named fields. */
function toRows(rows: AccessRow[]): Row[] {
  return rows.map(([entry, grants]) => ({ entry, grants }))
}

function toKnownClients(pairs: [string, string][]): KnownClient[] {
  return pairs.map(([fingerprint, label]) => ({ fingerprint, label }))
}

// ----------------------------------------------------------------- commands

export const api = {
  status: () => call<Status>('status'),

  /** Create the vault. Only valid while `status.initialized` is false. */
  init: (passphrase: string) => call<{ created: boolean }>('init', { passphrase }),

  unlock: (passphrase: string) => call<{ locked: boolean }>('unlock', { passphrase }),
  lock: () => call<{ locked: boolean }>('lock'),
  /** Delete the vault and start over. The way out of a forgotten passphrase. */
  wipe: () => call<{ wiped: boolean }>('wipe'),

  list: (provider?: string) =>
    call<{ entries: ListEntry[] }>('list', provider ? { provider } : {}),
  info: (entry: string) => call<InfoResult>('info', { entry }),

  /** Release a secret. Requires a grant; may raise an approval request. */
  request: (entry: string, purpose?: string) =>
    call<{ name: string; value: string }>('request', { entry, purpose }),

  approvals: () => call<PendingApproval[]>('approvals'),
  resolveApproval: (requestId: string, entry: string, mode: GrantModeWire) =>
    call<{ resolved: boolean }>('resolve_approval', { requestId, entry, mode }),

  createEntry: (input: {
    name: string
    display_name: string
    provider: string
    description?: string | null
    hidden: boolean
    secret: string
  }) => call<ApiKeyMetadata>('create_entry', input),

  updateEntry: (
    entry: string,
    input: {
      display_name: string
      provider: string
      description?: string | null
      hidden: boolean
      secret?: string
    },
  ) => call<ApiKeyMetadata>('update_entry', { entry, ...input }),

  deleteEntry: (entry: string) => call<{ deleted: boolean }>('delete_entry', { entry }),
  copyToClipboard: (entry: string) => call<{ masked: string }>('copy_to_clipboard', { entry }),

  accessOverview: () => call<AccessRow[]>('access_overview').then(toRows),
  knownClients: () => call<[string, string][]>('known_clients').then(toKnownClients),
  grant: (input: {
    entry: string
    clientFingerprint: string
    clientLabel: string
    mode: GrantModeWire
    expiresAt?: number
  }) => call<{ grant_id: string }>('grant', input),
  revokeGrant: (grantId: string) => call<{ revoked: boolean }>('revoke_grant', { grantId }),
  revokeClient: (clientFingerprint: string) =>
    call<{ revoked: number }>('revoke_client', { clientFingerprint }),

  getSettings: () => call<WireSettings>('get_settings').then(fromWire),
  setSettings: (settings: Settings) =>
    call<WireSettings>('set_settings', { settings: toWire(settings) }).then(fromWire),
  auditRecent: (limit: number) => call<AuditEvent[]>('audit_recent', { limit }),

  changePassphrase: (current: string, next: string) =>
    call<{ changed: boolean }>('change_passphrase', { current, new: next }),

  backupExport: (path: string, passphrase: string) =>
    call<{ path: string }>('backup_export', { path, passphrase }),
  backupImport: (path: string, passphrase: string, overwrite: boolean) =>
    call<ImportReport>('backup_import', { path, passphrase, overwrite }),
}

export interface AuditEvent {
  seq: number
  at: string
  /**
   * What happened.
   *
   * Nested, and not flattened into the parent: the Rust side is an internally
   * tagged enum used as a *field*, and serde emits the tag inside the field's
   * value rather than merging it into the surrounding object. So the name is
   * `kind.event`, not `event`.
   *
   * That distinction is not academic. Reading `e.event` gave `undefined`, an
   * unknown name then reached `undefined.replace(...)`, and the render threw —
   * which emptied the window the moment the Activity tab was opened. The Rust
   * side has a test pinning this shape; see `an_audit_event_carries_the_fields_
   * the_activity_screen_reads`.
   */
  kind: {
    /** snake_case name, e.g. `secret_released`. */
    event: string
    entry_id?: string
    name?: string
    reason?: string
    request_id?: string
    grant_id?: string
  }
  client?: string
  prev_chain: string
  mac: string
}

export interface ImportReport {
  added: number
  skipped: number
  replaced: number
  grants: number
  merged: boolean
}

/** Providers offered in the editor. Metadata, never a validity claim. */
export const PROVIDERS = ['OpenAI', 'Anthropic', 'Groq', 'GitHub', 'Cloudflare', 'Other'] as const

/** Capability suggestions per provider. Advisory; the user edits freely. */
export const SUGGESTED_CAPABILITIES: Record<string, string[]> = {
  OpenAI: ['llm', 'embeddings'],
  Anthropic: ['llm'],
  Groq: ['llm'],
  GitHub: ['source', 'ci'],
  Cloudflare: ['dns', 'workers', 'storage'],
  Other: [],
}