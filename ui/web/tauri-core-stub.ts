/**
 * A stand-in for `@tauri-apps/api/core`, used by the browser dev build.
 *
 * Aliased in `vite.config.ts` when `--mode web` is on. It exports exactly one
 * thing, `invoke`, which is all `api.ts` imports from the real module — so the
 * application's own code is identical in both builds.
 *
 * See `./fake-daemon.ts` for the behaviour and, more importantly, for what that
 * file is not allowed to become.
 */

/**
 * Only `invoke` is re-exported. Anything else the real module offers would have
 * to be imported from `@tauri-apps/api/core` — which is this module's own
 * specifier, so the import would resolve back here and loop. If the UI ever
 * needs a second export, that export gets stubbed here explicitly instead.
 */

export { invoke, resetFakeDaemon, __fakeDaemonState } from './fake-daemon'
