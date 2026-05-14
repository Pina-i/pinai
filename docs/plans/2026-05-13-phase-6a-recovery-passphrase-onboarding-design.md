# Phase 6a — Recovery passphrase onboarding — design

**Date:** 2026-05-13
**Scope:** Web client (no server changes). Phase 6a is the first of three Phase 6 sub-features:

- **6a** — Recovery passphrase onboarding (this doc)
- **6b** — Settings → Devices section (separate plan)
- **6c** — Device pairing via SPAKE2 (separate plan)

The crypto primitives for all three already exist; Phase 6 is the UI + flow that exposes them.

## Why

Today the web client silently auto-registers an MLS identity on every authenticated mount (`useRegisterMlsIdentity`). On a fresh device this is invisible to the user: their MSK is created, their KeyPackages get published, and conversations are encrypted — but if they ever lose all their devices they lose every conversation, because the spec's opt-in Recovery Key flow has no UI.

Phase 6a fills that gap with two onboarding views, plus the local-storage plumbing for the eventual 6b reveal UI. After 6a, every new account gets a recovery passphrase by default (Skip is allowed but the wrapped blob still uploads), and a fresh-device login can recover history by entering 24 words.

## The user-visible flow

Two new full-page onboarding routes sit between OIDC login and the app shell. The `_authenticated.tsx` layout uses a gate hook (`useIdentityOnboardingGate`) that probes local + server state, then either renders the app or redirects to one of the onboarding routes.

### `/onboarding/recovery-setup` — first device

Matches the `SecRecoveryKey` artboard in `web-client/design/screens/security.jsx`.

Behaviour: the page renders a "Setting up your recovery passphrase…" placeholder while a `bootstrap-first-device.usecase.ts` runs:

1. `e2eePort.register(...)` — generates MSK/SSK/USK locally, publishes identity row + initial KeyPackage batch.
2. `generateMnemonic(wordlist, 256)` from `@scure/bip39` — 24-word English mnemonic, ~256 bits entropy.
3. `e2eePort.setupRecoveryKey(idpUrl, token, mnemonic)` — wraps the local MSK under Argon2id-derived KEK + XChaCha20-Poly1305 (existing `recovery.adapter.ts`), uploads to `PUT /api/keys/recovery`.
4. `storage.saveRecoveryPassphrase(words)` — encrypted IDB slot, same per-device AES-GCM key as the identity bundle.

When all four succeed the page shows the 24 words in a 3-column grid. Actions: **Copy passphrase** / **Continue** / **Skip for now**. Continue and Skip are cryptographically equivalent — both have already uploaded the blob and saved the local copy. The only difference is UX assumption (Continue: "I wrote it down externally"; Skip: "I'll come back to Settings to see it later").

If any step fails the page shows an error message + retry button; partial state is tolerated because `register()` is idempotent and `setupRecoveryKey` overwrites.

### `/onboarding/recovery-restore` — new device (server identity exists)

Matches the `SecRecoverHistory` artboard.

Twenty-four input slots in a 3-column grid. Per-word validation against the BIP-39 wordlist highlights typos in real time. "Paste passphrase" parses whitespace-separated input and fills all 24 slots. "Restore" enables when all 24 slots hold valid BIP-39 words; clicking it calls `recoverFromPassphrase(passphrase)` and navigates to the app on success.

A "Start fresh on this device" link skips recovery and calls `register()` directly. Peers re-include this device on their next message send via the normal KeyPackage claim flow; the user keeps their account but loses message history.

### Gate logic

```text
local identity in IDB?
├── YES → render app
└── NO  → probe server:
          getIdentity(ownActorUri)  → has_server_identity
          getRecoveryBlob()         → has_server_blob
          ─────────────────────────────────────────────────
          ├── !has_server_identity                       → /onboarding/recovery-setup
          ├── has_server_identity && has_server_blob     → /onboarding/recovery-restore
          └── has_server_identity && !has_server_blob    → /onboarding/recovery-restore
                                                           (passphrase block disabled;
                                                            only "Start fresh" enabled)
```

The third branch (`has_server_identity && !has_server_blob`) is reachable in three ways: (1) the user explicitly deleted their recovery blob via the 6b Clear action, (2) the user skipped on the first device AND something corrupted the local IDB before the blob upload completed, (3) legacy accounts predating 6a. We handle it gracefully even though it is rare.

## Architecture

### Routes

```
src/routes/
├── onboarding/
│   ├── recovery-setup.tsx     → <RecoverySetupPage />
│   └── recovery-restore.tsx   → <RecoveryRestorePage />
└── _authenticated.tsx          → unchanged path; new gate hook decides whether to render
```

The onboarding routes use `beforeLoad` to require `accessToken && idpUrl` (redirect to `/` otherwise). They sit outside `_authenticated.tsx` so the sidebar/topbar/WS aren't mounted until onboarding completes.

### Hooks

- **`useIdentityOnboardingGate()`** — new in `presentation/hooks/`. Runs on mount in `_authenticated.tsx`. Returns `{ status: "loading" | "ready" | "redirecting" }`. While loading, the layout renders a minimal placeholder; while redirecting, it returns null (a `navigate` is in flight); on ready, it renders the app. The hook performs the probe table above and issues `navigate({ to: ... })` when redirection is needed.

- **`useRegisterMlsIdentity`** — removed from `_authenticated.tsx`. Registration is now driven exclusively by the onboarding setup view.

- **`useConsumeMlsWelcomes`** — stays mounted in `_authenticated.tsx`. It short-circuits when no device identity is set, so it's safe to mount before onboarding completes.

### Port + adapter surface

New on `IE2eePort` / `E2eeAdapter`:

| Method | Purpose | Implementation |
|---|---|---|
| `hasLocalIdentity(): Promise<boolean>` | Gate probe shorthand | Wraps `storage.loadIdentityKeypair()` returning non-null |
| `loadStoredPassphrase(): Promise<string[] \| null>` | Source for the eventual 6b reveal UI | Decrypts the new IDB slot under the device key |
| `clearRecoveryKey(idpUrl, accessToken): Promise<void>` | Server delete + wipe local slot. Used in 6b "Clear" action, landing in 6a so the storage adapter slot is symmetric | `keyDirectory.deleteRecoveryBlob(...)` + `storage.clearRecoveryPassphrase()` |

### Storage adapter

`IndexedDbStorageAdapter` gets one new object store:

- DB version bumps from **2 → 3** with a new `recovery_passphrase` store
- `saveRecoveryPassphrase(words: string[]): Promise<void>` — encrypts under device key, stores under a fixed key
- `loadRecoveryPassphrase(): Promise<string[] | null>` — decrypt + parse; null when missing or AEAD fails (treated as "not stored")
- `clearRecoveryPassphrase(): Promise<void>` — delete the row

Migration from v2 → v3 is additive (new store) — no data conversion needed.

### Use cases

New in `domain/usecases/e2ee/`:

- **`bootstrap-first-device.usecase.ts`** — orchestrates the four-step flow described above. Returns `{ words: string[]; fingerprint: string }` on success.

The existing `recover-from-passphrase.usecase.ts` is used as-is by the restore view.

### UI

New presentation components:

- `presentation/pages/onboarding/RecoverySetupPage/` — page + viewmodel
- `presentation/pages/onboarding/RecoveryRestorePage/` — page + viewmodel
- `presentation/molecules/RecoveryPassphraseDisplay/` — read-only 3-col grid of numbered words. Reused by the 6b reveal UI.
- `presentation/molecules/RecoveryPassphraseInput/` — 24-slot input with per-word BIP-39 validation, paste support, typo highlighting. Mirrors the `WordSlot` component in `design/screens/security.jsx`.

Toasts (sonner) for "Passphrase copied" / "Restoration failed: incorrect passphrase" / "Network error — retrying…".

## Dependencies

Add to `web-client/package.json`:

- `@scure/bip39` (~10 KB gzipped) — wordlist + mnemonic generation. Already part of the noble family used by `identity.adapter.ts` and `recovery.adapter.ts`.

## Atomicity and reliability

The setup page renders a single loading state until bootstrap completes; the 24-word grid only appears after all four steps succeed. The user never sees a partial state.

If they reload the tab mid-bootstrap:

- If `register()` completed but the blob upload didn't, the gate sees a local identity on next mount → renders the app. The account works; recovery is not configured. User reaches Settings → Devices in Phase 6b to re-trigger setup.
- If `register()` didn't complete (very rare — it's a few synchronous IDB writes plus one HTTP POST), the gate re-probes the server, sees no identity, re-renders the setup page, bootstrap re-runs.

The atomic-from-user-POV property is "what you Copy is what's actually live", not "no partial server state ever exists".

## Edge cases

| Scenario | Handling |
|---|---|
| User reloads mid-setup, post-register pre-upload | Gate admits to app. Recovery not configured; reset via 6b later. |
| Network failure on `setupRecoveryKey` | Error toast + retry button; idempotent. |
| Wrong passphrase on restore | `recoverFromPassphrase` throws AEAD failure → toast.error; input keeps state. |
| `has_server_identity && !has_server_blob` (legacy or post-Clear) | Restore view renders with passphrase block disabled + "Start fresh on this device" as the only enabled action. |
| Probe HTTP 500 | Gate shows error + retry; doesn't navigate either way until probe succeeds. Prevents flaky-network corruption. |
| Multiple tabs on the same fresh device | `E2eeAdapter.register` already dedupes concurrent calls via `registerPromise`; gate hook is idempotent under strict-mode double-fire. |
| User clicks "Start fresh on this device" | `register()` runs (skips passphrase entirely). Account works; conversation history empty; peers re-add via fresh KP claims. No recovery blob created. |

## Spec updates

None required. `specs/05-e2ee.md § 9` already describes this design.

Phase 6b will add a sentence noting the local passphrase storage (for the reveal UI) and a brief note that "Clear recovery key" wipes both server blob and local slot.

## Testing

Add to `web-client/test/`:

- `bootstrap-first-device.spec.ts` — usecase test with an in-memory `IE2eePort` mock + a fake storage. Asserts the four-step ordering, idempotent retry after a mid-flight failure, and that `saveRecoveryPassphrase` is called with the same words returned to the caller.
- `gate-routing.spec.ts` — pure-function test of the branch table: given `(has_local, has_server_identity, has_server_blob)` → expected route. Avoids React Router test plumbing.
- `recovery-passphrase-input.spec.ts` — component test for the 24-slot input. Asserts: paste support fills 24 slots, single-word typo flagged with warning state, "Restore" disabled until all 24 valid, "Restore" enabled when all 24 valid.

No server-side test additions — the IdP endpoints (`PUT/GET/DELETE /api/keys/recovery`) already exist and are covered by Phase 4b tests.

## Out of scope (deferred to 6b / 6c)

- Settings → Devices section (Phase 6b). Includes the "View recovery passphrase" reveal UI that consumes `loadStoredPassphrase`, the device list + revoke, and the "Clear recovery key" action.
- Device pairing via SPAKE2 + QR (Phase 6c). The setup view's first-device branch and the restore view's "Pair from another device — coming soon" label are sealed until 6c lands.
- A passphrase strength meter on the setup view. The wordlist-based generation guarantees a uniform entropy floor; no UI signal needed.
- "Confirm by re-typing some words" UX on first device. The display shows the words plus an explicit "I've written them down" gesture (`Continue`); we trust the user. Could add later.

## File touch list

```
web-client/
├── package.json                                                          # +@scure/bip39
├── src/routes/onboarding/recovery-setup.tsx                              # new route
├── src/routes/onboarding/recovery-restore.tsx                            # new route
├── src/routes/_authenticated.tsx                                         # remove useRegisterMlsIdentity; mount useIdentityOnboardingGate
├── src/presentation/pages/onboarding/RecoverySetupPage/                  # new page + viewmodel
├── src/presentation/pages/onboarding/RecoveryRestorePage/                # new page + viewmodel
├── src/presentation/molecules/RecoveryPassphraseDisplay/                 # new molecule
├── src/presentation/molecules/RecoveryPassphraseInput/                   # new molecule
├── src/presentation/hooks/useIdentityOnboardingGate.ts                   # new hook
├── src/presentation/hooks/useRegisterMlsIdentity.ts                      # delete
├── src/domain/usecases/e2ee/bootstrap-first-device.usecase.ts            # new use case
├── src/domain/ports/e2ee.port.ts                                         # +hasLocalIdentity, +loadStoredPassphrase, +clearRecoveryKey
├── src/adapters/e2ee/e2ee.adapter.ts                                     # impl of the three new methods
├── src/adapters/e2ee/storage.adapter.ts                                  # DB v3, +saveRecoveryPassphrase/loadRecoveryPassphrase/clearRecoveryPassphrase
└── test/
    ├── bootstrap-first-device.spec.ts                                    # new
    ├── gate-routing.spec.ts                                              # new
    └── recovery-passphrase-input.spec.ts                                 # new
```
