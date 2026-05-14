# Phase 6b — Settings → Devices section — design

**Date:** 2026-05-14
**Scope:** Server (identity-provider Rust) + web client (TypeScript). Adds device enumeration + revocation + recovery passphrase reveal/clear to the existing `SettingsModal`. Second of three Phase 6 sub-features (6a Recovery passphrase onboarding shipped; 6c Device pairing via SPAKE2 QR is next).

The visual design is fixed by `web-client/design/screens/security.jsx::SecDevicesSettings` — the implementation must match the prototype.

## Why

After 6a every account has a published identity, a stash of KeyPackages per device, and a wrapped MSK on the server. What's missing is the user-facing surface to:

- See which devices have published KeyPackages under their account (and when each was paired / last seen).
- Sign out a device they don't recognise.
- View their recovery passphrase later, after the onboarding step (the only place that shows it today).
- Clear their recovery key if they want to opt out.

Phase 6b adds a "Devices" section to the existing `SettingsModal` covering all of that.

## Architecture

The two-pane drill-in pattern already exists in `SettingsModal.tsx` — left pane is a card grid of section tiles, right pane is the active section's editor (currently only `ProfileEditor`). Phase 6b adds one new section descriptor and one new editor; no modal-level changes.

### Server-side

One new table, two new endpoints, one new repo module. The KP-publish handler gets a tiny hook to upsert device rows + touch `last_seen_at`.

```sql
CREATE TABLE user_devices (
    device_id      UUID PRIMARY KEY,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    display_name   TEXT NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('laptop','phone','tablet','unknown')),
    paired_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at     TIMESTAMPTZ
);
CREATE INDEX idx_user_devices_user ON user_devices(user_id);
```

Backfill in the same migration: any `device_id` already present in `key_packages` gets a row with `display_name = 'Web client'`, `kind = 'unknown'`, `paired_at = MIN(created_at) per device`. `ON CONFLICT DO NOTHING` keeps the migration safe to re-run.

Endpoints:

| Method | Path | Auth | Body | Returns |
|---|---|---|---|---|
| `GET` | `/api/keys/devices` | Bearer | — | `{ devices: DeviceListEntry[] }` sorted by `revoked_at NULLS FIRST, last_seen_at DESC` |
| `POST` | `/api/keys/devices/:device_id/revoke` | Bearer | — | `204 No Content` (idempotent — `UPDATE ... WHERE revoked_at IS NULL`) |

`DeviceListEntry` shape:

```json
{
  "device_id": "uuid",
  "display_name": "string",
  "kind": "laptop|phone|tablet|unknown",
  "paired_at": "rfc3339",
  "last_seen_at": "rfc3339",
  "revoked_at": "rfc3339|null"
}
```

`is_current` is computed client-side by comparing `device_id` to the local `storage.getOrCreateDeviceId()` — the server doesn't know which device the request came from.

KP-publish hook: `POST /api/keys/packages` already receives a `device_id`. The handler now:

1. `upsert_user_device(user_id, device_id, display_name_from_ua, kind_from_ua)` — on first publish, INSERT; on subsequent publishes, UPDATE `last_seen_at = now()`. The `display_name` and `kind` are not overwritten on subsequent calls (a user-set name in 6c+ would be preserved).
2. Continue with the existing KP storage path.

User-Agent parsing lives in `idp-e2ee::devices::parse_user_agent(ua: Option<&str>) -> (String, &'static str)`. Three buckets via simple substring checks — iOS/iPadOS heuristics for phone/tablet, default to laptop for everything else with a recognised browser, fall back to `("Web client", "unknown")` for missing UA. No new dependency.

### Client-side

New `DevicesEditor` mirrors the prototype's right-pane. New `IDeviceDirectoryPort` keeps the existing `IE2eePort` focused on crypto.

Component tree:

```
SettingsModal (existing, +1 section descriptor)
└── DevicesEditor (new — right-pane editor when activeSection === "devices")
    ├── Breadcrumb           "Settings › Devices"
    ├── Header               h1 "Devices." + "Pair new" button (disabled — 6c)
    ├── StatTiles            Active | Signed out | Recovery passphrase (3-up)
    ├── DeviceList           scrollable stack of <DeviceCard/> (new molecule)
    ├── RecoveryPassphraseCard  (new molecule, only when local passphrase stored)
    ├── Hint                 "Don't recognize a device? …"
    └── Footer               "Done" button (closes modal)
```

`DeviceCard` (new molecule): kind-icon tile, name + chips, last-seen + paired-at row, dashed fingerprint row with copy. `isCurrent` flag changes accent + button style; `revoked_at !== null` drops opacity to 0.55 and hides the "Sign out" button.

`RecoveryPassphraseCard` (new molecule): wraps the existing `RecoveryPassphraseDisplay` (from 6a) with a header row ("Show" / "Hide" toggle button, top-right) and a footer row with a destructive ghost "Clear recovery key" button. Default state is **blurred** (`filter: blur(8px)` + reduced opacity on the word grid). State is local to the component, not the viewmodel.

`RevokeDeviceDialog` (inline within `DevicesEditor`, no new molecule): uses the existing `Modal` + the FriendsPanel remove-friend pattern. Confirm copy: `"Sign out {name}? They'll be removed from your conversations and stop receiving new messages. This can't be undone."`. The current device shows the same dialog, but with a small note that signing out will end the local session.

`ClearRecoveryKeyDialog` (inline): same Modal pattern. Copy: `"Clear recovery key? You won't be able to recover this account on a new device unless you set up a new passphrase. This can't be undone."`.

Helpers (`presentation/_libs/`):

- `format-last-seen.ts` — `formatLastSeen(timestamp, revokedAt) → "Now" | "X min ago" | "X h ago" | "X days ago" | "Signed out DATE"`. Pure, unit-tested.
- `fingerprint.ts::fingerprintForDeviceId(deviceId: string) → string` — deterministic, base32 SHA-256 of the UUID, formatted as 25-char hyphenated groups. Not cryptographic, just a stable per-device identifier matching the prototype shape.

Port additions:

- `IE2eePort.getDeviceId(): Promise<string>` — wraps `storage.getOrCreateDeviceId()`. Used by the viewmodel to compute `isCurrent`.
- New `IDeviceDirectoryPort` (`domain/ports/device-directory.port.ts`):
  - `listDevices(idpUrl, accessToken): Promise<DeviceListResponse>`
  - `markRevoked(idpUrl, accessToken, deviceId): Promise<void>`
- New `DeviceDirectoryApiAdapter` in `adapters/device-directory/`. Registered in `ioc/init-adapters.ts`.

The existing `IE2eePort.revokeDevice` (the MLS Remove commits) stays in place — the new server endpoint only records the revocation flag for the directory view. Revoke orchestration in the viewmodel is: MLS commits → server mark_revoked → invalidate `useDevices`.

## Data flow

**Listing devices**:
1. `DevicesEditor` mounts → `useDevices()` hook fires.
2. `GET /api/keys/devices` (Bearer) → repo `list_user_devices(user_id)` → ordered list (active first).
3. Viewmodel resolves `getDeviceId()` once → maps `devices[i].is_current = devices[i].device_id === localId`.
4. Render.

**Recovery passphrase status + reveal**:
1. Viewmodel calls `loadStoredPassphrase()` on mount.
2. Result `null` → stat tile = "not saved", `<RecoveryPassphraseCard>` not rendered.
3. Result `string[24]` → stat tile = "saved", card rendered with words blurred by default.
4. User clicks "Show" → local state flip → blur removed.
5. User clicks "Clear" → confirm dialog → `port.clearRecoveryKey(idpUrl, token)` → invalidate the passphrase query → stat flips to "not saved", card disappears.

**Sign out another device**:
1. User clicks "Sign out" on a non-current row → confirm dialog.
2. On confirm:
   - For each conversation `IE2eePort.revokeDevice(idpUrl, token, ownActorUri, targetDeviceId, allConversationIds)` issues Remove commits.
   - `POST /api/keys/devices/:targetDeviceId/revoke` flags the row server-side.
   - Invalidate `useDevices` query.
3. The revoked row now appears in the "Signed out" bucket with reduced opacity.

**Sign out current device**:
1. User clicks "Sign out" on the current device row → confirm dialog (same component, copy mentions "this device").
2. On confirm:
   - `IE2eePort.revokeDevice(...)` with the current `device_id` — removes the local leaf from every group.
   - `POST /api/keys/devices/:id/revoke`.
   - `IE2eePort.wipeLocalDevice()` — clears the at-rest IDB so re-login lands on the onboarding flow.
   - `logoutUseCase(idpUrl, clearSession)` — redirects to the IdP `/logout`.

`useDevices` doesn't need to re-fetch in this case — the page is being navigated away.

## Edge cases

| Case | Handling |
|---|---|
| Legacy `device_id`s in `key_packages` predating the migration | Backfilled in the same migration: `INSERT ... SELECT DISTINCT device_id, ... FROM key_packages ... ON CONFLICT DO NOTHING`. |
| Missing `User-Agent` header on `/api/keys/packages` | `parse_user_agent(None) → ("Web client", "unknown")`. Same for unrecognised UAs. |
| Concurrent revoke clicks (two tabs) | Server: `UPDATE user_devices SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL` — second call is a no-op. Client: TanStack `invalidate` refreshes both tabs eventually. |
| Empty `display_name` or `kind = unknown` after backfill | UI fallbacks: name renders as the fingerprint's first segment, kind defaults to the laptop icon. |
| Revoked device shows fingerprint copy button? | Yes — fingerprint copy stays available for audit. Sign-out button is hidden, opacity drops to 0.55. |
| Network failure mid-revoke (MLS commits succeed, server mark fails) | Toast error + the row stays "active" in the list until the user retries. The MLS commits are already on the server's commit log so peers see the leaf as removed; the directory flag catches up on retry. |
| User explicitly cleared their recovery key, then opens Devices later | Stat tile shows "not saved", reveal card is hidden. No "set up a new one" CTA in 6b — adding that is a clean follow-up. |

## Testing

**Rust** (3 new specs):

- `parse_user_agent.spec` — six fixture UA strings (iPhone, iPad, Android, Firefox desktop, Chrome desktop, missing) → expected `(name, kind)` tuples.
- `repos::user_devices.spec` — upsert idempotency (`last_seen_at` advances on second call, `display_name` preserved), list ordering (active before revoked, then by `last_seen_at DESC`), `mark_revoked` is idempotent.
- Handler tests for `GET /api/keys/devices` (Bearer-only, foreign devices hidden, ordering) + `POST /api/keys/devices/:id/revoke` (own-device-only — 404 if `device_id` doesn't belong to caller).

**TypeScript** (3 new specs):

- `format-last-seen.spec.ts` — pure helper, covers Now / minutes / hours / days / revoked.
- `fingerprint-for-device-id.spec.ts` — deterministic, same UUID → same fingerprint, expected shape.
- `devices-editor.viewmodel.spec.ts` — in-memory `IDeviceDirectoryPort` + `IE2eePort` mocks, asserts revoke orchestration ordering (MLS commits → server mark_revoked → invalidate).

No new test infrastructure — same pattern as 6a's `bootstrap-first-device.spec.ts`.

## Out of scope (deferred)

- **"Pair new" button** wired up — the button renders disabled with a "Coming soon" tooltip; lights up in 6c.
- **User-editable device names** — display_name is auto-populated from UA only. A future "Rename this device" UX is a clean follow-up; the column is ready.
- **"Set up a new recovery passphrase" CTA** after Clear — would require a generate-and-display flow similar to onboarding. Deferred.
- **Inter-device "force sign out" notification** — the revoked device finds out next time it tries to use MLS state (peers' groups no longer include its leaf). No real-time WS push of "you've been signed out" in 6b.
- **Gate-time revocation check** — the onboarding gate doesn't check `user_devices.revoked_at` for the current device today. A signed-out device with intact local IDB still passes the gate. The MLS layer's leaf-removal is the real protection; adding a gate-time check is a defence-in-depth follow-up.

## File touch list

```
identity-provider/
├── migrations/20260514XXXXXX_user_devices.sql                               # new + backfill
├── crates/db/src/models/user_device.rs (or similar)                         # new struct
├── crates/db/src/repos/user_devices.rs                                      # new
├── crates/db/src/repos/mod.rs                                               # +user_devices
├── crates/e2ee/src/devices.rs                                               # parse_user_agent, list_handler, revoke_handler
├── crates/e2ee/src/packages.rs                                              # upsert + touch last_seen_at on POST /api/keys/packages
├── crates/e2ee/src/lib.rs                                                   # export new handlers
├── crates/server/src/router.rs                                              # +2 routes
└── tests/                                                                   # 3 new specs

web-client/
├── src/domain/ports/device-directory.port.ts                                # new
├── src/domain/models/device.ts                                              # DeviceListEntry, DeviceKind
├── src/adapters/device-directory/device-directory-api.adapter.ts            # new
├── src/ioc/init-adapters.ts                                                 # register new adapter
├── src/domain/ports/e2ee.port.ts                                            # +getDeviceId
├── src/adapters/e2ee/e2ee.adapter.ts                                        # +getDeviceId
├── src/presentation/_libs/fingerprint.ts                                    # fingerprintForDeviceId
├── src/presentation/_libs/format-last-seen.ts                               # formatLastSeen
├── src/presentation/hooks/useDevices.ts                                     # new TanStack Query hook
├── src/presentation/pages/home/SettingsModal/SettingsModal.tsx              # +section + right-pane branch
├── src/presentation/pages/home/SettingsModal/DevicesEditor/                 # new editor + viewmodel
│   ├── DevicesEditor.tsx
│   └── DevicesEditor.viewmodel.ts
├── src/presentation/molecules/DeviceCard/DeviceCard.tsx                     # new
├── src/presentation/molecules/RecoveryPassphraseCard/                       # new
│   └── RecoveryPassphraseCard.tsx
└── test/                                                                    # 3 new specs
```
