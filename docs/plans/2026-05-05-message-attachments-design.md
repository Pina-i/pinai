# Message Attachments — Design

- **Status**: Approved (design complete, ready for implementation plan)
- **Date**: 2026-05-05
- **Author**: Kilian
- **Scope**: file attachments on direct messages, end-to-end (upload, send,
  read, federate, GC).

## Context

Direct messages today carry a single `content TEXT` field. The CLAUDE.md
workspace structure already provisions a separate `attachments` storage bucket
in `idp-storage::StorageConfig`, but it is never initialized and no other
attachment code exists. The avatar handler (`crates/auth/src/avatar.rs`)
provides a working pattern for "validate → upload to RustFS → persist URL in
DB", but its model is too narrow for DM attachments: avatars are
public-readable, single-object-per-user, and unfederated, while DM attachments
must be private, multi-per-message, and federated.

## Decisions (from brainstorming)

| Question | Decision |
|---|---|
| Privacy model | Bucket private; access via short-lived presigned URLs. |
| Single vs multi | Multi — separate `message_attachments` table. |
| Federation scope | Federated (option B): server-side proxy with HTTP-Signature auth between IdPs. |
| MIME policy | Default-allow with extension + MIME blocklists for executables. SVG allowed but served with correct MIME and `X-Content-Type-Options: nosniff`. |
| Limits | 5 files per message, 50 MB per file. |
| Browser fetch | `Content-Disposition: attachment` by default; `X-Content-Type-Options: nosniff`. |
| URL TTL | 1 hour, configurable via `ATTACHMENT_URL_TTL_SECS`. |
| Caching of remote bytes | Deferred — Bob's IdP re-fetches Alice's attachments on demand for v1. |

## API surface

### `POST /api/attachments` — upload (Bearer auth)

Multipart/form-data, up to 5 files. Returns metadata for the orphans, which
the client then references in `POST /api/dm`.

Validation order, fail-fast:

1. Authenticate.
2. Reject if more than `attachment_max_files_per_message` parts (`400`).
3. For each part:
   1. Read up to `attachment_max_byte_size`; reject `413` if exceeded.
   2. Reject `415` if `original_filename`'s extension is in the blocklist.
   3. Reject `415` if `Content-Type` is in the MIME blocklist.
4. Begin DB transaction. For each accepted file insert a `message_attachments`
   row (`message_id = NULL`) and call `storage.upload_attachment`. Roll back +
   best-effort cleanup if any upload fails.
5. Commit. Return `{ attachments: [{ id, mime_type, byte_size, original_filename }] }`.

### `POST /api/dm` — modified

Body adds `attachment_ids: Vec<Uuid>`. New rules:

- `content` may be empty iff `attachment_ids` is non-empty.
- Each ID: row must exist with `message_id IS NULL` and
  `uploaded_by_actor_uri == sender's actor_uri`. Else `400 invalid_attachment`.
- After inserting the message, atomically `UPDATE message_attachments SET
  message_id = $new_msg WHERE id = ANY($ids)` in the same transaction.

### `GET /api/dm/{conv_id}` — modified response

Each message gains an `attachments: [{ id, mime_type, byte_size,
original_filename }]` field. Just metadata — no URLs in list responses.

### `GET /api/attachments/{id}` — fetch URL (Bearer auth)

Auth + access check:

- Caller is the `uploaded_by_actor_uri` of the row, OR a member of the
  conversation that contains the linked message.
- If `message_id IS NULL` and caller is not the uploader: `403`.
- If the linked message has `deleted_at IS NOT NULL`: `404`.

Response:
```json
{
  "url": "https://idp.bob.com/api/attachments/<id>/blob?token=<hmac>",
  "expires_at": "...",
  "mime_type": "image/png",
  "byte_size": 91244,
  "original_filename": "screenshot.png"
}
```

The URL points to *this* IdP's blob endpoint regardless of whether the
attachment is local or remote — the blob endpoint handles the dispatch.

### `GET /api/attachments/{id}/blob?token=...` — bytes (token auth)

Token is HMAC-SHA256 over `(attachment_id, user_id, expires_at)` using
`Config::session_secret`. Default TTL 1 hour, configurable via
`ATTACHMENT_URL_TTL_SECS`.

Behavior:

- Local attachment (`remote_origin_url IS NULL`): `302` to a fresh 5-min
  RustFS presigned URL with response-header overrides
  (`response-content-type`, `response-content-disposition=attachment`).
- Remote attachment: HTTP-Signature `GET` against `remote_origin_url`, follow
  the upstream `302`, stream the bytes back through this IdP. Adds
  `X-Content-Type-Options: nosniff` and `Content-Disposition: attachment` on
  the streamed response.

### `GET /api/attachments/{id}/content` — peer IdPs (HTTP-Signature auth)

The peer-facing endpoint that ActivityPub `Note.attachment.url` points to.

1. Verify HTTP signature.
2. Resolve `keyId` host → peer IdP's actor URI.
3. Look up attachment. If `remote_origin_url IS NOT NULL`, return `404` (we
   are not authoritative).
4. Verify the requesting peer's actors are conversation members.
5. `302` to a fresh RustFS presigned URL with the same response-header
   overrides.

## Schema

Migration `20260505000001_message_attachments.sql`:

```sql
CREATE TABLE message_attachments (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id            UUID REFERENCES direct_messages(id),
    uploaded_by_actor_uri TEXT NOT NULL,
    storage_key           TEXT NOT NULL UNIQUE,
    mime_type             TEXT NOT NULL,
    byte_size             BIGINT NOT NULL CHECK (byte_size > 0),
    original_filename     TEXT NOT NULL,
    -- For remote attachments: stable URL on the origin IdP serving the bytes
    -- under HTTP-Signature auth. NULL for local attachments.
    remote_origin_url     TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_message_attachments_orphan
    ON message_attachments (created_at)
    WHERE message_id IS NULL;

CREATE INDEX idx_message_attachments_message_id
    ON message_attachments (message_id)
    WHERE message_id IS NOT NULL;
```

Notes:

- `storage_key` is always `id::text`. For local attachments it identifies the
  RustFS object; for remote rows the column is filled for consistency but no
  object exists in our bucket.
- No `deleted_at`. Attachment rows are hard-deleted with their objects.
- No `ON DELETE CASCADE`. Messages soft-delete only; the FK exists for
  integrity, not eviction.

## Storage layer

`crates/storage/src/client.rs` gains:

```rust
pub async fn upload_attachment(
    &self, storage_key: &str, data: Vec<u8>, content_type: &str,
) -> Result<(), StorageError>;

pub async fn delete_attachment(&self, storage_key: &str)
    -> Result<(), StorageError>;

pub async fn presign_attachment_get(
    &self,
    storage_key: &str,
    mime_type: &str,
    original_filename: &str,
    ttl: Duration,
) -> Result<String, StorageError>;
```

`ensure_buckets()` initializes both buckets — `avatars` public-read (today),
`attachments` private (no policy, no ACL). Object keys are bare UUIDs; MIME
and original filename are reapplied via the presigned URL's response-header
overrides (`response-content-type`, `response-content-disposition`). RustFS is
configured (or, if needed, queried at startup) to honor these S3 query
parameters.

## ActivityPub federation

### Outbound

When `messaging::send_message` (or any path that creates a federated DM)
builds the `Create{Note}` activity, attachments are appended to
`Note.attachment` as standard `Document` objects:

```json
"attachment": [
  {
    "type": "Document",
    "mediaType": "application/pdf",
    "url": "https://idp.alice.com/api/attachments/<uuid>/content",
    "name": "report.pdf",
    "size": 482012
  }
]
```

`url` is the stable HTTP-Signature-protected `/content` endpoint, not a
presigned RustFS URL — presigned URLs expire, AP activities don't.

### Inbound (`federation::inbox::handle_create`)

When `Note.attachment` is a non-empty array, for each entry:

1. Validate: `type == "Document"`, all required fields present, `size > 0`,
   `size <= attachment_max_byte_size`, MIME passes the blocklist.
2. Insert a `message_attachments` row with `message_id` set, `remote_origin_url`
   set to the AP `url`, `uploaded_by_actor_uri` set to the AP
   `Note.attributedTo`. No bytes are fetched.
3. If validation fails for an entry, persist the message without that
   attachment and log a warning. Don't reject the whole DM.

## Lifecycle and garbage collection

| Event | Storage object | DB row |
|---|---|---|
| Upload | written | inserted, `message_id = NULL` |
| Linked | unchanged | `message_id` set |
| Orphan TTL expires (`message_id IS NULL` for > 30 min) | deleted | row deleted |
| Parent message soft-deleted | deleted | row deleted |
| Remote attachment received via inbox | none | inserted with `remote_origin_url` |

### Orphan sweep

New module `crates/messaging/src/orphan_sweep.rs`. Spawned from
`server/main.rs` alongside the presence sweepers. Every 5 minutes, selects
orphan rows older than `attachment_orphan_ttl` (default 30 min), deletes the
RustFS object, deletes the DB row. Errors logged, loop continues.

### Message soft-delete

`messaging::handlers::delete_message` and the AP `Delete` inbox path load the
message's attachments and, before setting `deleted_at`:

- Local row: `storage.delete_attachment(storage_key)`, then `DELETE FROM
  message_attachments WHERE id = $1`.
- Remote row: just delete the row.

Storage failures are logged but do not block the message delete; the orphan
sweep is the safety net.

## Config (`crates/config/src/lib.rs`)

```rust
pub attachment_max_files_per_message: usize,    // default 5
pub attachment_max_byte_size:         u64,      // default 50 * 1024 * 1024
pub attachment_url_ttl:               Duration, // default 3600s (1h)
pub attachment_orphan_ttl:            Duration, // default 1800s (30m)
pub attachment_blocked_extensions:    Vec<String>,
pub attachment_blocked_mimes:         Vec<String>,
```

Env vars:

- `ATTACHMENT_MAX_FILES_PER_MESSAGE` (default `5`)
- `ATTACHMENT_MAX_BYTE_SIZE` (default `52428800`)
- `ATTACHMENT_URL_TTL_SECS` (default `3600`)
- `ATTACHMENT_ORPHAN_TTL_SECS` (default `1800`)
- `ATTACHMENT_BLOCKED_EXTENSIONS` (comma-separated, *extends* built-in list)
- `ATTACHMENT_BLOCKED_MIMES` (comma-separated, *extends* built-in list)

Built-in blocklists (extension and MIME) cover the obvious executable shapes:

```
ext:  exe sh bat cmd com ps1 vbs js wsf hta scr pif lnk app dmg pkg
      msi msix deb rpm AppImage jar war dll so dylib
mime: application/x-msdownload application/x-msdos-program
      application/x-executable application/x-sh application/x-mach-binary
      application/vnd.microsoft.portable-executable
```

Env-provided lists *extend* the built-ins so a misconfigured empty value
cannot accidentally allow `.exe`.

## Crate-by-crate change inventory

- **`crates/storage`** — three new methods, private bucket policy.
- **`crates/db`**
  - new repo `repos/attachments.rs`
  - new model `Attachment` in `models.rs`
  - new migration `20260505000001_message_attachments.sql`
- **`crates/config`** — new fields + parsing.
- **`crates/messaging`**
  - amend `send_message` (validate + link `attachment_ids`).
  - amend `get_conversation` and `list_conversations` response shape.
  - new module `attachments.rs` for `POST /api/attachments` and
    `GET /api/attachments/{id}`.
  - new module `blob.rs` for `GET /api/attachments/{id}/blob` + HMAC token type.
  - new module `orphan_sweep.rs` for the GC task.
  - amend `delete_message` to clean up local attachments.
- **`crates/federation`**
  - `inbox::handle_create` parses `attachment` array.
  - new handler `attachments.rs::get_attachment_content` for the peer-facing
    `/api/attachments/{id}/content`.
- **`crates/server/src/router.rs`** — four new routes.
- **`crates/server/src/main.rs`** — spawn `run_orphan_sweep`.
- **`specs/03-direct-messages.md`** — new "Attachments" section.

## Out of scope for v1 (deferred)

- Caching of remote attachment bytes on the receiving IdP. v1 re-fetches every
  time. ADR follow-up if it becomes a perf concern.
- Retry queue / circuit breaker if `remote_origin_url` is unreachable. v1
  returns `502` and the client shows a broken-image icon.
- Federated edit / replace of attachments after delivery. Attachments are
  immutable across the federation post-`Create`.
- Image thumbnails / preview generation. Clients render originals.
- Magic-byte file-type sniffing as a second validation layer (defense in depth
  against MIME spoofing).
- Per-attachment revocation. Lifecycle is tied to the parent message.

## Web-client work (separate repo)

- Multipart upload UI for `POST /api/attachments`.
- Lazy URL fetch via `GET /api/attachments/{id}` per render of an attachment.
- `<img onError>` / `<a onError>` retry pattern: refetch metadata when the
  URL goes stale (TTL expiry mid-session).

## References

- ADR-0001 (bounded contexts). Attachments live in `messaging`; federation
  wire format and inbox parsing live in `federation`. The split is consistent
  with that ADR.
- `specs/03-direct-messages.md` — to be updated alongside implementation.
- ActivityPub spec `Note.attachment` — the wire format we conform to.
