# Pina'i — Message attachments

DMs may carry up to 5 file attachments per message (50 MiB each by default).
Bytes live in a private `attachments` RustFS bucket that **never faces the
public network** — every byte the browser or a peer IdP sees is proxied
through this IdP. Authorization is the IdP's HMAC token (browser) or HTTP
Signatures (peer). Local and federated paths use the same client-facing API;
federation is server-mediated (option B from
`docs/plans/2026-05-05-message-attachments-design.md`).

## 1. Schema

```sql
CREATE TABLE message_attachments (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id            UUID REFERENCES direct_messages(id),
    uploaded_by_actor_uri TEXT NOT NULL,
    storage_key           TEXT NOT NULL UNIQUE,
    mime_type             TEXT NOT NULL,
    byte_size             BIGINT NOT NULL CHECK (byte_size > 0),
    original_filename     TEXT NOT NULL,
    -- Set for remote attachments — points at origin IdP's
    -- /api/attachments/{id}/content endpoint.
    remote_origin_url     TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

> **Cross-IdP id bridging**: `id` is shared across IdPs the same way
> `direct_messages.id` is. On a **local** upload the client supplies the
> UUID up front via the `attachment_id` multipart form field (it's also
> the AAD bound to the AES-GCM ciphertext, so it has to exist before
> the encrypt). On a **remote** ingress the receiver extracts the same UUID from the activity's `attachment.url`
> field of shape `<issuer>/api/attachments/<uuid>/content` and uses it
> as the local row id. An id is recorded once: a local upload naming an id
> that already exists is refused with `409`, never written over the existing
> row. Both IdPs therefore agree on `message_attachments.id`,
> which is what `AttachmentBlobKey.id` (carried in the encrypted MLS
> body) references — without this bridging the receiver's
> `attachmentKeys[a.id]` lookup misses and images render as a "FILE"
> tile because the decrypted MIME never reaches the renderer.

Lifecycle:
- `message_id IS NULL` ⇒ orphan (uploaded but not yet attached); reaped by
  background sweep after `attachment_orphan_ttl` (default 30 min).
- `message_id IS NOT NULL` ⇒ linked; lifetime tied to its message. When the
  message is hard-deleted (or future soft-deleted), the storage object is
  deleted and the row removed.
- Linked to one of the uploader's messages whose `federation_status` is
  `'failed'` ⇒ still claimable by that uploader: a `POST /api/dm` naming it
  moves it to the new message (`identity-provider/specs/direct-messages.md § 3`). The uploader keeps
  access to it from the failed row, since `GET /api/attachments/{id}` always
  admits the uploader.

## 2. API

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/attachments` | Bearer | Upload up to 5 multipart files; returns orphan IDs. An `attachment_id` already taken answers `409 conflict`. |
| `POST /api/dm` | Bearer | New `attachment_ids: [Uuid]` field — each an orphan, or linked to one of the caller's `'failed'` messages. Empty `content` is allowed iff `attachment_ids` is non-empty. |
| `GET /api/dm/{conv_id}` | Bearer | Each message gains `attachments: [{ id, mime_type, byte_size, original_filename }]`. |
| `GET /api/attachments/{id}` | Bearer | Returns `{ url, expires_at, mime_type, byte_size, original_filename }`. The `url` is a token-protected blob URL on this IdP. |
| `GET /api/attachments/{id}/blob?token=...` | HMAC token, under the attachment-link key (`identity-provider/specs/auth.md` § 1, The session cookie) | The actual fetch. Streams bytes through the IdP — local from the private object store, remote via a signed download from the origin (`specs/06-federation-authentication.md` § Peer request policy), cut off past the `byte_size` the origin announced. |
| `GET /api/attachments/{id}/content` | HTTP Signature (see `specs/06-federation-authentication.md`) | Peer-IdP-facing source of truth. Streams bytes through the IdP after a membership check (peer must have an actor in the conversation). |

Blob URL TTL: `attachment_url_ttl` (default 1 hour). Browser caches the bytes
once loaded; the URL only needs to live until first fetch. `<img onError>` /
`<a onError>` should re-call `GET /api/attachments/{id}` to refresh on
expiry.

Headers on the blob response:
- `X-Content-Type-Options: nosniff`
- `Content-Disposition: attachment; filename="…"`
- `Content-Type: <verified MIME>`
- `Content-Length: <byte_size>` (when the object store reports a non-negative length)

> **No presigned URLs cross the public network.** An earlier design used
> `302` redirects to a presigned RustFS URL but that exposed the object
> store to the browser, leaked URLs via browser history/network logs, and
> bypassed the IdP's HMAC token as the actual authorization layer. The
> store now stays on the private network in every path.

## 3. Federation wire format

`Note.attachment` is a standard ActivityPub array of `Document` objects:

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

`url` points at the origin IdP's HTTP-Signature-protected `/content` endpoint.
The recipient IdP persists a `message_attachments` row with `remote_origin_url`
set to that URL — bytes are not fetched at inbox time, only on first read.

The recipient later fetches that URL as itself, so it only accepts the
sender's own content endpoint: the same scheme and host as the sender's actor,
and the path `/api/attachments/<uuid>/content`. Any other `url` is dropped and
the message is recorded without that attachment — otherwise a peer could point
the recipient at any address, private ones included. `size` becomes the row's
`byte_size`, and a read stops once that many bytes have arrived.

## 4. Validation

- File count: ≤ `attachment_max_files_per_message` (default 5).
- File size: ≤ `attachment_max_byte_size` (default 50 MiB).
- Extension blocklist (extends built-in list of common executables).
- MIME blocklist (extends built-in list).
- Built-in lists cannot be removed via env — only extended (defense in depth).

## 5. Configuration

```env
ATTACHMENT_MAX_FILES_PER_MESSAGE=5
ATTACHMENT_MAX_BYTE_SIZE=52428800
ATTACHMENT_URL_TTL_SECS=3600
ATTACHMENT_ORPHAN_TTL_SECS=1800
ATTACHMENT_BLOCKED_EXTENSIONS=    # comma-separated, additive
ATTACHMENT_BLOCKED_MIMES=          # comma-separated, additive
```

## 6. Out of scope (deferred)

- Caching of remote bytes (Bob's IdP re-fetches each time; ADR follow-up).
- Edit/replace of attachments after delivery — attachments are immutable
  post-`Create`.
- Image thumbnails / preview generation.
- Magic-byte file-type sniffing as a second validation layer.

See `docs/plans/2026-05-05-message-attachments-design.md` for the full design.
