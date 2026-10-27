# Hosting a Pīna'i instance

This directory runs one instance from the published image: the identity provider,
Postgres, Redis, RustFS for files, and Caddy in front, which gets and renews the
TLS certificate. People use the official web or desktop app and sign in with
their address on your instance; there is no client to host.

## What you need

- A Linux server with Docker and the Compose plugin, 2.23.1 or later, amd64 or arm64.
- A domain for the instance, its DNS (A / AAAA records) pointing at the server, and
  ports 80 and 443 open. The domain is part of every account's address
  (`alice_xk9mp@your.domain`) and cannot change once people have signed up.
- For a public instance, an SMTP relay, over STARTTLS (port 587) or TLS (port 465):
  sign-up codes are mailed. See [Mail relay](#mail-relay).
- For an invite-only instance, the default, its first admin's address and password.
  See [Public or invite-only](#public-or-invite-only).

## Install

1. Get the bundle: `compose.yaml`, `.env.example` and this README.

   ```bash
   curl -L https://github.com/Pina-i/pinai/releases/latest/download/pinai-deploy.tar.gz | tar xz
   cd pinai
   ```

2. Write `.env` beside `compose.yaml`; `.env.example` lists every setting. An
   invite-only instance needs its domain and its first admin:

   ```sh
   DOMAIN=chat.example.org
   ADMIN_EMAIL=you@example.org
   ADMIN_PASSWORD='at least 8 bytes'
   ```

   A public instance needs its domain and a [mail relay](#mail-relay):

   ```sh
   DOMAIN=chat.example.org
   REGISTRATIONS=open
   SMTP_HOST=smtp.example.com
   SMTP_USERNAME=…
   SMTP_PASSWORD=…
   ```

   A value holding spaces, `#` or `$` goes in single quotes. The file holds
   passwords: `chmod 600 .env`.

3. Start it:

   ```bash
   docker compose up -d
   docker compose logs -f idp
   ```

At the first start, the `init` service generates the instance's secrets in
`./data/secrets` (see [Secrets](#secrets)), and Docker creates the rest of `./data`.
The identity provider migrates the database and logs `listening`. Caddy takes a few
seconds more for the certificate; then `https://your.domain/.well-known/nodeinfo`
answers. On an invite-only instance, sign in to the Pīna'i web app with
`ADMIN_EMAIL` and `ADMIN_PASSWORD`, then remove `ADMIN_PASSWORD` from `.env`.

Settings live in `.env`; after changing one, `docker compose up -d` applies it.

## Public or invite-only

An instance is public or invite-only, set by `REGISTRATIONS` in `.env`.

- **Public**, `REGISTRATIONS=open`: anyone can create an account. In the
  official Pīna'i app, they enter the instance's domain and sign up on the instance's
  own page, and a one-time code mailed to them confirms their email address. So a
  public instance needs a [mail relay](#mail-relay), with the domain of `SMTP_FROM`
  verified by the relay, or the codes land in spam. It refuses to start without
  `SMTP_HOST`: nobody could finish signing up.
- **Invite-only**, `REGISTRATIONS=invite`, the default: only people an admin invited can
  create an account. The invitation vouches for them, so no code is needed and the mail
  relay is optional. It refuses to start without an admin: nobody could ever get in.

| | Public | Invite-only |
|---|---|---|
| `REGISTRATIONS` | `open` | `invite`, the default |
| Who can create an account | Anyone | People an admin invited |
| A new account's address | Confirmed by a mailed code | Never confirmed by a code |
| Mail relay (`SMTP_*`) | Required | Optional |
| Admin (`ADMIN_EMAIL`, `ADMIN_PASSWORD`) | Optional | Required |
| NodeInfo `openRegistrations` | `true` | `false` |
| The sign-in page shows | "open registration" | "invite only" |

In both modes, members sign in with their email address. An address that came
with an invitation or from `ADMIN_EMAIL` is never confirmed by a code. Invite-only
is about who can join, not federation: members of an invite-only instance still
talk with people on other instances.

### The first admin

`ADMIN_EMAIL` and `ADMIN_PASSWORD` name the first admin. At each start, if no
account has that address, the instance creates an admin account named "Admin" with
that password. Sign in with them from the app, no code asked, and rename the
account there. The password needs at least 8 bytes: with a shorter one, the
account isn't created and the instance doesn't start.

- The instance never writes over an existing account's password, and never makes
  an existing account admin: the log warns when `ADMIN_EMAIL` names an account that
  isn't one.
- Once the account exists, `ADMIN_PASSWORD` is unused: remove it from `.env`. Each
  start logs a warning while it is there.
- A public instance needs no admin. It starts without one, and logs a warning at
  each start.
- An admin's password forgotten on a public instance: **Forgot password?** on the
  sign-in page, as for anyone.
- Lost admin access — the password forgotten, the mailbox gone: set `ADMIN_EMAIL`
  to an address no account has, and a new `ADMIN_PASSWORD`, then
  `docker compose up -d`. That creates another admin account beside the first.

### Inviting someone

Sign in to the official web app as an admin: Settings → **Instance** shows
**Invite someone**. It makes a link, `https://your.domain/i/<token>`: single-use,
valid 7 days, and revocable from the same screen while unused. Send it however you
like.

The person who opens it reads "You've been invited by <name> to join <instance>".
**Continue** leads to the instance's sign-up form: display name, email address,
password. When the instance knows the address of the Pīna'i web app
(`WEB_APP_ORIGIN` in `.env`), they then land in it, already signed in; otherwise a
page says their account is ready, and they sign in from the app. They can install
the desktop app later and sign in there with the same email and password.

Invitations belong to invite-only instances: on a public one, people create their
accounts themselves. Settings → **Instance**, where invitations and reset links are
made, is shown on invite-only instances only.

### A forgotten password

On a public instance, **Forgot password?** on the sign-in page mails a single-use
link to the account's address, valid 30 minutes. Setting the new password there signs
the account out everywhere; each device then signs in with the new password, and its
two-factor code when that is on. The page links to the web app when the instance knows
its address (`WEB_APP_ORIGIN`).

The instance mails at most 60 of these links at once, then one every 6 seconds, all
accounts together; an address with no account is never mailed. Limit each client at
the proxy in front if you need to.

On an invite-only instance, an admin creates a single-use reset link for the member
from Settings → **Instance**, `https://your.domain/r/<token>`, valid 24 hours, and
sends it to them. Setting the new password there signs the member out everywhere.

### Switching modes

Change `REGISTRATIONS` in `.env` — unset, it is `invite` —, then `docker compose up -d`.

- **Invite-only to public**: set up the mail relay first, since a public instance
  doesn't start without one. Accounts that joined by invitation keep signing in,
  without being asked to confirm their address.
- **Public to invite-only**: sign-up closes, and existing accounts keep signing in,
  except one that never confirmed its address: it still needs its code, and without a
  relay it is deleted a week after it was created. The instance needs an admin, as any
  invite-only one does.

## Mail relay

A public instance needs a relay, and doesn't start without one; for an invite-only
instance it is optional, and without `SMTP_HOST` the instance sends no mail.

The instance mails sign-up codes through a relay rather than delivering them
itself: mail sent straight from a server's own address mostly lands in spam,
when the host lets it out at all. A transactional relay handles a small
instance's mail within its free tier; it asks you to verify the domain of
`SMTP_FROM` with a few DNS records it gives you (SPF, DKIM), which is what gets
the codes delivered.

| Relay | `SMTP_HOST` | `SMTP_PORT` / `SMTP_TLS` | `SMTP_USERNAME` / `SMTP_PASSWORD` |
|---|---|---|---|
| Amazon SES | `email-smtp.<region>.amazonaws.com` | `587` / `starttls` | SMTP credentials created in the SES console, not IAM keys |
| Brevo | `smtp-relay.brevo.com` | `587` / `starttls` | the SMTP login and an SMTP key, from its SMTP & API settings |
| Mailgun | `smtp.mailgun.org` (`smtp.eu.mailgun.org` in the EU) | `587` / `starttls` | the sending domain's SMTP credentials |
| Postmark | `smtp.postmarkapp.com` | `587` / `starttls` | the server's API token, as both |
| Resend | `smtp.resend.com` | `465` / `tls` | `resend` / an API key |
| Gmail | `smtp.gmail.com` | `587` / `starttls` | the address / an app password |
| Fastmail | `smtp.fastmail.com` | `465` / `tls` | the address / an app password |

Unset, `SMTP_PORT` is 587, `SMTP_TLS` is `tls` on port 465 and `starttls` on any
other, and `SMTP_FROM` is `Pīna'i <no-reply@your.domain>`. A personal mailbox (Gmail,
Fastmail…) works for a small instance, within its sending limits; `SMTP_FROM` must
then be that mailbox's address. The provider's own documentation has the current
details.

On every start the identity provider connects to the relay, signs in and logs
`SMTP relay reachable`, or `SMTP relay unusable` with the reason; an invite-only
instance without a relay logs `no SMTP relay: mail is off` instead:

```bash
docker compose logs idp | grep SMTP
```

## Secrets

At each start, the `init` service generates in `./data/secrets` any secret missing
or empty there, and never replaces one: the instance key `ed25519.pem`, which signs
tokens, federation requests and device attestations, and `session_secret`,
`email_otp_pepper`, `storage_secret_key` and `postgres/password`. Each is written to
a temporary file, synced, then renamed, so a start cut short, even by a crash,
never leaves one half-written. A directory in a secret's place stops `init` with
"… is not a file".

Each container sees only what it needs:

| Container | Runs as | Reads |
|---|---|---|
| `idp` | 65532 | every secret, through `./data/secrets` |
| `rustfs` | 10001 | `storage_secret_key` only: the others are closed to it |
| `postgres` | root, then 999 | `postgres/password` only: its own directory is all it mounts |

The identity provider reads any variable of its configuration from a file as well,
`RUST_LOG` and `LOG_FORMAT` aside: `<VAR>_FILE` names the file, as
`SESSION_SECRET_FILE` does in `compose.yaml`. Setting both `<VAR>` and `<VAR>_FILE`,
or naming a file that is empty, larger than 64 KiB or unreadable, refuses the
start. Docker secrets, and the secrets other orchestrators mount as files, plug in
that way. `DATABASE_PASSWORD` is set on the connection over any password the
`DATABASE_URL` holds, so the URL stays readable and a password never needs
escaping. Postgres and RustFS read theirs from `POSTGRES_PASSWORD_FILE` and
`RUSTFS_SECRET_KEY_FILE`.

## Upgrade

`compose.yaml` runs the latest release of its minor version, 0.1 for instance. Its
fixes, and the other images' patch releases:

```bash
docker compose pull && docker compose up -d
```

For a new minor version, read its release notes and back up first: the database
is migrated on start, and going back to an older version is not supported. Then,
in this directory (v0.2.0 here):

```bash
curl -L https://github.com/Pina-i/pinai/releases/download/v0.2.0/pinai-deploy.tar.gz | tar xz --strip-components=1
docker compose pull && docker compose up -d
```

The archive replaces the bundle's own files (`compose.yaml`, `.env.example`,
`README.md`), never `.env` or `data/`: make again any change you had made to them,
Caddy's configuration included, which is the `configs:` block at the end of
`compose.yaml`. `PINAI_VERSION` in `.env` runs another version than the bundle's.

## Back up

Everything the instance holds is in `./data`: the database, the files, and in
`data/secrets` the instance key and the secrets, which cannot be regenerated — a
new key breaks every device that signed in, a new `email_otp_pepper` every recovery
code, a new `session_secret` every session. `.env` holds only what you typed: keep
a copy of it too.

```bash
docker compose stop
sudo tar --numeric-owner -czf pinai-$(date +%F).tar.gz .env data
docker compose start
```

`sudo`, because the services own their directories under `data/`. To restore,
unpack the archive with `sudo tar --numeric-owner -xzpf` into a copy of this
directory, then `docker compose up -d`.

## Behind your own reverse proxy

Remove the `caddy` service and its `configs:` block, publish the identity provider
and RustFS on loopback (`ports: ["127.0.0.1:8080:8080"]` on `idp`,
`["127.0.0.1:9000:9000"]` on `rustfs`), and route as Caddy's configuration in
`compose.yaml` does:

- `GET` and `HEAD` on `/avatars/*` to RustFS, without the query string;
- everything else to the identity provider, WebSockets (`/ws`) and server-sent
  events included, keeping the request's `Host` header: other instances sign it,
  so a rewritten one fails every federated request.

The proxy must terminate TLS for the domain: the instance only speaks HTTPS to
other instances, and its cookies are `Secure`.
