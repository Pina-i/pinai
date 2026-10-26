# Hosting a Pīna'i instance

This directory runs one instance from the published image: the identity provider,
Postgres, Redis, RustFS for files, and Caddy in front, which gets and renews the
TLS certificate. People use the official web or desktop app and sign in with
their address on your instance; there is no client to host.

## What you need

- A Linux server with Docker and the Compose plugin, amd64 or arm64.
- A domain for the instance, its DNS pointing at the server, and ports 80 and 443
  open. The domain is part of every account's address (`alice_xk9mp@your.domain`)
  and cannot change once people have signed up.
- For a public instance, an SMTP relay, over STARTTLS (port 587) or TLS (port 465):
  sign-up codes are mailed. See [Mail relay](#mail-relay).
- For an invite-only instance, its first admin's address and password, set in
  `.env` before the first start. See [Public or invite-only](#public-or-invite-only).

## Install

For an invite-only instance, add its lines to `.env` after `./setup.sh` and before
`docker compose up -d`: see [Public or invite-only](#public-or-invite-only).

```bash
curl -L https://github.com/Pina-i/pinai/releases/latest/download/pinai-deploy.tar.gz | tar xz
cd pinai
./setup.sh            # asks for the domain and SMTP, generates the secrets
docker compose up -d
docker compose logs -f idp
```

The identity provider migrates the database and logs `listening`. Caddy takes a
few seconds more for the certificate; then `https://your.domain/.well-known/nodeinfo`
answers. Settings live in `.env` (see `.env.example`); after changing one,
`docker compose up -d` applies it.

## Public or invite-only

An instance is public or invite-only, set by `REGISTRATIONS` in `.env`.

- **Public**, `REGISTRATIONS=open`, the default: anyone can create an account. In the
  official Pīna'i app, they enter the instance's domain and sign up on the instance's
  own page, and a one-time code mailed to them confirms their email address. So a
  public instance needs a [mail relay](#mail-relay), with the domain of `SMTP_FROM`
  verified by the relay, or the codes land in spam. It refuses to start without
  `SMTP_HOST`: nobody could finish signing up.
- **Invite-only**, `REGISTRATIONS=invite`: only people an admin invited can create an
  account. The invitation vouches for them, so no code is needed and the mail relay
  is optional. It refuses to start without an admin: nobody could ever get in.

| | Public | Invite-only |
|---|---|---|
| `REGISTRATIONS` | `open`, the default | `invite` |
| Who can create an account | Anyone | People an admin invited |
| A new account's address | Confirmed by a mailed code | Never confirmed by a code |
| Mail relay (`SMTP_*`) | Required | Optional |
| Admin (`ADMIN_EMAIL`, `ADMIN_PASSWORD`) | Optional | Required |
| NodeInfo `openRegistrations` | `true` | `false` |
| The sign-in page shows | "open registration" | "invite only" |

The lines involved, in `.env`:

```sh
# Public: the default, with its relay (see Mail relay)
REGISTRATIONS=open
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_TLS=starttls
SMTP_USERNAME=…
SMTP_PASSWORD=…
SMTP_FROM="Pīna'i <no-reply@your.domain>"

# Invite-only
REGISTRATIONS=invite
ADMIN_EMAIL=you@example.com
ADMIN_PASSWORD='at least 8 bytes'
```

`./setup.sh` asks for the `SMTP_*` settings; an invite-only instance can leave them
empty. The other lines are added to `.env` by hand. A value holding spaces, `#` or
`$` goes in single quotes.

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
- Once the account exists, `ADMIN_PASSWORD` is no longer used: remove it from
  `.env`. Each start logs a warning while it is there.
- A public instance needs no admin. It starts without one, and logs a warning at
  each start.
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
password. Then they land in the Pīna'i web app, already signed in. They can install
the desktop app later and sign in there with the same email and password.

Invitations belong to invite-only instances: on a public one, people create their
accounts themselves, and Settings → **Instance** isn't shown.

### A forgotten password

An admin creates a single-use reset link for the member from Settings →
**Instance**, `https://your.domain/r/<token>`, valid 24 hours, and sends it to
them. Setting the new password there signs the member out everywhere.

### Switching modes

Change `REGISTRATIONS` in `.env`, then `docker compose up -d`.

- **Invite-only to public**: set up the mail relay first, since a public instance
  doesn't start without one. Accounts that joined by invitation keep signing in,
  without being asked to confirm their address.
- **Public to invite-only**: sign-up closes, and existing accounts keep signing in,
  except one that never confirmed its address: it still needs its code, and without a
  relay it is deleted a week after it was created. The instance needs an admin, as any
  invite-only one does.

## Mail relay

A public instance needs a relay, and doesn't start without one; for an invite-only
instance it is optional.

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

A personal mailbox (Gmail, Fastmail…) works for a small instance, within its
sending limits; `SMTP_FROM` must then be that mailbox's address. The provider's
own documentation has the current details.

On every start the identity provider connects to the relay, signs in and logs
`SMTP relay reachable`, or `SMTP relay unusable` with the reason:

```bash
docker compose logs idp | grep SMTP
```

## Upgrade

`PINAI_VERSION` in `.env` pins a minor version. Its fixes, and the other images'
patch releases:

```bash
docker compose pull && docker compose up -d
```

For a new minor version, read its release notes and back up first: the database
is migrated on start, and going back to an older version is not supported. Then,
in this directory (v0.2.0 here):

```bash
curl -L https://github.com/Pina-i/pinai/releases/download/v0.2.0/pinai-deploy.tar.gz | tar xz --strip-components=1
./setup.sh            # asks for, or generates, any setting the version adds
```

set `PINAI_VERSION=0.2` in `.env`, and pull and start as above. The archive
replaces the bundle's own files (`compose.yaml`, `Caddyfile`…), never `.env` or
`data/`: make again any change you had made to them.

## Back up

Everything the instance holds is in `.env` and `./data`, and they go together:
the instance key in `data/keys` and the secrets in `.env` cannot be regenerated —
a new key breaks every device that signed in, a new `EMAIL_OTP_PEPPER` every
recovery code.

```bash
docker compose stop
sudo tar --numeric-owner -czf pinai-$(date +%F).tar.gz .env data
docker compose start
```

`sudo`, because the services own their directories under `data/`. To restore,
unpack the archive with `sudo tar --numeric-owner -xzpf` into a copy of this
directory, then `docker compose up -d`.

## Behind your own reverse proxy

Remove the `caddy` service, publish the identity provider and RustFS on loopback
(`ports: ["127.0.0.1:8080:8080"]` on `idp`, `["127.0.0.1:9000:9000"]` on `rustfs`),
and route as `Caddyfile` does:

- `GET` and `HEAD` on `/avatars/*` to RustFS, without the query string;
- everything else to the identity provider, WebSockets (`/ws`) and server-sent
  events included, keeping the request's `Host` header: other instances sign it,
  so a rewritten one fails every federated request.

The proxy must terminate TLS for the domain: the instance only speaks HTTPS to
other instances, and its cookies are `Secure`.
