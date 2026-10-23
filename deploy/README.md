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
- An SMTP relay that accepts STARTTLS on port 587 (your provider's, Mailgun,
  SES, a Postfix of your own…): sign-up codes are mailed.

## Install

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
