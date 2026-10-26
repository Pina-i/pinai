#!/bin/sh
# Prepares this directory for `docker compose up -d`: .env from .env.example with
# the instance's values and generated secrets, and ./data. Safe to run again: a
# value already in .env is kept. A value can also come from the environment
# (DOMAIN=chat.example.org ./setup.sh).
set -eu
cd "$(dirname "$0")"

if [ ! -f .env ]; then
  cp .env.example .env
  echo "created .env"
fi
chmod 600 .env

# The value of $1 in .env, unquoted.
current() {
  sed -n "s/^$1=//p" .env | tail -n 1 | sed -e "s/^'\(.*\)'\$/\1/" -e 's/^"\(.*\)"$/\1/'
}

# Sets $1 to $2 in .env, quoted so compose reads it back as typed.
store() {
  case "$2" in
    *[!A-Za-z0-9._:@/+-]*)
      case "$2" in
        *"'"*)
          case "$2" in
            *'"'* | *\\* | *'$'*)
              echo "$1 can't hold both ' and one of \" \\ \$ here: set it in .env by hand" >&2
              exit 1 ;;
          esac
          quoted="\"$2\"" ;;
        *) quoted="'$2'" ;;
      esac ;;
    *) quoted=$2 ;;
  esac
  # Renamed into place, so an interrupted run never leaves .env half-written.
  (
    umask 077
    KEY="$1" VALUE="$quoted" awk '
      BEGIN { k = ENVIRON["KEY"]; v = ENVIRON["VALUE"] }
      index($0, k "=") == 1 { if (!done) print k "=" v; done = 1; next }
      { print }
      END { if (!done) print k "=" v }
    ' .env > .env.tmp
  )
  mv .env.tmp .env
}

# Asks for $1 when neither .env nor the environment has it; $3 is the default,
# also taken when there is no terminal to answer.
ask() {
  [ -z "$(current "$1")" ] || return 0
  eval "value=\${$1:-}"
  if [ -z "$value" ]; then
    if [ -n "${3-}" ]; then printf '%s [%s]: ' "$2" "$3"; else printf '%s: ' "$2"; fi
    read -r value || { value=; echo; }
    value=${value:-${3-}}
  fi
  store "$1" "$value"
}

random_hex() {
  od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'
}

generate() {
  [ -z "$(current "$1")" ] || return 0
  store "$1" "$2"
  echo "generated $1"
}

valid_domain() {
  case "$1" in "" | *[!A-Za-z0-9.:-]*) return 1 ;; esac
}

if [ -z "$(current DOMAIN)" ]; then
  domain=${DOMAIN:-}
  until valid_domain "$domain"; do
    [ -z "$domain" ] || echo "  a bare host name, without scheme or path" >&2
    printf 'Domain of the instance (e.g. chat.example.org): '
    read -r domain || { echo; echo "DOMAIN is needed: run ./setup.sh in a terminal, or set it in .env" >&2; exit 1; }
  done
  store DOMAIN "$domain"
fi
domain=$(current DOMAIN)

ask SMTP_HOST "SMTP relay host (empty: no mail, sign-ups can't complete)"
if [ -n "$(current SMTP_HOST)" ]; then
  ask SMTP_PORT "SMTP port (587 for STARTTLS, 465 for TLS)" 587
  if [ -z "$(current SMTP_TLS)" ]; then
    case "$(current SMTP_PORT)" in
      465) store SMTP_TLS tls ;;
      *) store SMTP_TLS starttls ;;
    esac
  fi
  ask SMTP_USERNAME "SMTP username (empty: none)"
  if [ -n "$(current SMTP_USERNAME)" ] && [ -z "$(current SMTP_PASSWORD)" ]; then
    password=${SMTP_PASSWORD:-}
    if [ -z "$password" ]; then
      printf 'SMTP password: '
      if [ -t 0 ]; then stty -echo; fi
      read -r password || true
      if [ -t 0 ]; then stty echo; fi
      echo
    fi
    store SMTP_PASSWORD "$password"
  fi
  ask SMTP_FROM "Sender address" "Pīna'i <no-reply@${domain%%:*}>"
fi

generate JWT_KEY_ID "key-$(date +%Y-%m)"
generate SESSION_SECRET "$(random_hex 32)"
generate EMAIL_OTP_PEPPER "$(random_hex 32)"
generate POSTGRES_PASSWORD "$(random_hex 32)"
generate STORAGE_ACCESS_KEY "pinai-$(random_hex 8)"
generate STORAGE_SECRET_KEY "$(random_hex 32)"

mkdir -p data/keys data/postgres data/redis data/rustfs data/caddy/data data/caddy/config

[ -n "$(current SMTP_HOST)" ] || echo "warning: no SMTP relay in .env, so sign-up codes can't be mailed" >&2

cat <<EOF

Ready. Next:
  1. Point $domain's DNS (A / AAAA records) at this server; open ports 80 and 443.
  2. docker compose up -d
  3. docker compose logs -f idp     # "listening" once the database is migrated

Back up .env and ./data together: README.md says how.
EOF
