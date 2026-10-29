#!/bin/sh
# Fails when the tag ($1, if any) names neither idp-api's version nor a release candidate of it,
# or when deploy/compose.yaml's default image isn't idp-api's minor.
set -eu
cd "$(dirname "$0")/.."

tag=${1:-}
version=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "idp-api") | .version')

# NodeInfo reports idp-api's version.
case "$tag" in
  "" | "v$version" | "v$version"-*) ;;
  *)
    echo "::error::tag $tag, but idp-api is at $version"
    exit 1 ;;
esac

# The README shows deploy/compose.yaml, whose default image is the latest minor's;
# a release candidate's bundle is pinned to its own version.
case "$tag" in
  *-*) exit 0 ;;
esac
minor=${version%.*}
grep -qF "\${PINAI_VERSION:-$minor}" deploy/compose.yaml || {
  echo "::error::set PINAI_VERSION's default to $minor in deploy/compose.yaml, and copy the file into README.md"
  exit 1
}
