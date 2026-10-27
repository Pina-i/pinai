#!/bin/sh
# Fails, showing the difference, when the compose.yaml in README.md is not deploy/compose.yaml.
set -eu
cd "$(dirname "$0")/.."

marker='<!-- deploy/compose.yaml -->'

# The ```yaml block opening on the line after the marker; fails when there is none.
shown() {
  awk -v marker="$marker" '
    state == 0 && $0 == marker { state = 1; next }
    state == 1 { if ($0 != "```yaml") exit; state = 2; next }
    state == 2 && $0 == "```" { state = 3; exit }
    state == 2 { print }
    END { exit (state != 3) }
  ' README.md
}

if ! shown > /dev/null; then
  echo "README.md: no \`\`\`yaml block on the line after $marker" >&2
  exit 1
fi
if ! shown | diff -u deploy/compose.yaml -; then
  echo "README.md shows another compose.yaml than deploy/compose.yaml: copy the file into it" >&2
  exit 1
fi
