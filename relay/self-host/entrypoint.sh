#!/bin/sh
# Writes the relay's secrets where `wrangler dev` reads them, then runs the Worker locally.
# Sign-in is the shared ACCESS_KEY (no GitHub needed), GitHub's device flow, or both.
set -eu

fail() { echo "$1" >&2; exit 1; }

[ -n "${SESSION_SECRET:-}" ] || fail "SESSION_SECRET is not set (see .env.example)"
[ "${#SESSION_SECRET}" -ge 32 ] || fail "SESSION_SECRET must be at least 32 characters"

if [ -n "${ACCESS_KEY:-}" ]; then
  [ "${#ACCESS_KEY}" -ge 32 ] || fail "ACCESS_KEY must be at least 32 characters"
fi
if [ -n "${GITHUB_CLIENT_ID:-}" ] || [ -n "${GITHUB_CLIENT_SECRET:-}" ]; then
  [ -n "${GITHUB_CLIENT_ID:-}" ] && [ -n "${GITHUB_CLIENT_SECRET:-}" ] || fail "Set both GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET, or neither"
fi
[ -n "${ACCESS_KEY:-}" ] || [ -n "${GITHUB_CLIENT_ID:-}" ] || fail "Set ACCESS_KEY (private relay) or the GITHUB_CLIENT_* pair (see .env.example)"

umask 077
vars=self-host/.dev.vars
printf 'SESSION_SECRET="%s"\n' "$SESSION_SECRET" > "$vars"
[ -z "${ACCESS_KEY:-}" ] || printf 'ACCESS_KEY="%s"\n' "$ACCESS_KEY" >> "$vars"
[ -z "${GITHUB_CLIENT_ID:-}" ] || printf 'GITHUB_CLIENT_ID="%s"\nGITHUB_CLIENT_SECRET="%s"\n' "$GITHUB_CLIENT_ID" "$GITHUB_CLIENT_SECRET" >> "$vars"

exec /opt/wrangler/node_modules/.bin/wrangler dev \
  --config self-host/wrangler.selfhost.jsonc \
  --ip 0.0.0.0 --port 8787 \
  --persist-to /data \
  --show-interactive-dev-session=false
