#!/usr/bin/env bash
# Starts a Monad-mode Anvil node and runs the integration test against it.
#
# Requires an official Foundry 1.8.0 or newer build with Monad support; a
# build without it fails at Anvil startup. Use ANVIL_BIN=/path/to/anvil to
# select a particular binary.
set -euo pipefail

cd "$(dirname "$0")/.."

ANVIL_BIN="${ANVIL_BIN:-anvil}"
ANVIL_PORT="${ANVIL_PORT:-$((20000 + RANDOM % 10000))}"
ANVIL_RPC_URL="http://127.0.0.1:${ANVIL_PORT}"
ANVIL_LOG="$(mktemp)"

if ! command -v "$ANVIL_BIN" >/dev/null; then
  echo "error: ${ANVIL_BIN} not found; install Foundry 1.8.0 or newer" >&2
  exit 1
fi

"$ANVIL_BIN" --network monad --hardfork MonadNine \
  --host 127.0.0.1 --port "$ANVIL_PORT" --quiet >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null || true; wait "$ANVIL_PID" 2>/dev/null || true; rm -f "$ANVIL_LOG"' EXIT

ready=""
for _ in $(seq 1 100); do
  if ! kill -0 "$ANVIL_PID" 2>/dev/null; then
    break
  fi
  if curl -sf -X POST -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
    "$ANVIL_RPC_URL" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.1
done

if [ -z "$ready" ]; then
  echo "error: Monad-mode Anvil did not start; is ${ANVIL_BIN} an official Foundry 1.8.0+ build with Monad support?" >&2
  cat "$ANVIL_LOG" >&2
  exit 1
fi

ANVIL_RPC_URL="$ANVIL_RPC_URL" bun test ./integration/anvil.ts
