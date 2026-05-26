#!/bin/sh
set -e

# Auto-initialize vault for Glama/demo if not already initialized
KEY_FILE="$HOME/.keyblind/.keyblind.key"
if [ ! -f "$KEY_FILE" ]; then
  mkdir -p "$HOME/.keyblind"
  node docker-init.js
  echo "Vault auto-initialized for demo."
fi

exec node dist/cli.js start --http --port "${KEYBLIND_HTTP_PORT:-3100}"
