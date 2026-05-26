#!/bin/sh
set -e

# Auto-initialize vault for Glama/demo if not already initialized
if [ ! -f /root/.keyblind/.keyblind.key ]; then
  mkdir -p /root/.keyblind
  node docker-init.js
  echo "Vault auto-initialized for demo."
fi

exec node dist/cli.js start --http --port "${KEYBLIND_HTTP_PORT:-3100}"
