#!/usr/bin/env bash
# Keyclasp Demo — self-running terminal script
# Usage: bash demo/run-demo.sh
# Record this terminal window with OBS/Screen Studio

set -e

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
CYAN=$'\033[0;36m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'
BOLD=$'\033[1m'

type_char() {
  # Simulate typing by printing character by character
  local text="$1"
  local delay="${2:-0.02}"
  for ((i=0; i<${#text}; i++)); do
    printf "%s" "${text:$i:1}"
    sleep "$delay"
  done
}

prompt() {
  printf "${GREEN}❯${NC} "
}

pause() {
  sleep "$1"
}

clear_section() {
  clear
  echo ""
}

# ─────────────────────────────────────────────────────
# SCENE 1: The Problem (0:00)
# ─────────────────────────────────────────────────────
clear_section
echo "${RED}${BOLD}Scene 1: The Problem${NC}"
echo ""

prompt; echo "cat .env"
sleep 0.3
cat demo/.env.real
echo ""

sleep 1.5

# ─────────────────────────────────────────────────────
# SCENE 2: Install & Init (0:15)
# ─────────────────────────────────────────────────────
clear_section
echo "${RED}${BOLD}Scene 2: Install & Init${NC}"
echo ""

prompt; echo "npm install -g keyclasp"
sleep 0.8
echo ""
echo "added 47 packages in 2.3s"
echo ""

prompt; echo "keyclasp init"
sleep 0.5
printf "Enter vault passphrase (or empty for machine-only key): "
sleep 1
echo ""
echo "🔑 Keyclasp vault created at ~/.keyclasp/"
echo ""

sleep 1.5

# ─────────────────────────────────────────────────────
# SCENE 3: Store Secrets (0:30)
# ─────────────────────────────────────────────────────
clear_section
echo "${RED}${BOLD}Scene 3: Store Secrets${NC}"
echo ""

prompt; echo 'echo "sk-proj-abc123xyz890" | keyclasp set OPENAI_API_KEY'
sleep 0.5
echo 'Stored "OPENAI_API_KEY"'
echo ""

prompt; echo "keyclasp set DATABASE_URL -"
sleep 0.5
printf "Enter value for DATABASE_URL: "
sleep 1
echo "********"
echo 'Stored "DATABASE_URL"'
echo ""

prompt; echo "keyclasp set STRIPE_SECRET -"
sleep 0.5
printf "Enter value for STRIPE_SECRET: "
sleep 0.8
echo "********"
echo 'Stored "STRIPE_SECRET"'
echo ""

prompt; echo "keyclasp list"
sleep 0.3
echo "  - DATABASE_URL"
echo "  - OPENAI_API_KEY"
echo "  - STRIPE_SECRET"
echo ""

sleep 1.5

# ─────────────────────────────────────────────────────
# SCENE 4: Sandbox (0:45)
# ─────────────────────────────────────────────────────
clear_section
echo "${RED}${BOLD}Scene 4: Sandbox${NC}"
echo ""

echo "${CYAN}# Before:${NC}"
echo '---'
prompt; echo "cat .env"
sleep 0.3
cat demo/.env.real
echo '---'
echo ""

prompt; echo "keyclasp sandbox"
sleep 0.5
echo "Sandboxed 3 value(s) in .env:"
echo "  - DATABASE_URL → fake (real value backed up to vault)"
echo "  - OPENAI_API_KEY → fake (real value backed up to vault)"
echo "  - STRIPE_SECRET → fake (real value backed up to vault)"
echo ""

echo "${CYAN}# After:${NC}"
echo '---'
prompt; echo "cat .env"
sleep 0.3
cat demo/.env.sandboxed
echo '---'
echo ""

sleep 2

# ─────────────────────────────────────────────────────
# SCENE 5: AI Agent Reads .env (1:05)
# ─────────────────────────────────────────────────────
clear_section
echo "${RED}${BOLD}Scene 5: AI Agent Sees Only Fakes${NC}"
echo ""

echo "${CYAN}# AI agent reads .env → sees only sandbox fakes:${NC}"
echo '---'
cat demo/.env.sandboxed
echo '---'
echo ""

echo "${CYAN}# But you can still run with real secrets:${NC}"
prompt; echo "keyclasp run -- npm test"
sleep 0.5
echo "  ✓ tests pass (3 secrets injected as env vars)"
echo ""

sleep 2

# ─────────────────────────────────────────────────────
# SCENE 6: Unsandbox & Restore (1:25)
# ─────────────────────────────────────────────────────
clear_section
echo "${RED}${BOLD}Scene 6: Unsandbox & Restore${NC}"
echo ""

prompt; echo "keyclasp unsandbox"
sleep 0.5
echo "Restored 3 value(s) in .env:"
echo "  - DATABASE_URL → real"
echo "  - OPENAI_API_KEY → real"
echo "  - STRIPE_SECRET → real"
echo ""

prompt; echo "cat .env"
sleep 0.3
cat demo/.env.real
echo ""

sleep 1.5

# ─────────────────────────────────────────────────────
# SCENE 7: TOTP & Sharing (1:40)
# ─────────────────────────────────────────────────────
clear_section
echo "${RED}${BOLD}Scene 7: TOTP Codes & Secret Sharing${NC}"
echo ""

echo "${CYAN}# Built-in 2FA code generation (zero deps):${NC}"
prompt; echo "keyclasp totp code github"
sleep 0.5
echo "  003486  (rotates in 22s)"
echo ""

echo "${CYAN}# Encrypted secret sharing (AES-256-GCM URL fragment):${NC}"
prompt; echo "keyclasp share DATABASE_URL --ttl 1h --max-views 1"
sleep 0.5
echo '  Share link (expires in 1h, 1 view remaining):'
echo '  keyclasp-share://v1.abc.def...'
echo ""

sleep 2

# ─────────────────────────────────────────────────────
# SCENE 8: Guarded Runtime (2:05)
# ─────────────────────────────────────────────────────
clear_section
echo "${RED}${BOLD}Scene 8: Secrets Only at Runtime${NC}"
echo ""
prompt; echo "keyclasp run -- npm test"
echo ""
echo "${GREEN}  Secrets injected into the child process · detected leaks are stopped${NC}"
echo ""

sleep 2

# ─────────────────────────────────────────────────────
# SCENE 9: Outro (2:20)
# ─────────────────────────────────────────────────────
clear_section
echo "${RED}${BOLD}Keyclasp v0.7.0 — Runtime Secrets for Coding Agents${NC}"
echo ""
echo "  Local encrypted vault · guarded commands · 7 backends"
echo ""
echo "  npm install -g keyclasp"
echo "  github.com/AndreaCatalucci/keyclasp"
echo ""
echo "  ${GREEN}MIT Licensed  ·  Zero Network  ·  Zero Telemetry${NC}"
echo ""

sleep 3
clear
