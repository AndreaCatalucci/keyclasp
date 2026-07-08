#!/usr/bin/env bash
# Keyblind Demo — self-running terminal script
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

prompt; echo "npm install -g keyblind"
sleep 0.8
echo ""
echo "added 47 packages in 2.3s"
echo ""

prompt; echo "keyblind init"
sleep 0.5
printf "Enter vault passphrase (or empty for machine-only key): "
sleep 1
echo ""
echo "🔑 Keyblind vault created at ~/.keyblind/"
echo ""

sleep 1.5

# ─────────────────────────────────────────────────────
# SCENE 3: Store Secrets (0:30)
# ─────────────────────────────────────────────────────
clear_section
echo "${RED}${BOLD}Scene 3: Store Secrets${NC}"
echo ""

prompt; echo 'echo "sk-proj-abc123xyz890" | keyblind set OPENAI_API_KEY'
sleep 0.5
echo 'Stored "OPENAI_API_KEY"'
echo ""

prompt; echo "keyblind set DATABASE_URL -"
sleep 0.5
printf "Enter value for DATABASE_URL: "
sleep 1
echo "********"
echo 'Stored "DATABASE_URL"'
echo ""

prompt; echo "keyblind set STRIPE_SECRET -"
sleep 0.5
printf "Enter value for STRIPE_SECRET: "
sleep 0.8
echo "********"
echo 'Stored "STRIPE_SECRET"'
echo ""

prompt; echo "keyblind list"
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

prompt; echo "keyblind sandbox"
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
prompt; echo "keyblind run -- npm test"
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

prompt; echo "keyblind unsandbox"
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
prompt; echo "keyblind totp code github"
sleep 0.5
echo "  003486  (rotates in 22s)"
echo ""

echo "${CYAN}# Encrypted secret sharing (AES-256-GCM URL fragment):${NC}"
prompt; echo "keyblind share DATABASE_URL --ttl 1h --max-views 1"
sleep 0.5
echo '  Share link (expires in 1h, 1 view remaining):'
echo '  keyblind-share://v1.abc.def...'
echo ""

echo "${CYAN}# Dead man's switch for team vaults:${NC}"
prompt; echo "keyblind deadman status"
sleep 0.3
echo "  Status: active | Check-in: 3 days ago | Deadline: 4 days"

sleep 2

# ─────────────────────────────────────────────────────
# SCENE 8: MCP Config (2:05)
# ─────────────────────────────────────────────────────
clear_section
echo "${RED}${BOLD}Scene 8: MCP Everywhere${NC}"
echo ""

cat << 'JSONEOF'
{
  "mcpServers": {
    "keyblind": {
      "command": "npx",
      "args": ["keyblind", "start"]
    }
  }
}
JSONEOF
echo ""
echo "${GREEN}  Claude Code · Cursor · Copilot · Windsurf · Cline · Zed${NC}"
echo ""

sleep 2

# ─────────────────────────────────────────────────────
# SCENE 9: Outro (2:20)
# ─────────────────────────────────────────────────────
clear_section
echo "${RED}${BOLD}Keyblind v0.6.0 — Blind AI to Your Keys${NC}"
echo ""
echo "  16 MCP tools · 7 backends · 40+ CLI commands"
echo ""
echo "  npm install -g keyblind"
echo "  github.com/AndreaCatalucci/keyblind"
echo ""
echo "  ${GREEN}MIT Licensed  ·  Zero Network  ·  Zero Telemetry${NC}"
echo ""

sleep 3
clear
