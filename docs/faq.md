# FAQ

## What is Keyblind?

Keyblind is an encrypted secrets vault that integrates with AI coding tools via the Model Context Protocol (MCP). It stores API keys, tokens, and passwords in an AES-256-GCM encrypted SQLite database and resolves them at runtime — plaintext never appears in your LLM conversation transcript.

## How is this different from a .env file?

`.env` files are read by your code. When you paste code into an AI chat, the `.env` contents can leak. Keyblind keeps secrets in an encrypted vault and only resolves them when the AI needs them, keeping them out of the chat transcript entirely.

For local `.env` files, `keyblind sandbox` replaces real values with deterministic fakes that are safe to share with AI tools.

## How is this different from 1Password / Bitwarden?

Keyblind is **MCP-native**. It integrates directly with AI agents via the Model Context Protocol. 1Password and Bitwarden are human-facing password managers. Keyblind also supports using 1Password and Bitwarden as backends — so you can use both together.

## Is Keyblind open source?

Yes. MIT license. The full source is at [github.com/AndreaCatalucci/keyblind](https://github.com/AndreaCatalucci/keyblind).

## Where is my data stored?

By default, in `~/.keyblind/vault.db` — an AES-256-GCM encrypted SQLite database. Nothing leaves your machine. No cloud, no telemetry, no accounts.

## What happens if I lose my passphrase?

Your secrets are unrecoverable. The passphrase encrypts the vault key. There is no backdoor, no recovery email, no "forgot password" flow. **Write down your passphrase and store it securely.**

## Does Keyblind require a license key?

No. Keyblind is MIT licensed, local-first, and does not include activation, paid-tier gates, or phone-home license checks.

## Can I use Keyblind in CI/CD?

Yes. Use a local vault or one of the optional backend adapters available in your CI environment. Keyblind does not require a license key for private repositories.

## What MCP tools does Keyblind expose?

16 tools: `resolve_secret`, `store_secret`, `list_secrets`, `delete_secret`, `sandbox_env`, `unsandbox_env`, `audit_log`, `totp_code`, `totp_store`, `totp_list`, `totp_delete`, `create_share_link`, `receive_share`, `deadman_status`, `deadman_checkin`, `sso_status`.

## Does Keyblind support team vaults?

The current package includes local team-vault commands, but they are not tied to a paid tier or hosted admin service.

## How do I switch between backends?

```bash
keyblind config backend aws    # Use AWS Secrets Manager
keyblind config backend local  # Back to local vault
```

Run `keyblind backends` to see which backends are available.

## Is there a browser extension?

Yes. The Keyblind browser extension detects API keys in your clipboard and warns before pasting into AI chat sites (Claude.ai, ChatGPT, GitHub Copilot web). Available in the Chrome Web Store.

## Can I use Keyblind with non-MCP tools?

Yes. `keyblind get OPENAI_API_KEY` works as a standard CLI. You can use it in shell scripts, Makefiles, or anywhere you'd normally use environment variables.

## How do I report a security issue?

Email security@keyblind.dev. PGP key available on request. Do not open a public issue for security bugs.
