# Core Surface Decisions

Date: 2026-07-09

## G3 Public API Contract

Future integrations should use the MCP stdio server as the stable product boundary. Package exports are retained for the local CLI, tests, and narrow library reuse around the vault, sandbox, config, backends, TOTP, sharing, sync, hooks, watch, auth, doctor, setup, and completions. They are not a broad extension SDK.

## U4 Distribution Surface Classification

| Surface | Current product promise | Maintenance/test evidence | Decision | Rationale |
| --- | --- | --- | --- | --- |
| `browser-extension/` | Chrome extension for paste interception on AI chat sites | Separate MV3 package and assets, no root build/test integration | Delete from core | Useful as a separate product, but not part of the local MCP vault kernel. |
| `vscode/` | Editor-specific extension | Separate package skeleton, no root build/test integration | Delete from core | MCP setup docs cover editor integration without shipping editor-specific code. |
| `vscode-extension/` | Duplicate editor-specific extension | Separate package skeleton, no root build/test integration | Delete from core | Duplicates MCP-first integration and increases maintenance surface. |
| `terraform-provider-keyblind/` | Terraform provider for managing Keyblind secrets | Separate Go module, not part of root tests | Delete from core | Terraform state stores secret values and does not serve the agent runtime secret-resolution loop. |
| `landing/` | Alternate landing page artifact | Static marketing artifact, not part of root build/test | Delete from core | The core package should not carry a second website surface. |

Deleted surfaces can be recreated from git history or split into separate repositories if they get a committed owner and product plan.

## U5 Optional Domain Classification

| Domain | Decision | Rationale | MCP parity action |
| --- | --- | --- | --- |
| TOTP/HOTP | Keep in core | Lets an agent complete 2FA-gated local workflows without exposing the seed. | Existing MCP coverage retained; safety metadata added in U7. |
| Secret sharing | Keep in core | Provides a local encrypted handoff path that avoids plaintext chat. | Existing MCP coverage retained; safety metadata added in U7. |
| Sync/history/rollback/expiry | Keep in core | Vault lifecycle recovery belongs close to the encrypted store. | U7 adds MCP parity for retained CLI actions. |
| External backends | Keep as optional adapters | Adapters are not part of default local/offline operation, but they support existing local developer workflows when configured explicitly. | U6/U7 expose safe backend status and configuration parity. |
| Alerts/webhooks | Delete from core | Outbound Slack/Discord notification delivery is not required by the local agent secret-resolution loop and adds network behavior. | None; removed from CLI and exports. |
