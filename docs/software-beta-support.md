# Software beta support matrix

This beta targets coding agents running on local developer machines.

Supported targets for the published `0.2.0-beta.2` software beta:

| Operating system | Node.js | Status | Authorization |
|---|---:|---|---|
| macOS (`arm64`) | 24, 26 | Supported | Touch ID, then the interactive passphrase when needed |
| macOS (`x64`) | Any | Unsupported; install and stateful use fail closed | Not qualified |
| Linux glibc (`arm64`, `x64`) | 24, 26 | Supported | One interactive passphrase entry authorizes and unlocks |
| Windows | Any | Unsupported; install and stateful use fail closed | Not qualified |
| Other platforms | Any | Unsupported; stateful use fails closed | Not qualified |

The package accepts Node.js `24.x || 26.x`. Other Node versions, Alpine/musl Linux, and platforms outside this table are unsupported. Install and stateful CLI checks reject unsupported environments before vault creation.

The package bundles SQLite native bindings for the supported OS/architecture pairs and verifies their SHA-256 hashes. Source builds require a supported compiler toolchain. See [installation](getting-started.md#install).

“Supported” describes the intended platform matrix, not completion of every physical trial. The published beta passed isolated macOS arm64/Node 26 machine-custody injection and output-leak checks. Physical Touch ID, Linux execution, and fresh-machine human onboarding remain unverified in this documentation pass. The macOS helper is ad hoc signed; Developer ID signing and notarization are not included.

Windows is unsupported because owner-only ACL handling and operator authorization have not been qualified.

Hardware mode is outside this matrix. `keyclasp doctor` is status-only and cannot enroll, decrypt, recover, or launch a secret-bearing child.
