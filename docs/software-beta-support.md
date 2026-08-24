# Software beta support matrix

This matrix is frozen for `0.2.0-beta.1`.

| Operating system | Node.js | Status | Authorization |
|---|---:|---|---|
| macOS (`arm64`) | 24, 26 | Supported | Touch ID, then the interactive passphrase when needed |
| macOS (`x64`) | Any | Unsupported; install and stateful use fail closed | Not qualified |
| Linux glibc (`arm64`, `x64`) | 24, 26 | Supported | One interactive passphrase entry authorizes and unlocks |
| Windows | Any | Unsupported; install and stateful use fail closed | Not qualified |
| Other platforms | Any | Unsupported; stateful use fails closed | Not qualified |

Node 24 is the current LTS line. Node 26 is the current release line at beta qualification. Node 25 is end-of-life and excluded. The package engine range is exact: `24.x || 26.x`.

The package carries one N-API `better-sqlite3` prebuild for each supported OS-and-architecture pair and enforces their SHA-256 values. The same reviewed binaries cover Node 24 and 26. The Linux qualification is for glibc; Alpine and other musl environments fail closed outside the beta matrix. An explicit source build from the bundled reviewed sources requires a supported compiler toolchain and is recorded separately. Physical authorization qualification remains limited to the host architectures named in the release receipt.

Windows missed the qualification cutline because Unix modes do not prove NTFS ACL ownership and no Windows operator-authorization mechanism passed. The package declares only `darwin` and `linux`; npm returns `EBADPLATFORM` on a normal Windows install. A forced diagnostic install still rejects every stateful CLI command before creating the lifecycle database or vault directory.

Hardware mode is outside this matrix. `keyclasp doctor` is status-only and cannot enroll, decrypt, recover, or launch a secret-bearing child.
