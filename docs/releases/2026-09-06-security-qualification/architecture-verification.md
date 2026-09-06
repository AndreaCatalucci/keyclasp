# KC-Q01 architecture verification

Status: **the three architecture views match frozen source `31aac732…`; overall qualification remains failed.**

| View | Diagram count | Inspected implementation | Result |
| --- | ---: | --- | --- |
| [`system-context.md`](../../architecture/system-context.md) | 1 | CLI, policy, vault, key bundle, file authority, recovery, software runtime, current user and agent guidance | Matched |
| [`software-vault-lifecycle.md`](../../architecture/software-vault-lifecycle.md) | 1 | CLI restore ordering, complete DB/WAL/SHM authority, authenticated journals, backup validation, custody sanitation, key retirement, lifecycle lock | Matched |
| [`operator-authorization.md`](../../architecture/operator-authorization.md) | 1 | runtime request boundary, helper preflight and minimal environment, Linux passphrase path, child supervision, independent output matchers | Matched, including the documented limitation when descendant termination cannot be confirmed |

The views keep these boundaries consistent:

- Software and hardware implementations share request/status contracts but do not share keys or secret plaintext. Hardware remains status-only.
- `vault.db`, `vault.db-wal`, and `vault.db-shm` form one SQLite live state, managed by the internal file authority.
- Emergency restore is authorized and authenticated before relying on damaged live state.
- Policy commits and custody sanitation are distinct durable phases; success waits for cleanup and record validation.
- Exact selection and required authorization precede selected-value decryption or child launch.
- macOS helper verification precedes stateful access and repeats immediately before authentication.
- Output matching is per stream and returns a nonzero leak result; the selected child remains trusted.

No implementation deviation required a diagram change. Only each verification basis was advanced to the frozen revision and candidate evidence.

The wider product-text gate did not pass. [`docs/faq.md`](../../faq.md) claims unsupported runtime versions fail before vault creation, but exact Node 22.23.2 installation and `init --machine-only` created a synthetic vault. The architecture views do not make that Node-version claim. A replacement candidate must either add fail-closed runtime enforcement or follow an explicit product decision that narrows the contract and updates every affected document.
