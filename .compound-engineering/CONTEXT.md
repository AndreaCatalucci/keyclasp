# Keyblind — Project Context

## Fork Provenance

- **Upstream**: https://github.com/aarifmms/keyblind
- **Fork**: https://github.com/AndreaCatalucci/keyblind
- **License**: MIT — original copyright preserved in `LICENSE`
- **Upstream remote**: `upstream` → `https://github.com/aarifmms/keyblind.git`

## License Compliance

MIT License requires the original copyright notice and permission notice to be
included in all copies or substantial portions of the Software. The `LICENSE`
file at the repo root carries the original `Copyright (c) 2026 Keyblind` notice
and must be preserved through all changes.

When adding new files, include a short SPDX header:
```
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Keyblind
```

When substantially rewriting existing files, retain or update the copyright
line to reflect both original and new authorship:
```
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Keyblind, Andrea Catalucci
```

## Syncing with Upstream

```bash
git fetch upstream
git merge upstream/main
```