# KC-Q01 external assurance handoff

Status: **prepared, not commissioned.** No reviewer was contacted, and no agent review is represented as independent assurance.

## Review target

- Frozen source: `31aac732317e40597eeee02695b019a2045228ad`.
- Unpublished candidate SHA-256: `7fdf6c4fbd09a4e2d0e2d7203227ffa11f080658d58e379480f3761878042323`.
- Candidate path: local-only `candidate/KC-Q01-31aac732-7fdf6c4f-keyclasp-0.2.0-beta.1.tgz`; transfer requires a separately authorized owner-approved channel.
- Current verdict: not qualified. Known source, Linux signal, and unsupported-Node blockers are listed in [KC-Q01-receipt.md](./KC-Q01-receipt.md).

The reviewer may inspect KC-Q01 now, but assurance cannot be accepted for release while known blockers remain. Any source or artifact fix creates a replacement candidate and requires affected evidence to be repeated.

## Evidence package

- [KC-Q01 receipt](./KC-Q01-receipt.md), [build provenance](./build-provenance.md), and [generated evidence](./evidence/README.md).
- [Architecture verification](./architecture-verification.md) and the three linked current views.
- [`2026-09-05` audit](../../security/audits/2026-09-05/audit.md), its immutable receipt, and retained probes.
- [Canonical production-readiness plan](../../plans/2026-09-05-security-production-readiness-plan.md), including W2, W3, and KC-Q01 records.
- [Security model](../../security.md), [support matrix](../../software-beta-support.md), current command/help documentation, and historical rc receipt.

## Required review scope

1. Custody transitions, free-page/WAL/SHM remanence, authenticated defaults, sanitation restartability, machine-key retirement, and memory-limit claims.
2. SQLite writer exclusion, healthy versus damaged classification, complete file-set publication, authenticated pre/post operation states, repeated interruption, rollback evidence, and emergency restore.
3. Backup authorization and required-key selection, including machine-only, mixed, all-interactive, wrong-passphrase, cross-machine, and corrupt-live cases.
4. CLI ordering from platform/helper preflight through authorization, recovery, migration, selection, decryption, and mutation.
5. Streaming stdout/stderr matching for overlap, duplication, Unicode, EOF, child groups, signals, escalation, and privilege-changing descendants.
6. macOS helper path/owner/mode/ACL/hash/signature/designated-requirement checks, minimal environment, toolchain pinning, signing identity, and distribution boundary.
7. Package allowlist, public exports, bundled native source/prebuild verification, install scripts, dependency integrity, SBOM/licenses, reproducibility, and provenance.
8. Threat model and documentation: OS-user boundary, trusted child, metadata exposure, backup freshness/retention, snapshots, credential rotation, unsupported targets, and unavailable hardware.

## Required report shape

- Identify the exact source revision and candidate SHA-256 reviewed.
- State methods, environments, evidence sampled, and untested areas.
- Classify each finding by release impact, with reproduction and affected boundary.
- Keep historical failures visible.
- Do not claim absence of vulnerabilities or password-manager equivalence.
- Conclude whether any P1/P2 or equivalent release-blocking issue remains.

Acceptance requires no unresolved release-blocking finding against the final replacement source and artifact. A changed candidate requires a new report or an explicit reviewer addendum covering every affected gate.
