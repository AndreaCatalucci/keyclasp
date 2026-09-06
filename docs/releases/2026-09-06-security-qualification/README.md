# KC-Q01 security qualification

Status: **not qualified; do not publish, globally install, or use for a production vault.**

KC-Q01 freezes source `31aac732317e40597eeee02695b019a2045228ad` and preserves one unpublished local candidate. Reproducible build and several security gates passed, but source acceptance, supported Linux signal handling, unsupported Node rejection, physical checks, and independent assurance remain open.

The [post-KC-Q01 blocker-remediation record](./blocker-remediation.md) documents later committed fixes and diagnostic checks. Those results do not change this candidate's failed receipt.

- [Qualification receipt](./KC-Q01-receipt.md)
- [Post-KC-Q01 blocker remediation](./blocker-remediation.md)
- [Build and provenance receipt](./build-provenance.md)
- [Architecture verification](./architecture-verification.md)
- [Physical and platform checklist](./physical-platform-checklist.md)
- [External assurance handoff](./external-review-handoff.md)
- [Operator migration and rollback runbook](./operator-migration-rollback-runbook.md)
- [Generated evidence inventory](./evidence/README.md)

The unpublished candidate remains owner-only in the local qualification directory. It is identified by path and hash in the receipt and is intentionally excluded from Git.

Historical audit and release evidence remains unchanged:

- [`2026-09-05` security audit](../../security/audits/2026-09-05/audit.md)
- [`0.2.0-beta.1` historical rc receipt](../0.2.0-beta.1-rc-receipt.md)
