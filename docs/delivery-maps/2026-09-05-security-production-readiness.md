# Keyclasp security remediation and production readiness

Outcome: repair every finding in the 2026-09-05 audit, establish safe credential-custody behavior, and qualify the resulting software artifact for a clearly stated production threat model. Software implementation, physical/platform qualification, independent professional assurance, and operator rollout have separate completion evidence. Hardware custody remains unavailable unless separately chosen and qualified.

State: **approval**. KC-P01 is verified as the remediation plan after coordinator inspection and correction. KC-W01 (Slice 1 backup/recovery implementation) is proposed and awaits approval of the displayed prompt/settings. No implementation executor is active and no remediation is complete.

## Basis and existing plans

- Audit: `docs/security/audits/2026-09-05/audit.md`; exact source hashes and results: `docs/security/audits/2026-09-05/receipt.json`; three synthetic probe files in the same directory.
- Current source revision: `d94189b30fb5e52ee5f4eb6435e96fe865c13142`. On coordination setup, every source hash in the audit receipt still matched. Application source is unchanged; the audit directory is untracked local input.
- Existing plan: `docs/plans/2026-08-23-001-software-beta-and-optional-hardware-mode-plan.md`. Slices 1–4 contain historical acceptance/qualification records. Those records remain historical; they cannot establish production readiness against the newly demonstrated custody, masking, and recovery failures. Slice 5 hardware work remains deferred.
- Required remediation plan: `docs/plans/2026-09-05-security-production-readiness-plan.md`, verified by coordinator inspection after targeted corrections; SHA-256 `fcda1b545e140e893b1eafb71bd3ae4c7f277e14184904926bb5baa500524520`. Four slices remain planned: S1 recovery, S2 custody/defaults, S3 output/helper, S4 qualification/assurance/rollout.
- Existing hardware GA plans/checklist remain background context. They do not authorize enabling hardware custody or force unrelated hardware work into the software repair path.

## Behaviors and evidence

“Verified failure” means the coordinator inspected or reproduced a failing behavior. It is not a completed delivery criterion. No successful remediation evidence exists yet.

| Scope | Current evidence | Plan coverage / closure condition |
| --- | --- | --- |
| F1: tightening custody removes decryptable old machine representations | Verified failure: fresh process recovered 50 of 500 locked records from post-lock SQLite free space | S2 planned: crash-consistent custody cleanup, sidecars, historical-copy limitations, and fresh-process forensic acceptance |
| F2: exact selected secrets cannot escape default output masking | Verified failure: self-overlapping synthetic value escaped intact with exit 0 | S3 planned: streaming match semantics and real-child/property regressions |
| F3: restore publishes exactly the authenticated snapshot | Verified failure: old live WAL replayed after successful restore | S1 planned: complete SQLite-state handling, consistent rollback image, and post-publication validation |
| F4: interrupted recovery can itself recover | Verified failure: interruption during rollback makes next recovery reject an already-restored file | S1 planned: restartable rollback and fault injection within recovery |
| F5: valid authorized backup can replace corrupt live custody state | Verified failure: CLI fails before restore, while library succeeds | S1 planned: emergency CLI dispatch without weakening backup authentication or ordinary startup recovery |
| F6: supported machine-only backup succeeds after operator authorization | Verified source/wrapper failure; physical macOS flow not exercised | S1 planned: required-key selection and CLI/wrapper coverage; S4 physical qualification |
| Safe storage defaults and explicit unattended use | Verified current behavior: passphrase enrollment leaves new records machine-class | S2 planned: interactive default, explicit machine use, legacy compatibility, and accurate help/status |
| Software trust boundary and helper hardening | Verified documented same-user exclusion; helper injection proof is defense-in-depth evidence, not interactive-key compromise | S3 planned: bounded helper environment/signing improvements and honest trusted-child/policy limits |
| Memory lifetime, rollback, retained backups and credential rotation | Documented limitations; no hostile-process or universal secure-erasure proof | S2 planned: owned-buffer cleanup and residual-risk/rotation guidance; S4 operator decisions |
| Reproducible qualification and package integrity | Source suite 474 pass, 2 skip, 1 fail; helper linker differs 27037.0/27037.1; dependency audit zero known advisories | S3 toolchain hardening and S4 exact-artifact/platform checks planned; retain failed evidence |
| Physical macOS and Linux authorization/recovery of final artifact | Blocked: no current final artifact or new physical/platform receipts | S4 names exact-artifact checks and operator/platform dependencies |
| Independent professional assurance | Blocked: not performed; this source audit is not certification | Prepare reviewable evidence and scope locally; external engagement is an explicit later dependency |
| Operator production rollout | Blocked: no approved final candidate, migration/backup receipt, or rollout authorization | Prepare safe migration/rollback/runbook and artifact handoff; actual vault mutation/publication belongs to the operator |

## Architecture

Starting artifact: `docs/architecture/operator-authorization.md`, an authorization flow with a historical rc6 verification basis. It is not a complete current Context/Container inventory. Its historical claims must not be silently relabeled as verified at the repaired revision.

The verified plan assigns `software-vault-lifecycle.md` to S1, `system-context.md` to S2, `operator-authorization.md` updates to S3, and final implementation verification of all three to S4. Each file has one Mermaid block. Intended deltas cover custody tightening and defaults, SQLite lifecycle/recovery, required-key authorization, and the helper process boundary. Preserve software/hardware separation, application-owned validation/authorization, trusted-child semantics, explicit scope, and the disabled hardware path. Diagrams are current-state evidence only after inspection against the final implementation.

## Frontier and decisions

KC-W01 is ready for S1. S2 depends on its SQLite lifecycle implementation. S3 is independent in code, but shares the canonical plan write scope, so it will run serially unless ownership is explicitly reassigned. S4 follows all implementation slices. No other packet is proposed or active.

The requested production outcome authorizes preparation of local fixes and verification. KC-P01 is planning-only. Production vault access/mutation, secrets, paid services, external messages, Git mutation, publication, installation into the operator environment, and hardware enrollment are not authorized by this packet. Synthetic temporary-vault work is permitted. Do not let external qualification dependencies block local planning or implementation.

The plan specifies interactive defaults for new passphrase vaults, explicit machine opt-in, and labeled legacy defaults pending an operator decision. It specifies healthy-live checkpointing versus authenticated damaged-live quarantine and journal intent/pre-state/post-state validation. Production threat-model acceptance, real-vault default/retention/rotation choices, physical targets, signing identity, and independent review remain external gates for S4.

## Packet ledger

| ID | Coverage | Status | Write scope | Settings and decision | Evidence/task |
| --- | --- | --- | --- | --- | --- |
| KC-P01 | Complete remediation/qualification plan for F1–F6 and all audit design/assurance gaps | verified | `docs/plans/2026-09-05-security-production-readiness-plan.md` only | Local host; saved project keyclasp (`local-0a5950b8ae2081e8284bb151dcdd78ac`); direct checkout `/Users/andreacatalucci/Developer/keyclasp`; current source including local audit inputs; `gpt-5.6-sol`, medium; user approved with “yes” immediately after the KC-P01 preview | Exact prompt/settings: coordinator response to “ae-coordinate fixes for all these issues and production readiness”; created task `01a070a7-de51-7a41-b826-144d7fe9a337`, host `local` |
| KC-W01 | Plan Slice 1, F3–F6: complete SQLite-state backup/restore and restartable authenticated recovery | proposed | `src/recovery.ts`, new `src/vault-files.ts`, `src/cli.ts`, necessary lifecycle/vault/policy/owner-path integration; recovery/authorization/CLI tests; scoped recovery docs; canonical plan; `docs/architecture/software-vault-lifecycle.md` | Local host/project keyclasp; isolated worktree copied from `/Users/andreacatalucci/Developer/keyclasp` current working tree including audit/plan/map; base `d94189b30fb5e52ee5f4eb6435e96fe865c13142`; `gpt-5.6-sol`, high; approval pending | Exact prompt/settings: coordinator response reconciling KC-P01 completion; no task created |

The direct checkout is approved for planning because its only write is a new, exclusively owned plan and it already contains the uncommitted audit evidence. KC-P01 executor is confirmed idle after correction turn `01a070b6-d036-7e91-9376-4609218b4c71`. KC-W01 will use an isolated worktree if approved. Its report must identify that checkout and the full patch; integration is not inferred from a report.

## Completion

Do not close this map until every remediation slice is verified, the applicable final-artifact and architecture evidence is current, every issued packet is reconciled or retired, and unresolved external production gates are satisfied or explicitly excluded by an informed scope decision. Keep “local fixes verified,” “artifact qualified,” “independently reviewed,” and “production rollout complete” distinct. Missing external evidence must remain visible; green unit tests cannot substitute for it.
