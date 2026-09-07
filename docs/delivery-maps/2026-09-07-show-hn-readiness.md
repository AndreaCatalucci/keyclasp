# Keyclasp Show HN readiness

Outcome: a newcomer can understand the published beta's purpose and limits, install it, configure agent use, and complete a disposable-credential demonstration using consistent documentation.

State: **Show HN documentation scope complete; beta.3 publication and human trial remain open.** PRs #20 and #21 are merged. The user rejected W03 and R01 restored the preferred PR21 documentation. A fresh-machine human trial is still unverified; it is not evidence of production readiness.

## Current status — 2026-09-07

This snapshot supersedes the registry, checkout, and next-step statements in the historical reconciliation sections below.

| Work | Status | Evidence |
| --- | --- | --- |
| Documentation fixes and simpler demo | Complete for the merged scope | PRs #20 and #21; remote main `b7bead886f3ca3e74e3b4480c7643b1af21b220e`; published beta.2 demo passed in Bash and Zsh |
| Restore preferred prose | Complete | R01 restored the PR21 README, getting-started, and FAQ; W03 is superseded |
| Remove obsolete npm releases | Complete | Live public registry contains only `0.2.0-beta.2`; both `beta` and `latest` point to it |
| Moving beta installation instructions | Prepared locally | Beta.3 release checkout uses `npm install -g keyclasp@beta`; those changes are uncommitted |
| Publish beta.3 | Open | Candidate prepared, but `.3` is absent from the public registry |
| Fresh-machine human trial | Open | No completed human trial or physical authorization receipt |
| Show HN submission | Not recorded | No submission was performed or verified in this task |

The original documentation scope is finished. The remaining human trial is useful onboarding evidence; full production qualification is a separate scope in the [security readiness plan](../plans/2026-09-05-security-production-readiness-plan.md).

## Original gaps and scope (historical)

The user explicitly waived a plan for documentation changes and requested GPT-6 Astra plus a thorough unslop pass. KC-HN-W01 implements the known fixes directly; no implementation plan is required. Scope includes these gaps and tightening existing current user-facing documentation:

| Gap | Required behavior | Current evidence |
| --- | --- | --- |
| HN-01 | Opening claims describe accidental-exposure protection and trusted-child limits accurately | Verified contradiction: README.md:4 promises the agent never sees values; README.md:37 and :110 document narrower guarantees |
| HN-02 | Public installation guidance identifies the published beta and removes obsolete prepublication instructions from current user paths | Verified: npm beta points to 0.2.0-beta.2; docs/getting-started.md:19 says unpublished |
| HN-03 | CI and container recipes agree with explicit machine custody and portability limits | Verified: docs/recipes.md:10 empty-passphrase initialization fails against the published beta; the container example conflicts with the laptop-vault warning |
| HN-04 | README contains a self-contained dummy-credential demo, expected results and prompts, and explicit agent setup | Verified gap: README uses an unspecified npm test and only links to the agent skill; getting-started contains a partial dummy demo |
| HN-05 | Readers can understand when Keyclasp is preferable to an existing op run setup | Verified gap: README, getting-started, and FAQ lack the comparison; current 1Password documentation already provides subprocess injection and output masking |
| HN-06 | A first-user trial establishes whether the published quickstart works without author assistance | Open: no fresh-machine human trial; current smoke evidence covers only temporary macOS arm64 machine custody on Node 26 |
| HN-07 | Existing current user documentation is concise, consistent, and easy to follow | User requested a thorough unslop pass; retain material security limits, compatibility facts, commands, and attribution |

Historical audit and release receipts remain intact. This work does not certify production security, publish a package, post to HN, or contact testers. New defects discovered through verification must remain explicit gaps until resolved or deliberately deferred.

## Initial verification basis (historical)

Coordinator inspected primary documentation and package behavior on 2026-09-07 at source revision `61041649544f05ee5b1ac5eb501b9ccd3a36f62b` on `main`.

- Published version: `0.2.0-beta.2`; npm latest remains `0.1.1`.
- Downloaded tarball SHA-256: `b747a97ba033a24edc46979105491c16c11c27f757610bf2c5976b70a19f113e`, matching docs/releases/0.2.0-beta.2.md.
- Isolated install, explicit bundled-native verification, dummy storage, names-only listing, and injection passed. Dummy output leakage produced redaction and exit code 2.
- Documented empty-passphrase CI initialization returned exit code 1 and required a non-empty passphrase or explicit `--machine-only`.
- Smoke artifacts: `/var/folders/8c/t2tmqjw11gx8pkf90z3p3rbc0000gn/T/keyclasp-showhn-review-nd1sznin`. Exact commands and outputs are in the coordinator task's preceding review turn. Temporary artifacts are not durable release qualification.
- Physical Touch ID, fresh-machine human onboarding, and Linux were not exercised in that review.

## Architecture and invariants

Starting references: `docs/architecture/system-context.md`, `docs/architecture/software-vault-lifecycle.md`, and `docs/architecture/operator-authorization.md`. Existing architecture verification is dated evidence, not refreshed by this documentation review.

Intended delta: no runtime architecture change. Current architecture artifacts are read-only inputs; executor reports any observed contradiction for coordinator reconciliation. No new diagram or verification claim is required for prose-only work.

Preserve trusted-child and OS-user boundaries, explicit project/environment/secret selection, interactive defaults, operator authorization, no real credential exposure, and historical failed receipts. Demo work must use isolated disposable state.

## Packet ledger

| ID | Scope | Status | Settings and decision | Evidence / task |
| --- | --- | --- | --- | --- |
| KC-HN-P01 | Plan HN-01 through HN-06 | superseded | User rejected a planning step and selected Astra in the next message. Never launched; no executor or outstanding write scope. | Prior coordinator preview retained as history |
| KC-HN-W01 | Direct documentation fixes HN-01 through HN-05, preparation and feasible checks for HN-06, thorough unslop HN-07 | verified | User replied yes to the revised KC-HN-W01 prompt and settings. Created on local host in saved Keyclasp project `local-0a5950b8ae2081e8284bb151dcdd78ac`, isolated worktree from current primary working tree at 6104164, gpt-6-astra / medium, with the exact approved prompt. | Task `01a07bfc-dc82-7811-96e8-ac34f542fe1e`, local; worktree `/Users/andreacatalucci/.codex/worktrees/f420/keyclasp`. Turn `01a07bfc-dea7-78c1-9a40-24c305b4bd39` completed. Coordinator read final report and check evidence; original queued client reference retained in task history. |

| KC-HN-W02 | Simpler demo, removal of current 0.1.1/latest discussion, and consistent acceptance instructions | verified | User requested follow-up edits; reused existing executor task and unchanged gpt-6-astra / medium settings. No new task created. | Task `01a07bfc-dc82-7811-96e8-ac34f542fe1e`; exact packet in this coordinator turn’s send-message tool call; docs-only finish line, no Git or registry writes |

| KC-HN-S01 | Commit, PR and merge only README.md and docs/getting-started.md | verified | User authorized the proposed Git integration; existing Astra task/settings reused, no new task created | Task `01a07bfc-dc82-7811-96e8-ac34f542fe1e`; exact shipping packet in coordinator tool call |

| KC-HN-W03 | Short first-visitor README; detailed walkthrough and setup moved to guides | superseded | User corrective feedback authorizes further documentation edits; existing Astra task/settings reused | Task `01a07bfc-dc82-7811-96e8-ac34f542fe1e`; no Git or registry mutation authorized for this packet |

| KC-HN-R01 | Restore exact pre-W03 README, getting-started and FAQ | verified | User explicitly requested restoration; existing executor reused | All three files match /tmp/kc-hn-w03-before and executor verified PR21 revision b7bead8; no commits or pushes |

Coordinator: task `01a07bf3-8a48-74a1-a8fe-fa18a33ede2e`, local host, title `Assess product need and audience`.

Source checkout: `/Users/andreacatalucci/Developer/keyclasp`. Existing modified security plan/map and untracked KC-W02 receipt are unrelated and must remain untouched. The readiness map belongs to the coordinator. KC-HN-W01 write scope is README.md, current top-level docs/*.md, and skills/keyclasp-agent/SKILL.md where agent setup or consistency needs it. Historical release/audit/plan/ideation/solution records and architecture artifacts are outside executor write scope. No overlapping executor for this scope has been issued by this coordinator.

## Reconciliation on 2026-09-07

The task listing omitted the executor, but the queued client reference was resolved through a scoped desktop log lookup. A direct wait snapshot confirmed completion, not failure. No duplicate task was created.

Coordinator inspected the revised README and getting-started guide, scoped diffs, the completed task's commands and outputs, and `/tmp/keyclasp-hn-check-results.json`. Thirteen isolated checks passed against the published beta on macOS arm64/Node 26.8.1, including README execution in Bash and Zsh and CI bootstrap-variable removal. Skill validation, 28 relative file links, code fences, historical-body preservation and diff checks passed in the executor report; coordinator independently reran `git diff --check` and confirmed inherited unrelated edits and runtime files match the primary checkout.

Eleven documentation files changed: README; commands, FAQ, getting started, recipes, security and support guides; three historical hardware references with added scope notices and preserved bodies; and the agent skill. HN-01 through HN-05 and HN-07 are satisfied for the local documentation packet. HN-06 has a documented trial checklist and automated evidence, but no completed human trial. No new runtime architecture was introduced.

At the first reconciliation, the edits were uncommitted in the executor worktree and had not been copied to main or published. Two additional wording issues were reported outside the packet: `package.json:4` promises secrets never touch agent context; `src/run.ts:412` calls output scanning exfiltration protection. Both were subsequently fixed by merged PR #20, as verified below.

## Merge reconciliation

User reported the docs merged. GitHub API confirms PR [#20](https://github.com/AndreaCatalucci/keyclasp/pull/20), “Clarify beta setup and trusted-command security limits”, merged at 2026-09-07T14:16:37Z. Remote main is `966b83ba7d7f27886c157677758670614a3d9a94`.

Coordinator compared the Git blob identities of all 13 merged files with the executor worktree: all match, including the 11 previously verified documentation files. The two additional patches replace the absolute package description with selected-secret injection into trusted commands, and replace the exfiltration-protection warning with an accurate command-preflight/output-scanning warning. Both previously deferred wording gaps are closed in repository source. These source-only wording changes do not establish a republished npm artifact.

The primary local checkout remains at `6104164` with unrelated uncommitted changes. It was not pulled or modified to match remote main; remote verification used read-only GitHub API calls. The prior documentation checks still apply to the unchanged merged documentation bytes.

## KC-HN-W02 reconciliation

Executor turn `01a07c3e-1beb-7c20-8893-dc03a14e0709` completed in the existing Astra task. Coordinator inspected both changed files and the executed verification command/output. README now separates install, temporary-vault initialization, dummy storage, and named command execution, with expected results. Cleanup is optional in getting-started. Both guides omit the old 0.1.1/latest discussion and retain the exact beta install. Human acceptance is reduced to fresh-machine install/demo and approval/cancellation behavior, with other checks optional.

Exact revised steps passed in Bash and Zsh against published beta.2, including exact dummy injection, expected output, no dummy-value output, and cleanup. Relative links/anchors and code fences passed. Coordinator reran `git diff --check`; it passed. Evidence: `/tmp/keyclasp-hn-w02-check.py` and `/tmp/keyclasp-hn-w02-results.json`. These edits are local and uncommitted in `/Users/andreacatalucci/.codex/worktrees/f420/keyclasp`.

Registry research used current official npm documentation and implementation via Context7 and direct source reads. Public registry still contains 0.1.0, 0.1.1 and 0.2.0-beta.2; latest points to 0.1.1 and beta to beta.2 at inspection. Version unpublishing is permanent and policy-limited; tags are mutable aliases. No registry write was performed.

## Registry and frontier refresh

Public registry read on 2026-09-07 confirms `0.1.1` is absent, `latest` and `beta` both point to `0.2.0-beta.2`, and `0.1.0` remains available. The user's requested default-version change is reflected in registry state; this coordinator performed no registry mutation.

Remote main advanced to `39b5383ae04f9d5959716120d93600f7dc7ad058` (7 character warning). The simplified four-step demo and old-tag prose removal are still absent from remote README/getting-started. KC-HN-W02 remains uncommitted in the existing executor worktree at `fd773d0`. The new source-only short-secret warning does not change the already-published beta used for demo verification.

## KC-HN-S01 merge reconciliation

PR [#21](https://github.com/AndreaCatalucci/keyclasp/pull/21) merged at 2026-09-07T15:03:23Z as `b7bead886f3ca3e74e3b4480c7643b1af21b220e`. Coordinator independently verified the PR is merged into main and contains only README.md and docs/getting-started.md. PR head was `ea0f002a11099659fb35b97a229d9a8761031626`; executor verified the documentation bytes matched the tested W02 examples.

All four source CI jobs were in progress at inspection. The user then stated “merged, i dont want to wait for ci”. CI monitoring was stopped by instruction; the jobs were not cancelled and their results were not inferred. Existing local demo verification remains evidence for the docs, not a substitute for those CI results. Executor was instructed to return without further Git mutations.

## KC-HN-W03 reconciliation

Executor turn `01a07c67-b1b6-7ca0-b55e-4b178fbed8c4` completed. Coordinator read the complete revised README and independently ran `/tmp/kc-hn-w03-check.py` and `git diff --check`: both passed. Seven moved demo/agent/output blocks are byte-identical, all existing guide commands are preserved, 27 local links and anchors resolve, and code fences balance. Existing W02 execution evidence remains applicable to unchanged commands. The full walkthrough and agent setup moved to getting-started, and the detailed comparison moved to FAQ. Security and architecture artifacts are untouched. README total whitespace-delimited words fell from 931 to 290; prose from 733 to 263. Three files are edited locally in the existing executor worktree; no new commit or registry mutation was requested for W03.

## Restoration

User rejected the shortening pass. Executor R01 completed; coordinator independently verified byte equality for README.md, docs/getting-started.md and docs/faq.md against the pre-W03 snapshot. The executor also verified those snapshots against merged PR21 revision b7bead886f3ca3e74e3b4480c7643b1af21b220e. W03 must not be shipped or reapplied. Unrelated edits remain preserved.

## Beta.3 preparation and current next steps

Candidate checkout: `/Users/andreacatalucci/Developer/keyclasp-beta3-release`, based on remote main `b7bead886f3ca3e74e3b4480c7643b1af21b220e`. The package, lockfile, version assertions, dependency inventory, release metadata, and beta-channel install instructions were updated locally. No commit, push, or publication was performed.

- Candidate: `release-artifacts/keyclasp-0.2.0-beta.3.tgz` in that checkout.
- SHA-256: `7c64734e1fb324c470e55785d369c80f8b80aeb20cb0cf121b91d8c8b263d9f0`.
- Exact-package checks passed on macOS arm64, Node 26.8.1, with the bundled native prebuild. Helper reproducibility and dependency inventory checks passed.
- Source verification is incomplete: key-invariant and integration tests timed out; the isolated key-invariant rerun also timed out. The broader run was stopped. Thresholds and assertions were not changed. Logs are preserved under `release-artifacts/evidence/` in the release checkout.
- Linux, Node 24, and physical authorization were not checked for this candidate. The package pass does not close those gates or erase the source failures.

The primary checkout now also contains uncommitted documentation changes covering local-machine positioning and the 1Password comparison, plus changes to AGENTS.md and index.html. These were not reviewed by this status update and are not included in the frozen beta.3 tarball. The earlier statement that no further documentation integration was needed applied to PR21 only.

Before publishing beta.3, reconcile whether those newer edits belong in it and resolve or explicitly disposition the source-test failures. If the package contents change, build and verify a new tarball and record its hash. Publish the selected artifact with `--tag beta`; updating `latest` is separate. Complete the human trial when available, and keep production qualification open until its own gates are met.
