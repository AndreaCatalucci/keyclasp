# Keyclasp Show HN readiness

Outcome: a newcomer can understand the published beta's purpose and limits, install it, configure agent use, and complete a disposable-credential demonstration using consistent documentation.

State: **blocked on external acceptance**. PR #20 remains verified merged. KC-HN-W02 is verified locally; its follow-up documentation edits are uncommitted. Fresh-machine human/physical checks remain open.

## Scope and coverage

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

## Verification basis

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

## Next transition

Follow-up documentation is ready for requested Git integration. Registry action remains the user's choice; advice does not establish a changed tag or unpublished version. A fresh-machine tester must still return the checklist results before HN-06 can be accepted. No HN post is authorized.
