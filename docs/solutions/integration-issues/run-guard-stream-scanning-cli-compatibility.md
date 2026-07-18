---
title: keyclasp run stream scanning must preserve CLI compatibility
date: 2026-07-09
category: integration-issues
module: keyclasp run
problem_type: integration_issue
component: tooling
symptoms:
  - "Terraform output was over-redacted when a short injected value matched ordinary text"
  - "Interactive prompts appeared to ignore pasted stdin because prompt text was withheld"
root_cause: logic_error
resolution_type: code_fix
severity: high
tags: [keyclasp-run, stream-redaction, terraform, stdin, secrets]
---

# keyclasp run stream scanning must preserve CLI compatibility

## Problem

`keyclasp run` added stdout/stderr scanning so commands that print injected secrets are redacted and terminated. The first implementation protected the transcript, but it broke real CLI workflows such as Terraform by treating ambiguous output as a leak and by buffering interactive prompts.

## Symptoms

- `keyclasp run -- terraform init` redacted normal Terraform words such as `Initializing`, `available`, and `terraform`, then terminated the child as a leak.
- `keyclasp run -- terraform plan` appeared to ignore pasted stdin because Terraform-style prompt text could be held in the redactor carry buffer instead of being displayed while the child waited for input.
- The remaining Terraform backend failure after the fix was a real provider/backend auth error (`InvalidAccessKeyId`), not a Keyclasp guard failure.

## What Didn't Work

- Matching every non-empty injected value was too broad. A one-character secret value like `a` turns ordinary English output into false leak matches.
- Holding back `longestSecret - 1` characters from every output chunk was too conservative. It protects split-secret detection, but a short prompt such as `Enter a value:` can be shorter than the longest secret and therefore never reach the terminal before the child waits for stdin.
- Relying on `--allow-unsafe` would have restored CLI behavior, but it would disable the protection that `keyclasp run` is supposed to provide by default.

## Solution

Keep the guard, but make the matcher and carry buffer precise enough for interactive CLIs.

First, inject short values normally but exclude them from output leak detection. The current guard only tracks injected values with at least `MIN_LEAK_VALUE_LENGTH` characters in [src/run.ts](../../../src/run.ts):

```ts
export const MIN_LEAK_VALUE_LENGTH = 8;

if (value.length >= MIN_LEAK_VALUE_LENGTH && !seenLeakValues.has(value)) {
  leakValues.push(value);
  seenLeakValues.add(value);
}
```

Second, retain only suffixes that could actually become an injected secret on the next chunk. The redactor computes the suffix length with `prefixCarryLength`, which checks whether the current output suffix is a prefix of any tracked secret in [src/run.ts](../../../src/run.ts):

```ts
const combined = carry + chunk;
const keepLength = prefixCarryLength(combined, values, maxSecretLength);
const flushLength = combined.length - keepLength;

carry = combined.slice(flushLength);
const redacted = redact(combined.slice(0, flushLength));
return redacted;
```

```ts
function prefixCarryLength(input: string, values: string[], maxSecretLength: number): number {
  for (let length = Math.min(input.length, maxSecretLength - 1); length > 0; length -= 1) {
    const suffix = input.slice(-length);
    if (values.some((value) => value.startsWith(suffix))) return length;
  }
  return 0;
}
```

This keeps split-secret detection without buffering unrelated prompts.

## Why This Works

The guard has two jobs that compete with normal CLI behavior:

1. It must not release a prefix of a secret before seeing whether the next chunk completes it.
2. It must not hold arbitrary output forever, because many CLIs print prompts and then wait for input.

The short-value threshold avoids impossible-to-disambiguate signatures. A value like `a` is not a useful transcript leak matcher because it appears constantly in normal output. The prefix-aware carry keeps only text that could become a real injected secret, so ordinary prompts flush immediately while split values such as `sk-test` followed by `-secret` are still caught.

The regression tests in [tests/run.test.ts](../../../tests/run.test.ts) encode both boundaries: short injected values are still injected but not tracked as leak values; Terraform-like text with a short value does not trigger a leak; ordinary prompts are emitted immediately; and split secrets are still withheld and redacted.

## Prevention

- Any stream-scanning secret guard must test both safety and CLI compatibility. Add regression cases for exact leaks, split leaks, short-value false positives, and prompt-like output that does not end in a newline.
- Avoid fixed-size output buffering unless the buffer length is tied to an actual possible match. For interactive tools, unrelated output should pass through immediately.
- When testing `keyclasp run` against Terraform or similar tools, distinguish Keyclasp guard failures from the wrapped tool's real backend errors. In this case, `InvalidAccessKeyId` was a Terraform backend credential problem after the Keyclasp guard stopped interfering.

## Related Issues

- PR #6 updates the `keyclasp run` guard to ignore tiny leak signatures and preserve interactive prompts.
