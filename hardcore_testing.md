# Testing Philosophy — Hardcore, Adversarial, Break-It Testing

This document overrides the default instinct to write "a few unit tests
and call it done." That is not what testing means for this product. Read
this in full before writing any test for any feature.

## The core rule

The goal of testing here is NOT to prove a feature works. The goal is to
**actively try to break it** using real values, real code patterns, and
real adversarial scenarios — and only trust a feature once it survives
that attempt. A test suite that only confirms happy-path behavior has
not tested anything meaningful.

Standard unit tests and integration tests checking basic input/output
wiring are necessary but not sufficient. They are the floor, not the
target. Do not present "unit tests pass" as evidence a feature is ready.

## What "hardcore testing" means concretely, per component

### Scan engine (file targeting, AST parsing, relevance filtering)
- Feed it real, messy, large open-source codebases — not toy examples.
- Feed it codebases in every supported language, including ones with
  unusual project layouts, monorepos, generated code mixed with
  hand-written code, and vendored/third-party code checked into the
  repo.
- Feed it deliberately adversarial structures: auth logic split across
  many files, auth logic hidden inside generic-looking utility
  functions, wrapped/decorated functions, dynamically dispatched
  handlers — anything that would defeat naive pattern matching.
- Confirm the secrets-file denylist (04_SECURITY.md) cannot be bypassed
  by unusual filenames, symlinks, or nested paths that resemble but
  don't exactly match denylist patterns.

### Model (detection accuracy)
- Evaluate against a held-out test set of REAL confirmed vulnerabilities
  the model has never seen during training or mutation generation —
  not synthetic lookalikes of the training distribution.
- Actively test with **known hard cases**: vulnerabilities that look
  clean at a glance (subtle logic errors), and clean code that looks
  suspicious at a glance (defensive code with unusual but correct
  patterns) — this is where false positives and false negatives
  actually live.
- Test cross-language generalization directly: take the same logical
  vulnerability pattern, written in multiple different languages/styles
  the model wasn't specifically trained on for that exact phrasing, and
  confirm it still detects the pattern rather than memorized syntax.
- Report real numbers: precision, recall, false positive rate, false
  negative rate, and confidence calibration (does "80% confidence"
  actually correspond to ~80% real-world accuracy on that bucket of
  cases). Never report a single "accuracy %" number as if it's the
  whole picture.

### Mutation testing / confidence verification layer
- Stress-test the mutation generator itself: does it produce mutations
  that are realistic and genuinely represent the vulnerability class, or
  does it produce degenerate/unrealistic variants that inflate apparent
  confidence without meaning anything?
- Test the self-consistency logic directly: deliberately feed it cases
  designed to produce inconsistent model judgments across near-identical
  variants, and confirm the system correctly reports low confidence
  instead of forcing a high-confidence answer.
- Test performance under real load: how long does mutation verification
  actually take on a real, large codebase with many borderline-confidence
  candidates — not a cherry-picked small example.

### BYOK / cloud LLM loop
- Test the loop termination logic with a suggestion that never
  satisfies the local model's confidence threshold — confirm it
  actually stops at the max iteration cap instead of looping
  indefinitely or silently failing.
- Test with malformed, incomplete, or adversarial LLM responses
  (truncated output, wrong format, an LLM confidently suggesting a fix
  that introduces a new vulnerability) and confirm the local model
  correctly catches and flags these rather than trusting them blindly.

### Security boundaries (04_SECURITY.md)
- Actively attempt to make the tool violate its own boundaries:
  try to get it to read a `.env` file through an indirect path, try to
  get it to send full-file content instead of a snippet through the
  BYOK path, try to get an API key to end up in a log file or error
  message. These are adversarial tests against the product's own
  promises, not standard functional tests.

## Reporting results — no pass/fail flattening

- Do not summarize hardcore test results as a simple pass/fail. Report:
  actual numbers, actual failure cases found, actual edge cases that
  broke something, and what was fixed as a result.
- If a test run finds zero issues, treat that as suspicious rather than
  reassuring — it likely means the test wasn't adversarial enough, not
  that the feature is flawless. Go back and try harder scenarios before
  accepting a clean result.
- Every "hardcore test" cycle should end with a concrete list of what
  broke, what the real-world impact of that break would be, and whether
  it was fixed and re-verified — not a vague "tests passed" statement.

## When a feature is allowed to be called done

A feature is only considered validated when it has survived deliberate,
real-scenario attempts to break it — not when it passes the tests that
were convenient to write. If you (the agent) find yourself writing only
tests you're confident will pass, stop and write the ones designed to
find where it actually fails.