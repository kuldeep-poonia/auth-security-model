# Product Vision — Auth/Authz Security Scanner (Local Model)

This document is the single source of truth for what this product IS and IS NOT.
Read this before writing any code. If a task conflicts with this document, stop
and flag it instead of proceeding.

## One-line description

A local, offline, lightweight fine-tuned language model that scans a codebase
specifically for **authentication and authorization vulnerabilities**, verifies
its own findings through mutation testing, and reports high-confidence issues
to the developer — without ever modifying code, without sending code to the
cloud, and without pretending to be a general-purpose security scanner.

## Who this is for

Individual developers and small-to-mid teams who want a fast, private,
zero-cost-per-scan check on the highest-blast-radius part of their codebase:
the code that decides who is logged in and what they're allowed to do.

## What this product DOES

- Scans a codebase and identifies files/functions likely to contain
  authentication or authorization logic (login, session, token validation,
  RBAC checks, ownership checks, permission middleware, IDOR-prone endpoints).
- Runs a fine-tuned local model against that narrowed set of candidates.
- For borderline-confidence findings, runs mutation-based verification
  (testing the model's judgment against generated vulnerable/safe variants
  of the same pattern) to raise or lower confidence before reporting.
- Reports findings with an explicit confidence score and a plain-language
  explanation of the suspected issue.
- Optionally (user opt-in, user's own API key) calls an external LLM to
  generate a deeper explanation or suggested fix — which the local model
  then re-verifies before showing it to the user.
- Runs entirely on the user's machine. No code, file paths, or scan results
  leave the machine unless the user explicitly enables the BYOK feature —
  and even then, only the specific snippet sent for that one call leaves.

## What this product explicitly does NOT do

- Does NOT scan for every vulnerability class (no SQLi, XSS, deserialization,
  crypto misuse, etc. in v1). Scope is auth + authz only. Do not add other
  vulnerability classes without an explicit scope change to this document.
- Does NOT modify, patch, or auto-fix any file. It only reads code and
  produces a report. Zero write access to the scanned codebase, ever.
- Does NOT perform dynamic analysis (DAST). It does not run the target
  application, send it live requests, or require the app to be deployed.
- Does NOT claim a codebase is "secure" when no issues are found. Absence
  of a finding must always be reported as "no high-confidence issue found
  in this scope" — never as a security guarantee.
- Does NOT send code to any cloud service by default. The BYOK LLM path is
  opt-in only, off by default, and scoped to a single snippet per call.
- Does NOT store, log, or transmit the user's API key anywhere but local
  OS-native credential storage.
- Does NOT scan or touch `.env` files, secret stores, credential files, or
  any file whose primary purpose is holding secrets. This is a hard
  boundary — see 04_SECURITY.md.
- Does NOT require the target application to be language-specific. The
  model must generalize across languages for the same logical pattern
  (e.g., a missing ownership check looks structurally similar in Go,
  Python, or Java) — it is not a "Go security scanner" or "Python security
  scanner."

## Confidence tiers (how findings are shown to the user)

- **>= 90% confidence**: shown as an actionable finding — "this needs a fix."
- **50–89% confidence**: shown in a secondary/collapsed "worth reviewing"
  section — flagged but not asserted.
- **< 50% confidence**: not shown by default (available in verbose/debug mode
  only). Do not surface low-confidence noise as if it were a finding.

## Definition of done for any feature

A feature is NOT done just because it runs without errors. It is done when:
1. It stays within the scope defined above.
2. It produces output a working developer would trust enough to act on.
3. It fails safely and transparently when uncertain (never guesses silently).

If you (Gemini) are unsure whether a task fits this scope, stop and ask
rather than assuming and building it anyway.