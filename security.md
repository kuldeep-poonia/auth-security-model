# Security Requirements

This is a security product. Its own security posture has to be higher than
average, because a security tool that leaks data or introduces risk is worse
than having no tool at all. Treat every rule below as non-negotiable unless
explicitly changed by the product owner.

## Hard boundaries — do not touch these file types

- Never read, index, embed content from, or send to any model (local or
  cloud) any file whose primary purpose is secrets or credentials:
  `.env`, `.env.*`, files matching common secret-store patterns, key
  files (`.pem`, `.key`, `.pfx`), cloud credential files, files inside
  known secret directories (`.aws/`, `.ssh/`, etc.).
- Maintain an explicit denylist of filename/path patterns that are
  skipped before any scan touches them. This denylist check runs first,
  before file targeting, before AST parsing — nothing downstream should
  ever see these files' contents.
- If a file is ambiguous (might contain secrets, might not), exclude it
  by default and require explicit user opt-in to include it.

## Code never leaves the machine by default

- The local model and scan engine must never make outbound network
  calls with user code, file contents, or file paths, under any
  default configuration.
- The BYOK (bring your own API key) feature is the only path where a
  code snippet leaves the machine, and only:
  - when the user has explicitly enabled it,
  - for the specific snippet the user asked to get a deeper
    explanation/fix for (not the whole file, not the whole codebase),
  - going only to the endpoint tied to the API key the user provided.
- Nothing about scan results, findings, file paths, or codebase
  structure should ever be transmitted to any server operated by us.
  There is no "phone home" telemetry of code content, ever.

## API key handling (BYOK feature)

- Store API keys only in OS-native secure storage (Windows Credential
  Manager, macOS Keychain, Linux Secret Service / libsecret). Never
  write a key to a plaintext file, config file, log file, or database.
- Never log the key, even partially, in debug output or error messages.
- Keys stay in memory only for the duration needed to make the call.
  Do not cache keys in memory longer than the active session requires.
- If a call using the key fails, the error message must not include the
  key value even in a truncated/partial form.

## Findings and reports never modify the target codebase

- The tool has zero write access to scanned files. It produces read-only
  reports. This is both a product decision (01_PRODUCT_VISION.md) and a
  security requirement — a security tool that can write to a codebase is
  itself an attack surface. Do not add a "fix" or "patch" write path
  without an explicit, separate security review.

## Model output must not overclaim

- The model must never report a scanned scope as "secure" or
  "vulnerability-free." A clean scan result is always phrased as "no
  high-confidence issue found in this scope" — never as a guarantee.
- Confidence scores must be genuinely calibrated (via mutation testing,
  see the training/mutation design docs), not cosmetic numbers. Do not
  hardcode or fake a confidence value anywhere in the pipeline.

## General posture

- Treat all file paths and code content passing through the pipeline as
  potentially sensitive, even for a local-only tool — assume the
  codebase being scanned could belong to a company with strict
  compliance requirements (finance, healthcare, defense-adjacent).
- Any new dependency added to the project must be from a reputable,
  actively maintained source. Do not add a dependency with a small or
  unverified maintainer base without flagging it first, since supply
  chain risk in a security tool is especially damaging.
- Any feature that would change the boundaries in this document (e.g.,
  adding a default network call, adding write access, loosening the
  secrets-file denylist) requires explicit confirmation from the product
  owner before implementation — never assume it's fine because it seems
  convenient.