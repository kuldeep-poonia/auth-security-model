# Data Pipeline — Sourcing, Cleaning, and Preparing Training Data

This document governs how training data is sourced and prepared. The model
is only as good as this pipeline — no step here should be treated as
optional or "good enough for now."

## Core principle: real-world data first, synthetic data as augmentation

Do not train primarily on synthetic/generated examples. The model must
learn from real, historically confirmed vulnerabilities before any
synthetic augmentation is added on top. Synthetic/injected examples exist
to scale volume and diversity — they are not the foundation.

## Primary real-world sources (in priority order)

1. **CVE-linked fix commits** — pull from public vulnerability databases
   (NVD, GitHub Security Advisories) filtered specifically to auth/authz
   relevant CWE categories:
   - CWE-287 (Improper Authentication)
   - CWE-862 / CWE-863 (Missing / Incorrect Authorization)
   - CWE-639 (Authorization Bypass Through User-Controlled Key / IDOR)
   - CWE-798 (Hardcoded Credentials) — only if in scope; otherwise exclude
   For each advisory, retrieve the linked fix commit and extract the
   before/after code as a matched pair.

2. **Known vulnerability benchmark datasets** — existing labeled research
   datasets (e.g., CVEfixes, Big-Vul, PrimeVul, OWASP Benchmark) filtered
   down to auth/authz-relevant entries only. Do not import unrelated
   vulnerability classes from these datasets — filter at ingestion time.

3. **Multi-language coverage, deliberately balanced** — do not let the
   dataset default to whatever language has the most public data (usually
   C/C++/Java). Actively pull examples across the languages this product
   targets. If one language is underrepresented, source more for it
   rather than letting the model skew toward the best-covered language.

## Never use raw data directly

Raw pulled data (commit diffs, advisory text, scraped code) must never go
straight into a training file. Every source passes through a defined
cleaning stage before it's usable:

1. **Extraction** — pull only the relevant code unit (function/method plus
   directly necessary context), not the entire file or entire diff noise
   (formatting-only changes, unrelated refactors in the same commit).
2. **Validation** — confirm the "before" version actually contains the
   vulnerability described and the "after" version actually fixes it.
   Do not trust commit messages or advisory text blindly — spot-check a
   meaningful sample manually before trusting a source at scale.
3. **Deduplication** — remove near-duplicate examples (same pattern from
   forks, mirrors, or repeated boilerplate) so the model doesn't
   overweight one recurring pattern.
4. **Normalization** — consistent formatting, consistent field structure,
   stripped of irrelevant metadata, before it enters the labeled dataset.
5. **Negative examples included deliberately** — clean, non-vulnerable
   auth/authz code must be part of the dataset in meaningful proportion.
   A dataset made only of vulnerable examples produces a model that
   overpredicts vulnerabilities (high false-positive rate).

## Labeled data format (structure, not final schema — confirm before building)

Each training example should carry, at minimum:
- the code unit (function + minimal necessary context)
- language
- vulnerability class (or "clean" for negative examples)
- a plain-language explanation of why it is/isn't vulnerable
- source provenance (which CVE/advisory/dataset it came from, for
  traceability and later auditing)

Do not finalize the schema without confirming it matches what the model's
training format actually needs — check the training script's expected
input before locking the schema.

## Synthetic augmentation (injection-based) — scale, not foundation

- Injected vulnerabilities are generated only from real, clean base code
  (sourced the same way as above), by applying deliberate, realistic
  mutations (removing a check, flipping a comparison, reordering
  validation, breaking an ownership check).
- Injected examples are used to multiply the volume and diversity of the
  real dataset, not to replace it. Track the ratio of real to synthetic
  examples and keep real examples as the majority share of what the model
  is evaluated against, at minimum.
- Do not generate injected examples that are unrealistic or wouldn't
  plausibly occur in real code — a mutation that no real developer would
  ever produce teaches the model a pattern it will never see in practice.

## Train / validation / test split discipline

- Split by source (e.g., by repository or by CVE), not by individual
  example. Two examples from the same commit or same codebase must never
  end up in different splits — this causes data leakage and inflates
  evaluation scores artificially.
- Keep the test set untouched by any augmentation or mutation process
  that also touches the training set, so evaluation reflects genuine
  generalization, not memorization of the same injection templates.

## Before treating a data source as ready

Do not mark a data source "done" just because ingestion ran without
errors. Confirm:
1. A meaningful manual sample was checked for label accuracy.
2. Negative (clean) examples are present in reasonable proportion.
3. No single repository, CVE, or injection template dominates the
   dataset disproportionately.
4. The train/val/test split has no leakage across sources.

If any of these aren't true yet, the data source is not ready for
training — flag it rather than proceeding.