# Architecture & Code Style Guide — Model Repo

This document covers ONLY this repository — the fine-tuning, training data
handling, and local inference code for the auth/authz detection model.

This is a standalone project. It is one of three separate, independently
built parts of the overall product:
1. MCP server (separate repo — user-facing interface, not covered here)
2. Scan engine (separate repo — file targeting, AST parsing, mutation
   testing orchestration, not covered here)
3. **This repo — the model itself** (training pipeline + packaged
   inference artifact)

Do not design this repo assuming it also owns MCP-handling or scan
orchestration logic. This repo's job ends at: take a code unit as input,
return a structured prediction as output. How that input arrives and
what happens to the output is the scan engine's responsibility, not this
repo's.

## What this repo contains

- Data pipeline code (sourcing, cleaning, formatting training data —
  see 05_DATA_PIPELINE.md for the rules governing this).
- Fine-tuning code (LoRA/QLoRA training scripts — see
  06_MODEL_TRAINING_SPEC.md for the concrete ML decisions).
- Evaluation code (held-out test set scoring, calibration checks).
- Quantization/packaging code (producing the final local inference
  artifact).
- A minimal local inference interface (load model, accept one code unit
  plus context, return the structured prediction defined in
  06_MODEL_TRAINING_SPEC.md). This is a thin wrapper — it does not parse
  files, walk a codebase, or do anything the scan engine repo owns.

## What this repo does NOT contain

- No MCP protocol handling code.
- No file/codebase scanning, AST parsing, or file targeting logic.
- No mutation generation or mutation-orchestration logic (the scan
  engine calls this repo's inference interface once per mutation — this
  repo doesn't know or care that mutation testing is happening upstream).
- No UI, no report formatting, no user-facing output beyond the raw
  structured prediction schema.

## Before creating any new file

Search the existing repo first. Ask: does a file with this
responsibility already exist? Do NOT create a new file "to be safe" or
because it seems tidy. Every new file must have a single, obvious
responsibility that cannot be reasonably folded into an existing file.

If you cannot state the file's responsibility in one sentence, it should
not exist yet.

## Suggested repo layout (adjust only if a responsibility genuinely
doesn't fit — don't restructure for its own sake)

```
data/            - raw source manifests, cleaning scripts, dataset builders
training/        - LoRA/QLoRA fine-tuning scripts, hyperparameter configs
evaluation/      - held-out test scoring, calibration/metrics reporting
packaging/       - quantization, GGUF export, artifact packaging
inference/       - thin local inference wrapper (load model, predict)
```

Do not create additional top-level directories without a clear,
single-sentence reason tied to a responsibility that doesn't fit above.

## File naming

- Names must describe what the file *does*, not implementation trivia.
  Good: `clean_cve_pairs.py`, `train_lora.py`, `score_calibration.py`.
  Bad: `utils.py`, `helper2.py`, `model_stuff.py`, `new_v2.py`.
- No version numbers, no "final", no "new", no "temp" in filenames — ever.
- Use snake_case (or whatever convention this repo's language ecosystem
  standard is) consistently — do not mix conventions within the repo.
- One file, one clear purpose. Split a file only when it actually starts
  doing two unrelated things — not preemptively.

## Function and variable naming

- Names must read like something a real senior engineer would write and
  another engineer would understand without opening the function body.
  `filter_auth_related_cves`, not `checkThing2` or `processData`.
- No generic placeholder names: no `doStuff`, `handleData`, `process`,
  `manager`, `helper` as a standalone name.
- Naming must stay consistent across the whole repo — if a field is
  called "confidence" in one place, don't call it "score" elsewhere
  without reason.

## Function size and complexity

- A function does what it needs to do in as few lines as that honestly
  takes. A 5-line function stays 5 lines. Do not pad functions with
  defensive scaffolding, redundant checks, or restructuring "for
  clarity" that adds no real clarity.
- If a well-maintained library already does something reliably (dataset
  loading, tokenization, LoRA application, quantization), use it. Do not
  hand-roll a worse version of functionality a library already solves —
  use established ML tooling (e.g., Hugging Face `transformers`/`peft`,
  `llama.cpp` for quantization) rather than reimplementing training
  mechanics from scratch.
- Prefer straight-line, readable logic over clever abstractions. No
  premature interfaces, no factory patterns for something that has one
  implementation, no configuration options nobody asked for.

## Comments

- Comments explain **why**, not what the code already says. Do not
  comment `# increment i by 1` above `i += 1`.
- Write comments the way a developer would leave a note for a teammate —
  plain, specific, short. No comment blocks that restate the function
  signature in prose.
- Do not leave comments describing what you (the AI) did, your reasoning
  process, or "TODO: improve this later" placeholders unless there's a
  real, specific follow-up task with enough detail that someone else
  could pick it up.
- No commented-out code left in the repo. Delete it — version control
  already has the history.

## Dead code and unused code

- Do not generate functions, classes, or config options that nothing
  calls. If you write it, something must use it in the same change.
- Do not add speculative extensibility ("in case we need this later").
  Build for the current, real requirement only — e.g., don't add support
  for a second base model architecture "just in case" if only one is
  actually being used.
- Before finishing a task, check for and remove anything you added that
  ended up unused by the final implementation.

## Optimization

- Prefer established libraries over custom implementations for solved
  problems (tokenization, LoRA injection, quantization, metrics
  computation).
- Avoid unnecessary recomputation — don't reload/retokenize the same
  dataset multiple times in one run, don't recompute metrics that were
  already computed, but don't add caching complexity for hypothetical
  future scenarios either.
- Keep the inference wrapper lightweight: minimal dependencies, fast
  load time, since the scan engine will call it repeatedly (including
  once per mutation during mutation testing).

## Consistency check before finishing any task

Before marking a task complete, verify:
1. No new file was created that could have been an addition to an
   existing file.
2. No function exists that isn't called anywhere.
3. All names read like something a human engineer would write and
   another engineer would immediately understand.
4. Comments explain reasoning, not restate code.
5. Nothing was over-engineered beyond what the current requirement
   actually needs.
6. Nothing here assumes ownership of MCP or scan-engine responsibilities
   that belong to the other two repos.