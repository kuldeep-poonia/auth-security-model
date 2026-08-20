# Execution Environment Strategy — No Local Hardware

There is no local GPU/dedicated hardware available for this project. All
work happens across two free/cheap cloud environments. This document
defines which environment does what, and — critically — how the agent
moves work between them **without requiring manual babysitting from the
user at every step**. The user will only review outcomes, not perform
manual handoff steps unless something requires a decision only they can
make (e.g., approving a paid Colab tier, approving a design tradeoff).

## The two environments and what each is for

### GitHub Codespaces — CPU-only, source of truth
Use for everything that does NOT require a GPU:
- Repo setup, all non-training code (data scraping, cleaning, dedup,
  formatting, mutation generator, evaluation scoring logic, inference
  wrapper, tests).
- This is where the actual repository lives and where all code is
  committed. Codespaces is the canonical development environment.
- Quantized model testing (Phase 9 hardcore testing) also happens here,
  since a quantized model is expected to run on CPU-class hardware
  anyway — this environment doubles as a realistic target-hardware proxy.

### Google Colab — GPU, training-only
Use ONLY for steps that require a GPU:
- Phase 5 (fine-tuning / LoRA training).
- Phase 7 (quantization), if it turns out to benefit from GPU — otherwise
  this can also run in Codespaces since GGUF conversion is CPU-feasible,
  just slower.
- Colab is not where code is authored or iterated on. It pulls finished,
  already-committed code from the repo and runs it. Do not develop or
  debug general logic inside a Colab notebook — that belongs in
  Codespaces and gets committed first.

## The handoff — this must be automated, not manual

The agent is responsible for making this handoff work without the user
needing to copy files back and forth by hand. Concretely:

1. All code (data pipeline, training scripts, configs) lives in the
   GitHub repo, committed from Codespaces.
2. The Colab notebook's job is minimal and mechanical:
   - Clone/pull the latest repo from GitHub.
   - Mount Google Drive (for storing checkpoints and datasets too large
     for the git repo).
   - Install pinned dependencies (same versions as Phase 0 environment
     setup — do not let Colab's environment drift from what was tested
     in Codespaces).
   - Run the actual training/quantization script that already exists in
     the repo — the notebook should call into repo code, not contain
     duplicated logic of its own.
3. After a Colab run finishes, checkpoints/artifacts save to Drive
   automatically as part of the script's own logic (not as a manual
   "please download this file" step left for the user).
4. Any code changes discovered as necessary while working in Colab
   (e.g., a bug only visible during actual training) get pulled back
   into the main repo and committed — Colab is never the permanent home
   of any code, only a temporary execution environment for GPU steps.

## Storage rules

- **Git repo**: code only — scripts, configs, small metadata files
  (dataset statistics reports, provenance manifests). Never commit model
  weights, checkpoints, or large datasets to git.
- **Google Drive**: checkpoints, trained adapters, large intermediate
  datasets, quantized model artifacts. Organize with a clear folder
  structure that mirrors the repo's phase structure (e.g.,
  `checkpoints/`, `datasets/cleaned/`, `packaging/quantized/`) so it's
  obvious what belongs where without guessing.
- Datasets that are large but reproducible (e.g., raw CVE pulls that can
  be re-fetched from source) do not need permanent Drive storage if
  re-running Phase 1 is cheap — only persist what's expensive to
  regenerate (cleaned/validated data, trained weights).

## Session limits — design for interruption, not around it

Free Colab sessions disconnect (idle timeout, ~12 hour hard cap). This is
a constraint to design for, not an edge case to hope doesn't happen:

- Training scripts (Phase 5) must checkpoint frequently enough that a
  disconnect loses minimal progress — define a concrete checkpoint
  interval (e.g., every N steps or every M minutes, whichever is more
  frequent) rather than leaving this vague.
- Training scripts must be resumable from the last checkpoint by default
  — restarting a Colab runtime should mean "continue from where it left
  off," not "start over." This is not optional for this project; treat
  it as a hard requirement of Phase 5, not a nice-to-have.
- Long-running steps (large dataset cleaning, big evaluation runs) that
  might also exceed a comfortable single session should be structured to
  process in resumable batches where practical, for the same reason.
- Before starting a long Colab run, confirm the resume logic actually
  works (e.g., by deliberately interrupting a short test run and
  confirming it picks back up correctly) rather than assuming it works
  because it was written to.

## What the agent should NOT do

- Do not write code that assumes a persistent local filesystem across
  sessions (Colab's local disk is wiped between sessions — anything not
  saved to Drive or committed to git is lost).
- Do not leave manual, undocumented steps for the user to perform inside
  Colab (e.g., "user should manually download checkpoint and re-upload
  next time"). If a step needs to happen, script it.
- Do not develop or debug substantial new logic directly inside a Colab
  notebook cell. Iterate in Codespaces, commit, then pull into Colab to
  run on GPU.
- Do not assume Colab's free-tier GPU (T4-class, ~16GB VRAM) has more
  headroom than it does — keep batch size, model size, and quantization
  choices realistic for that hardware unless the user has explicitly
  confirmed a paid tier is in use.

## Division of responsibility

The agent handles the full mechanics of this split — writing the
Colab notebook, the Drive mounting logic, the checkpoint/resume logic,
and keeping Codespaces and Colab in sync via git. The user reviews
outcomes (does training actually work, do results look right) and makes
decisions the agent cannot make on its own (e.g., whether to upgrade to
Colab Pro if free-tier limits become a real blocker). The user is not
expected to manually shuttle files between environments — if that's
happening, the automation isn't done yet.