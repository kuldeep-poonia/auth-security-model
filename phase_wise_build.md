# Phase-Wise Build Plan — Model Repo

This is the execution order. Do not start a phase until the previous
phase's exit criteria are met. Do not mix steps across phases (e.g., do
not start writing training code while data validation from Phase 2 is
still incomplete). Each phase has a clear entry condition, steps, and an
exit condition — do not move forward if the exit condition isn't
genuinely satisfied.

Refer back to 01–07 docs constantly — this plan is the sequence, those
docs are the rules that govern how each step is actually done.

---

## Phase 0 — Repo Setup & Environment

**Entry condition:** Fresh empty repo.

**Steps:**
1. Initialize repo structure per 02_ARCHITECTURE_AND_CODE_STYLE.md
   layout (`data/`, `training/`, `evaluation/`, `packaging/`,
   `inference/`) — create only the folders needed for Phase 1, not all
   of them upfront if not yet needed.
2. Set up Python environment with pinned dependency versions (Hugging
   Face `transformers`, `peft`, `datasets`, `bitsandbytes` or equivalent
   QLoRA tooling, `llama.cpp` bindings/build for later quantization).
   Pin exact versions, not loose ranges.
3. Confirm GPU/hardware availability and record actual specs (VRAM,
   CPU, RAM) that training and later local inference will target — this
   affects decisions in every later phase.
4. Set up a lightweight experiment-tracking mechanism (even a simple
   structured log file is fine) so every data run and training run
   produces a traceable record — this is required by Phase 3 and Phase 4
   reporting requirements, so it must exist before those phases start.

**Exit condition:** Environment runs a trivial "load base model, run one
inference" smoke test successfully. Repo structure exists and is empty
of placeholder/speculative files.

---

## Phase 1 — Data Sourcing (Raw Collection Only)

**Entry condition:** Phase 0 complete.

**Steps:**
1. Build the CVE/advisory filtering step: query NVD / GitHub Security
   Advisories for the specific CWE categories listed in
   05_DATA_PIPELINE.md (CWE-287, CWE-862, CWE-863, CWE-639 — confirm
   final CWE list before starting, don't silently add others).
2. For each matched advisory, resolve and pull the linked fix commit.
   Store the raw commit diff + surrounding file context, unmodified, in
   a raw/staging area — this raw data is NOT training data yet.
3. Pull relevant filtered subsets from existing benchmark datasets
   (CVEfixes, Big-Vul, PrimeVul, OWASP Benchmark) — filter to auth/authz
   relevant entries only at this pull stage, per 05_DATA_PIPELINE.md.
4. Track source provenance for every single raw item pulled (source
   dataset/CVE ID, repo, commit hash, language) — this is required for
   later dedup, split-by-source, and auditing. Do not pull data without
   capturing provenance at the same time.
5. Record raw counts per language and per CWE category — this is the
   first checkpoint for whether multi-language balance (05_DATA_PIPELINE.md)
   is achievable or needs more targeted sourcing.

**Exit condition:** A raw staging dataset exists with provenance
metadata for every item. Counts per language/category are known and
documented. Nothing in this raw staging area has been cleaned,
validated, or labeled yet — it is intentionally rough at this point.

---

## Phase 2 — Data Cleaning & Validation

**Entry condition:** Phase 1 complete, raw staging dataset with
provenance exists.

**Steps:**
1. Extraction: from each raw commit diff, extract only the relevant
   code unit (function/method + minimal necessary context) — strip
   formatting-only changes and unrelated refactors in the same commit.
2. Validation: manually spot-check a meaningful sample (define and
   record the sample size and method) to confirm the "before" version
   genuinely contains the described vulnerability and the "after"
   version genuinely fixes it. Do not trust commit messages or advisory
   text without this check.
3. Deduplication: remove near-duplicate examples (forks, mirrors,
   repeated boilerplate patterns) so no single recurring pattern is
   overrepresented.
4. Normalization: convert everything to the final consistent field
   structure/format needed downstream — confirm this format against
   what Phase 4's training data schema actually requires before
   finalizing it.
5. Negative example sourcing: deliberately source clean, non-vulnerable
   auth/authz code in meaningful proportion to the positive examples —
   this is not an afterthought step, it happens in this phase alongside
   positive example cleaning.
6. Re-check language/category balance after cleaning — cleaning
   typically drops examples, so counts may shift. Source more for any
   category/language that fell below a usable threshold.

**Exit condition:** A cleaned, validated, deduplicated dataset exists
with negative examples included in reasonable proportion, and language/
category balance is documented and acceptable. No raw, unvalidated data
remains mixed into this cleaned set.

---

## Phase 3 — Synthetic Augmentation (Mutation-Based)

**Entry condition:** Phase 2 complete — a real, cleaned dataset exists
as the foundation.

**Steps:**
1. Build the mutation generator: deterministic, template-based mutations
   applied to real clean code (from Phase 2's negative examples) —
   removing a check, flipping a comparison operator, reordering
   validation, breaking an ownership check, etc. Base this on the
   specific auth/authz sub-patterns defined in earlier planning
   (IDOR, missing auth check, JWT validation bypass, privilege
   escalation via role check).
2. Generate synthetic vulnerable/clean pairs from real base code only —
   never from already-synthetic code (no mutating mutations).
3. Track the ratio of real to synthetic examples in the combined
   dataset. Real examples must remain the majority share of what the
   model is evaluated against later (05_DATA_PIPELINE.md).
4. Sanity-check a sample of generated mutations manually — confirm they
   represent realistic patterns a developer could plausibly produce, not
   degenerate or nonsensical code.

**Exit condition:** Synthetic augmented examples exist, clearly tagged
as synthetic (vs. real) in provenance metadata, with a documented real:
synthetic ratio. Test set (Phase 4) will exclude synthetic examples that
mutate from the same source as anything in train — this gets enforced in
Phase 4, but the tagging needed for it happens here.

---

## Phase 4 — Dataset Finalization (Train/Val/Test Split)

**Entry condition:** Phase 2 and Phase 3 complete.

**Steps:**
1. Split by source (repository or CVE ID), not by individual example —
   ensure no data leakage where examples from the same commit/repo end
   up in different splits.
2. Keep the test set free of any synthetic augmentation derived from
   sources also present in train — test set should be dominated by real,
   unseen examples to genuinely measure generalization.
3. Finalize the exact schema fields per 06_MODEL_TRAINING_SPEC.md
   (code unit, language, vuln_class, confidence-relevant label,
   explanation, provenance) — confirm this matches what the training
   script in Phase 5 actually expects before locking it.
4. Generate final dataset statistics report: total examples per split,
   real vs synthetic ratio per split, language distribution per split,
   positive vs negative ratio per split. This report must be reviewed
   before moving to Phase 5.

**Exit condition:** Final train/val/test datasets exist as versioned
artifacts with a written statistics report. No further changes to the
test set are made from this point onward for the remainder of the
project (a genuinely held-out set).

---

## Phase 5 — Fine-Tuning

**Entry condition:** Phase 4 complete, final datasets locked.

**Steps:**
1. Load the chosen base model (06_MODEL_TRAINING_SPEC.md) and confirm
   license terms and current benchmark claims are verified, not assumed.
2. Set up LoRA/QLoRA configuration (target modules, rank, alpha) correct
   for the specific base model architecture — confirm target module
   names against the actual model rather than assuming a generic name.
3. Build the training data loader that maps the finalized schema
   (Phase 4) into the base model's expected prompt/completion format.
4. Run an initial small-scale training pass (subset of data, few steps)
   purely to confirm the pipeline works end-to-end — this is a plumbing
   check, not a real training run.
5. Run the full training run with recorded, real hyperparameters
   (rank, alpha, learning rate, epochs, batch size) — log these values,
   don't just run and discard the config.
6. Save checkpoints at reasonable intervals so a mid-run failure doesn't
   require restarting from scratch.

**Exit condition:** A trained LoRA adapter (or fine-tuned weights) exists
as a versioned artifact, with the exact training configuration recorded
alongside it. Training loss curves are recorded but NOT yet treated as
evidence of success — that only comes from Phase 6 evaluation.

---

## Phase 6 — Evaluation

**Entry condition:** Phase 5 complete, trained model artifact exists.

**Steps:**
1. Run inference on the held-out test set (Phase 4) using the trained
   model.
2. Compute real metrics: precision, recall, false positive rate, false
   negative rate — per vuln_class, not just aggregate.
3. Check confidence calibration specifically: bucket predictions by
   stated confidence and check whether actual accuracy in each bucket
   roughly matches the stated confidence (per 06_MODEL_TRAINING_SPEC.md).
4. Test cross-language generalization directly per
   07_HARDCORE_TESTING.md — evaluate on the same logical vulnerability
   pattern expressed in a language/style underrepresented in training.
5. Test hard cases specifically: vulnerabilities that look clean at a
   glance, and clean code that looks suspicious — report how the model
   handles these separately from aggregate metrics.
6. If results are inadequate, identify the specific failure mode (data
   gap, class imbalance, insufficient examples for a sub-pattern,
   base model limitation) before deciding what to change — do not
   blindly retrain with different hyperparameters without a diagnosis.

**Exit condition:** A written evaluation report exists with real numbers
(not just "looks good"), including per-class metrics, calibration check
results, and hard-case behavior. Model is only promoted to Phase 7 if
this report shows genuinely acceptable performance against criteria
defined before evaluation started — not criteria adjusted after seeing
results.

---

## Phase 7 — Quantization & Packaging

**Entry condition:** Phase 6 complete, model evaluation accepted.

**Steps:**
1. Merge LoRA adapter into base weights (if applicable) to produce a
   single deployable model artifact.
2. Convert to GGUF format (or the chosen local-inference format) via
   llama.cpp or equivalent tooling.
3. Quantize at the target level defined in 06_MODEL_TRAINING_SPEC.md
   (e.g., Q4_K_M or Q5_K_M) as a starting point.
4. Re-run the Phase 6 evaluation suite (or a representative subset)
   against the quantized model specifically — do not assume
   quantization is accuracy-neutral. Compare quantized vs.
   full-precision results directly.
5. If quantization causes meaningful accuracy degradation, test one
   step up in precision (e.g., Q5 instead of Q4) and re-evaluate, rather
   than accepting degraded accuracy silently.
6. Measure and record final artifact size, RAM footprint at inference,
   and inference latency on the target hardware profile (average
   developer laptop, no dedicated GPU — per 06_MODEL_TRAINING_SPEC.md).

**Exit condition:** A packaged, quantized model artifact exists with
documented size, RAM footprint, latency, and a side-by-side accuracy
comparison against the full-precision version. The quantization level
shipped is the one that was actually verified, not just assumed
acceptable.

---

## Phase 8 — Local Inference Wrapper

**Entry condition:** Phase 7 complete, packaged model artifact exists.

**Steps:**
1. Build the thin inference interface (per 02_ARCHITECTURE_AND_CODE_STYLE.md
   scope — load model, accept one code unit + context, return the
   structured prediction schema from 06_MODEL_TRAINING_SPEC.md).
2. Confirm the output strictly matches the schema contract the scan
   engine (separate repo) expects — this interface is a contract
   boundary, treat it as one.
3. Test load time and per-call latency directly, since the scan engine
   will call this repeatedly (including once per mutation during
   mutation testing) — this needs to be genuinely fast, not just
   "works."
4. Handle malformed/unexpected input gracefully (e.g., code unit that's
   empty, too large, or in an unsupported language) — fail with a clear
   error rather than crashing or silently returning a meaningless
   prediction.

**Exit condition:** The inference wrapper is callable as a clean,
documented interface, verified against real latency/load-time
requirements, and its output schema is confirmed compatible with what
the scan engine repo expects.

---

## Phase 9 — Hardcore Testing (Full Pass)

**Entry condition:** Phase 8 complete — full pipeline from raw data to
packaged, callable model exists.

**Steps:**
Follow 07_HARDCORE_TESTING.md in full at this stage, applied to the
finished artifact rather than components in isolation:
1. Run the model against real, messy, previously-unseen codebases (not
   just the held-out test set already used in Phase 6) to catch issues
   that only appear with genuinely novel input.
2. Specifically hunt for false positives and false negatives using
   adversarial hard cases beyond what Phase 6 already covered.
3. Test the packaged artifact under real resource constraints (the
   actual target hardware profile, not the training machine).
4. Document every failure found, its real-world impact, and whether it
   was fixed and re-verified — per 07_HARDCORE_TESTING.md reporting
   rules. A clean result here is treated as suspicious, not reassuring,
   until adversarial effort is genuinely exhausted.

**Exit condition:** A hardcore testing report exists with concrete
findings (not a pass/fail summary), and known failure modes are either
fixed or explicitly documented as accepted limitations for this version.

---

## Phase ordering rules (do not violate)

- Do not begin Phase 3 (synthetic augmentation) before Phase 2 (real
  data cleaning) is genuinely complete — synthetic data must augment a
  real foundation, not substitute for one.
- Do not begin Phase 5 (fine-tuning) before Phase 4's dataset is fully
  locked — changing the dataset mid-training invalidates the run.
- Do not treat Phase 5's training loss as evidence of success — only
  Phase 6 evaluation determines that.
- Do not begin Phase 7 (quantization) before Phase 6 evaluation is
  formally accepted — quantizing an unvalidated model wastes the
  quantization-specific verification effort in Phase 7.
- Phase 9 (hardcore testing) is not optional and is not the same as
  Phase 6 (evaluation). Phase 6 measures the model against a held-out
  set; Phase 9 actively tries to break the finished, packaged system.