# Model Training Specification

This document locks down the concrete ML decisions so the agent doesn't
guess or improvise on model architecture, training method, or output
format. If a change is needed here, it must be a deliberate decision, not
a silent substitution.

## Base model

- Start from an existing pretrained code-capable base model in the
  0.5B–1.5B parameter range (e.g., Qwen2.5-Coder-0.5B or
  Qwen2.5-Coder-1.5B). Do not pretrain from scratch — the base model
  already has general code/language understanding; our job is narrow
  specialization on top of it (see 01_PRODUCT_VISION.md scope).
- Before finalizing which specific base model/size, verify current
  license terms allow the intended commercial use, and verify actual
  current benchmark numbers rather than assuming — do not state a
  specific accuracy/benchmark figure without checking it first.
- Do not swap the base model mid-project without flagging it — data
  format, tokenizer, and prompt template are all tied to the specific
  base model chosen.

## Fine-tuning method

- Use parameter-efficient fine-tuning (LoRA or QLoRA), not full
  fine-tuning. Reasons: preserves the base model's general code
  understanding (avoids catastrophic forgetting), works with the data
  volumes described in 05_DATA_PIPELINE.md (thousands, not billions, of
  examples), and is feasible on a single consumer/prosumer GPU.
- Target the attention and relevant projection layers per standard LoRA
  practice for the chosen base model architecture — confirm the correct
  target modules for the specific base model rather than assuming a
  generic layer name applies.
- Track and report actual hyperparameters used (rank, alpha, learning
  rate, epochs, batch size) in training run logs. Do not present a
  training run as complete without these being recorded.

## Task framing — structured input/output, not free-form chat

- Input to the model: one candidate code unit (function + minimal
  necessary context: direct callers/callees or related data-access
  calls when relevant to auth/authz reasoning) plus its language.
- Output must be structured and parseable, not free-form prose. Define
  a fixed schema, for example:
  ```
  {
    "vulnerable": true | false,
    "vuln_class": "IDOR" | "auth_bypass" | "missing_authz_check" | "incorrect_authz" | "none",
    "confidence": 0.0–1.0,
    "explanation": "short plain-language reasoning",
    "flagged_lines": [start, end]
  }
  ```
  Confirm the exact schema against what the scan engine (Layer 2) expects
  before training — the schema is a contract between the model and the
  orchestrator, not something to redesign per training run.
- **Confidence Semantics Contract:**
  The `confidence` field strictly represents **$P(\text{vulnerable} = \text{true})$** — the estimated probability that the code contains an actionable authentication or authorization vulnerability.
  - When `vulnerable: false` (clean), `confidence` is close to `0.0` (e.g. `0.02 - 0.06` for verified clean framework modules, `0.20 - 0.35` for ambiguous code).
  - When `vulnerable: true`, `confidence >= 0.50` (e.g. `0.55 - 0.70` for borderline review candidates, `0.75 - 0.85` for high-confidence review, `0.88 - 0.98` for high-priority actionable alerts).
  - Downstream engine thresholding is strictly monotonic on `confidence`:
    - `confidence >= 0.90`: Direct actionable finding
    - `0.50 <= confidence < 0.90`: Flagged for review / Layer 3 mutation testing
    - `confidence < 0.50`: Suppressed alert / treated as clean
- Train the model to refuse to overclaim: when evidence is weak, the
  correct label is a low confidence score, not a forced binary
  vulnerable/clean call.

## Class balance and evaluation

- Maintain a deliberate balance of vulnerable vs. clean (negative)
  examples during training — an imbalanced dataset produces a model
  biased toward one direction. See 05_DATA_PIPELINE.md for sourcing of
  negative examples.
- Evaluate on a held-out test set that has zero source overlap with
  training data (same rule as 05_DATA_PIPELINE.md's split-by-source
  discipline). Report real metrics: precision, recall, and false
  positive rate specifically — not just overall accuracy, which is
  misleading on imbalanced security data.
- Confidence calibration matters as much as raw accuracy: a model that
  says "60% confidence" should be right about 60% of the time on those
  cases, not just directionally correct. Check calibration, don't assume
  it from accuracy alone.

## Quantization and packaging (for local, lightweight deployment)

- After fine-tuning, quantize the model for local inference (e.g., GGUF
  format via llama.cpp, Q4_K_M or Q5_K_M quantization level as a
  starting point) to minimize disk footprint and RAM usage.
- Verify quantized model accuracy against the same held-out test set
  used for the full-precision model — do not assume quantization is
  "free." If quantization meaningfully degrades auth/authz detection
  quality, document the tradeoff rather than silently shipping it.
- Target a final packaged model size and RAM footprint suitable for
  running on an average developer laptop without a dedicated GPU. Do
  not assume GPU availability at inference time.

## Context window and input size discipline

- Keep the model's practical input small — one function plus minimal
  context, not entire files. This is both an accuracy decision (less
  irrelevant context, better signal) and a performance decision (faster
  inference, matches the scan-engine design in
  02_ARCHITECTURE_AND_CODE_STYLE.md where Layer 2 does the filtering
  before Layer 3 is ever called).

## What NOT to do

- Do not train the model to generate code fixes/patches directly as
  part of its core task — that's out of scope (see 01_PRODUCT_VISION.md;
  fix suggestions, if any, come from the optional BYOK cloud LLM path,
  not from this specialized model).
- Do not expand training data to unrelated vulnerability classes to
  "improve general usefulness" — this model's entire value is being
  narrow and reliable on auth/authz specifically.
- Do not report a training run as successful based on training loss
  alone. Loss going down does not mean the model generalizes — only
  held-out evaluation results confirm that.