import argparse
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

from training.dataset_formatter import format_user_prompt, SYSTEM_PROMPT
from evaluation.metrics import (
    compute_binary_metrics,
    compute_per_class_metrics,
    compute_per_language_metrics,
    compute_cross_language_matrix,
    compute_confidence_calibration,
)


def extract_json_from_response(response_text: str) -> Dict[str, Any]:
    """Robustly extract and parse JSON completion from model output text."""
    # 1. Look for ```json ... ``` code fences
    json_fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", response_text, re.DOTALL)
    if json_fence_match:
        try:
            return json.loads(json_fence_match.group(1))
        except json.JSONDecodeError:
            pass

    # 2. Look for top-level { ... } block
    brace_match = re.search(r"(\{.*?\})", response_text, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(1))
        except json.JSONDecodeError:
            pass

    # 3. Direct JSON parse
    try:
        return json.loads(response_text.strip())
    except json.JSONDecodeError:
        pass

    # 4. Fallback heuristic extraction
    is_vuln = False
    vuln_class = "none"
    confidence = 0.50
    explanation = "Parsed via heuristic fallback."

    if re.search(r'"is_vulnerable"\s*:\s*true', response_text, re.IGNORECASE):
        is_vuln = True
    elif re.search(r'"is_vulnerable"\s*:\s*false', response_text, re.IGNORECASE):
        is_vuln = False

    class_match = re.search(r'"vulnerability_class"\s*:\s*"([^"]+)"', response_text, re.IGNORECASE)
    if class_match:
        vuln_class = class_match.group(1)
    elif is_vuln:
        # Check mentions of common CWEs
        if "auth_bypass" in response_text or "CWE-287" in response_text:
            vuln_class = "auth_bypass"
        elif "missing_authz_check" in response_text or "CWE-862" in response_text:
            vuln_class = "missing_authz_check"
        elif "incorrect_authz" in response_text or "CWE-863" in response_text:
            vuln_class = "incorrect_authz"
        elif "IDOR" in response_text or "CWE-639" in response_text:
            vuln_class = "IDOR"

    conf_match = re.search(r'"confidence"\s*:\s*([0-9.]+)', response_text)
    if conf_match:
        try:
            confidence = float(conf_match.group(1))
        except ValueError:
            confidence = 0.85 if is_vuln else 0.05
    else:
        confidence = 0.85 if is_vuln else 0.05

    return {
        "is_vulnerable": is_vuln,
        "vulnerability_class": vuln_class,
        "confidence": confidence,
        "explanation": explanation,
    }


def load_model_for_evaluation(
    model_id: str,
    adapter_path: Optional[str] = None,
    device: Optional[str] = None,
) -> Tuple[Any, Any]:
    """Load base model and optionally apply LoRA adapter weights."""
    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"

    print(f"[INFO] Loading tokenizer: {adapter_path or model_id}")
    tokenizer = AutoTokenizer.from_pretrained(
        adapter_path if (adapter_path and os.path.exists(adapter_path)) else model_id,
        trust_remote_code=True,
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    torch_dtype = torch.float16 if device == "cuda" else torch.float32

    print(f"[INFO] Loading base model '{model_id}' on {device} (dtype={torch_dtype})")
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch_dtype,
        device_map="auto" if device == "cuda" else None,
        trust_remote_code=True,
    )

    if adapter_path and os.path.exists(adapter_path):
        print(f"[INFO] Merging LoRA adapter from: {adapter_path}")
        model = PeftModel.from_pretrained(model, adapter_path)
    else:
        print("[INFO] Evaluating in zero-shot base mode (no adapter attached).")

    model.eval()
    return model, tokenizer


def run_evaluation_on_split(
    model: Any,
    tokenizer: Any,
    test_records: List[Dict[str, Any]],
    batch_size: int = 1,
    max_new_tokens: int = 256,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Run sequential greedy inference on test records and compute evaluation metrics."""
    device = next(model.parameters()).device
    evaluated_items: List[Dict[str, Any]] = []

    print(f"[INFO] Running evaluation on {len(test_records)} test samples...")
    start_time = time.time()

    for idx, record in enumerate(test_records):
        code_unit = record.get("code_unit", "")
        language = record.get("language", "generic")
        user_prompt = format_user_prompt(code_unit, language)

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        if hasattr(tokenizer, "apply_chat_template"):
            input_text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        else:
            input_text = f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\n{user_prompt}<|im_end|>\n<|im_start|>assistant\n"

        inputs = tokenizer(input_text, return_tensors="pt").to(device)

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=False,  # deterministic greedy decoding for reproducible evaluation
                pad_token_id=tokenizer.pad_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )

        # Extract only generated response tokens
        input_len = inputs["input_ids"].shape[1]
        gen_tokens = outputs[0][input_len:]
        response_text = tokenizer.decode(gen_tokens, skip_special_tokens=True).strip()

        parsed = extract_json_from_response(response_text)

        true_is_vuln = bool(record.get("is_vulnerable", False))
        true_vuln_class = record.get("vuln_class", "none") if true_is_vuln else "none"

        pred_is_vuln = bool(parsed.get("is_vulnerable", False))
        pred_vuln_class = parsed.get("vulnerability_class", "none")
        pred_confidence = float(parsed.get("confidence", 0.85 if pred_is_vuln else 0.05))

        evaluated_item = {
            "record_id": record.get("id", f"rec_{idx}"),
            "language": language,
            "code_unit": code_unit,
            "true_is_vulnerable": true_is_vuln,
            "true_vuln_class": true_vuln_class,
            "pred_is_vulnerable": pred_is_vuln,
            "pred_vuln_class": pred_vuln_class,
            "pred_confidence": pred_confidence,
            "pred_explanation": parsed.get("explanation", ""),
            "raw_response": response_text,
            "is_correct_binary": (pred_is_vuln == true_is_vuln),
            "is_correct_class": (pred_vuln_class == true_vuln_class),
        }
        evaluated_items.append(evaluated_item)

        if (idx + 1) % 25 == 0 or (idx + 1) == len(test_records):
            elapsed = time.time() - start_time
            print(f"[{idx+1}/{len(test_records)}] Processed ({elapsed:.1f}s, {(idx+1)/elapsed:.2f} samples/s)")

    # Compute comprehensive metric breakdown
    y_true = [r["true_is_vulnerable"] for r in evaluated_items]
    y_pred = [r["pred_is_vulnerable"] for r in evaluated_items]

    overall_metrics = compute_binary_metrics(y_true, y_pred)
    per_class_metrics = compute_per_class_metrics(evaluated_items)
    per_language_metrics = compute_per_language_metrics(evaluated_items)
    cross_lang_matrix = compute_cross_language_matrix(evaluated_items)
    calibration_metrics = compute_confidence_calibration(evaluated_items, num_bins=5)

    evaluation_report = {
        "total_test_samples": len(test_records),
        "overall_metrics": overall_metrics,
        "per_class_metrics": per_class_metrics,
        "per_language_metrics": per_language_metrics,
        "cross_language_matrix": cross_lang_matrix,
        "confidence_calibration": calibration_metrics,
    }

    return evaluation_report, evaluated_items
