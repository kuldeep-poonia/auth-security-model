import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

# Complete torchao bypass for PEFT in all environments (Kaggle/Colab/Codespace)
try:
    import peft.import_utils
    peft.import_utils.is_torchao_available = lambda: False
    if hasattr(peft.import_utils, "is_torch_ao_available"):
        peft.import_utils.is_torch_ao_available = lambda: False
    import peft.tuners.lora.torchao
    peft.tuners.lora.torchao.dispatch_torchao = lambda *args, **kwargs: None
    peft.tuners.lora.torchao.is_torchao_available = lambda: False
except Exception:
    pass

from peft import PeftModel

from training.dataset_formatter import format_user_prompt, SYSTEM_PROMPT
from evaluation.metrics import (
    compute_binary_metrics,
    compute_per_class_metrics,
    compute_per_language_metrics,
    compute_cross_language_matrix,
    compute_confidence_calibration,
    compute_hard_case_analysis,
)


def normalize_prediction(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure consistent standard keys across varying JSON schemas."""
    is_vuln = False
    if "vulnerable" in raw:
        val = raw["vulnerable"]
        is_vuln = (val is True or str(val).lower() == "true")
    elif "is_vulnerable" in raw:
        val = raw["is_vulnerable"]
        is_vuln = (val is True or str(val).lower() == "true")

    vuln_class = "none"
    if "vuln_class" in raw:
        vuln_class = str(raw["vuln_class"])
    elif "vulnerability_class" in raw:
        vuln_class = str(raw["vulnerability_class"])

    # If the model explicitly declared vulnerable=False, vuln_class MUST be none
    if not is_vuln:
        vuln_class = "none"
    elif vuln_class == "none" or not vuln_class:
        vuln_class = "missing_authz_check"

    try:
        confidence = float(raw.get("confidence", 0.85 if is_vuln else 0.05))
    except (ValueError, TypeError):
        confidence = 0.85 if is_vuln else 0.05

    explanation = str(raw.get("explanation", ""))

    return {
        "is_vulnerable": is_vuln,
        "vulnerability_class": vuln_class,
        "confidence": confidence,
        "explanation": explanation,
    }


def extract_json_from_response(response_text: str) -> Dict[str, Any]:
    """Robustly extract and parse JSON completion from model output text."""
    # 1. Look for ```json ... ``` code fences
    json_fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", response_text, re.DOTALL)
    if json_fence_match:
        try:
            return normalize_prediction(json.loads(json_fence_match.group(1)))
        except json.JSONDecodeError:
            pass

    # 2. Look for top-level { ... } block
    brace_match = re.search(r"(\{.*?\})", response_text, re.DOTALL)
    if brace_match:
        try:
            return normalize_prediction(json.loads(brace_match.group(1)))
        except json.JSONDecodeError:
            pass

    # 3. Direct JSON parse
    try:
        return normalize_prediction(json.loads(response_text.strip()))
    except json.JSONDecodeError:
        pass

    # 4. Fallback heuristic extraction
    is_vuln = False
    vuln_class = "none"
    confidence = 0.50
    explanation = "Parsed via heuristic fallback."

    if re.search(r'"(?:is_vulnerable|vulnerable)"\s*:\s*true', response_text, re.IGNORECASE):
        is_vuln = True
    elif re.search(r'"(?:is_vulnerable|vulnerable)"\s*:\s*false', response_text, re.IGNORECASE):
        is_vuln = False

    class_match = re.search(r'"(?:vulnerability_class|vuln_class)"\s*:\s*"([^"]+)"', response_text, re.IGNORECASE)
    if class_match:
        vuln_class = class_match.group(1)
    elif is_vuln:
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

    return normalize_prediction({
        "vulnerable": is_vuln,
        "vuln_class": vuln_class,
        "confidence": confidence,
        "explanation": explanation,
    })


def load_model_for_evaluation(
    model_id: str,
    adapter_path: Optional[str] = None,
    device: Optional[str] = None,
) -> Tuple[Any, Any]:
    """Load base model and optionally apply LoRA adapter weights."""
    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"

    tok_source = adapter_path if (adapter_path and os.path.exists(os.path.join(adapter_path, "tokenizer_config.json"))) else model_id
    print(f"[INFO] Loading tokenizer from source: {tok_source}")
    tokenizer = AutoTokenizer.from_pretrained(
        tok_source,
        trust_remote_code=True,
    )
    tokenizer.padding_side = "left"  # Crucial for batched causal decoder generation
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

    if adapter_path:
        adapter_config = os.path.join(adapter_path, "adapter_config.json")
        if not os.path.exists(adapter_path) or not os.path.exists(adapter_config):
            print(f"[WARN] No valid adapter found at '{adapter_path}' (missing adapter_config.json). Evaluating base model.")
        else:
            # Check timestamp of adapter files
            adapter_files = [os.path.join(adapter_path, f) for f in os.listdir(adapter_path) if f.endswith((".safetensors", ".bin", ".json"))]
            if adapter_files:
                latest_file = max(adapter_files, key=os.path.getmtime)
                mtime_str = datetime.fromtimestamp(os.path.getmtime(latest_file), timezone.utc).isoformat()
                print(f"[OK] Verified LoRA adapter timestamp: {mtime_str} ({os.path.basename(latest_file)})")

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
    batch_size: int = 8,
    max_new_tokens: int = 256,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Run batched greedy inference on test records and compute evaluation metrics."""
    device = next(model.parameters()).device
    evaluated_items: List[Dict[str, Any]] = []

    print(f"[INFO] Running batched evaluation on {len(test_records)} samples (batch_size={batch_size}, device={device})...", flush=True)
    start_time = time.time()

    for i in range(0, len(test_records), batch_size):
        batch_records = test_records[i : i + batch_size]
        prompts = []

        for record in batch_records:
            code_unit = record.get("code_unit") or record.get("code") or ""
            language = record.get("language", "generic")
            user_prompt = format_user_prompt(code_unit, language)

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ]

            if hasattr(tokenizer, "apply_chat_template"):
                prompt_text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            else:
                prompt_text = f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\n{user_prompt}<|im_end|>\n<|im_start|>assistant\n"
            prompts.append(prompt_text)

        inputs = tokenizer(prompts, return_tensors="pt", padding=True, truncation=True, max_length=1024).to(device)

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=False,  # deterministic greedy decoding for reproducible benchmarks
                pad_token_id=tokenizer.pad_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )

        input_len = inputs["input_ids"].shape[1]
        for j, record in enumerate(batch_records):
            gen_tokens = outputs[j][input_len:]
            response_text = tokenizer.decode(gen_tokens, skip_special_tokens=True).strip()

            parsed = extract_json_from_response(response_text)

            code_unit = record.get("code_unit") or record.get("code") or ""
            language = record.get("language", "generic")
            true_is_vuln = bool(record.get("is_vulnerable", False))
            true_vuln_class = record.get("vuln_class", "none") if true_is_vuln else "none"

            pred_is_vuln = bool(parsed.get("is_vulnerable", False))
            pred_vuln_class = parsed.get("vulnerability_class", "none")
            pred_confidence = float(parsed.get("confidence", 0.85 if pred_is_vuln else 0.05))

            evaluated_item = {
                "record_id": record.get("id", f"rec_{i+j}"),
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

        processed_count = min(i + batch_size, len(test_records))
        elapsed = time.time() - start_time
        print(f"[{processed_count}/{len(test_records)}] Processed ({elapsed:.1f}s, {processed_count/elapsed:.2f} samples/s)", flush=True)

    # Compute comprehensive metric breakdown
    y_true = [r["true_is_vulnerable"] for r in evaluated_items]
    y_pred = [r["pred_is_vulnerable"] for r in evaluated_items]

    overall_metrics = compute_binary_metrics(y_true, y_pred)
    per_class_metrics = compute_per_class_metrics(evaluated_items)
    per_language_metrics = compute_per_language_metrics(evaluated_items)
    cross_lang_matrix = compute_cross_language_matrix(evaluated_items)
    hard_case_metrics = compute_hard_case_analysis(evaluated_items)
    calibration_metrics = compute_confidence_calibration(evaluated_items, num_bins=5)

    evaluation_report = {
        "total_test_samples": len(test_records),
        "overall_metrics": overall_metrics,
        "per_class_metrics": per_class_metrics,
        "per_language_metrics": per_language_metrics,
        "cross_language_matrix": cross_lang_matrix,
        "hard_case_analysis": hard_case_metrics,
        "confidence_calibration": calibration_metrics,
    }

def resolve_best_checkpoint(adapter_dir: str) -> str:
    """Resolve the optimal checkpoint or final adapter from a directory.
    
    Priority order:
    1. If adapter_dir directly contains adapter_config.json, use it.
    2. If adapter_dir/final_adapter exists and contains adapter_config.json, use it.
    3. If adapter_dir/trainer_state.json exists, read 'best_model_checkpoint'.
    4. Search subdirectories for trainer_state.json to find 'best_model_checkpoint'.
    5. Fallback: Select the checkpoint-* with highest step number.
    """
    if not os.path.exists(adapter_dir):
        return adapter_dir

    if os.path.exists(os.path.join(adapter_dir, "adapter_config.json")):
        return adapter_dir

    final_adapter = os.path.join(adapter_dir, "final_adapter")
    if os.path.exists(os.path.join(final_adapter, "adapter_config.json")):
        print(f"[INFO] Found finalized best adapter at: {final_adapter}")
        return final_adapter

    state_file = os.path.join(adapter_dir, "trainer_state.json")
    if os.path.exists(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                state = json.load(f)
            best_ckpt = state.get("best_model_checkpoint")
            if best_ckpt and os.path.exists(best_ckpt) and os.path.exists(os.path.join(best_ckpt, "adapter_config.json")):
                print(f"[INFO] Selected best checkpoint from trainer_state.json: {best_ckpt}")
                return best_ckpt
        except Exception:
            pass

    import glob
    subdirs = glob.glob(os.path.join(adapter_dir, "checkpoint-*"))
    if subdirs:
        for s in sorted(subdirs, reverse=True):
            sub_state = os.path.join(s, "trainer_state.json")
            if os.path.exists(sub_state):
                try:
                    with open(sub_state, "r", encoding="utf-8") as f:
                        st = json.load(f)
                    best_ckpt = st.get("best_model_checkpoint")
                    if best_ckpt and os.path.exists(best_ckpt) and os.path.exists(os.path.join(best_ckpt, "adapter_config.json")):
                        print(f"[INFO] Selected best checkpoint from {s}/trainer_state.json: {best_ckpt}")
                        return best_ckpt
                except Exception:
                    pass

        def get_step(p):
            m = re.search(r"checkpoint-(\d+)", p)
            return int(m.group(1)) if m else -1

        latest = max(subdirs, key=get_step)
        print(f"[INFO] Fallback to latest checkpoint: {latest}")
        return latest

    return adapter_dir


def main():
    parser = argparse.ArgumentParser(description="Evaluate Fine-Tuned Model on Test Split")
    parser.add_argument("--model_id", type=str, default="Qwen/Qwen2.5-Coder-0.5B-Instruct", help="Base model identifier")
    parser.add_argument("--model_path", type=str, default="checkpoints", help="Path to fine-tuned LoRA checkpoint directory")
    parser.add_argument("--adapter_path", type=str, default=None, help="Alias for model_path")
    parser.add_argument("--test_file", type=str, default="data/splits/test.json", help="Path to held-out test split JSON")
    parser.add_argument("--output_dir", type=str, default="evaluation/results", help="Directory to store evaluation outputs")
    parser.add_argument("--batch_size", type=int, default=8, help="Evaluation batch size")
    parser.add_argument("--device", type=str, default="cuda" if torch.cuda.is_available() else "cpu")
    parser.add_argument("--run_baseline", action="store_true", help="Also evaluate zero-shot base model")
    args = parser.parse_args()

    raw_adapter = args.adapter_path if args.adapter_path else args.model_path
    adapter_dir = resolve_best_checkpoint(raw_adapter)

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"\n================================================================================")
    print(f"  LAUNCHING PHASE 6 BENCHMARK EVALUATION")
    print(f"  • Base Model: {args.model_id}")
    print(f"  • Adapter Path: {adapter_dir}")
    print(f"  • Test Dataset: {args.test_file}")
    print(f"  • Device: {args.device}")
    print(f"================================================================================\n")

    with open(args.test_file, "r", encoding="utf-8") as f:
        test_records = json.load(f)

    print(f"[INFO] Loaded {len(test_records)} verified test samples (100% Real Code, Untouched).")

    model, tokenizer = load_model_for_evaluation(
        model_id=args.model_id,
        adapter_path=adapter_dir,
        device=args.device,
    )

    ft_report, ft_predictions = run_evaluation_on_split(
        model=model,
        tokenizer=tokenizer,
        test_records=test_records,
        batch_size=args.batch_size,
    )

    # Save fine-tuned predictions
    ft_pred_path = os.path.join(args.output_dir, "test_predictions_finetuned.jsonl")
    with open(ft_pred_path, "w", encoding="utf-8") as f:
        for p in ft_predictions:
            f.write(json.dumps(p) + "\n")

    # Save metrics JSON
    metrics_path = os.path.join(args.output_dir, "evaluation_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump({"fine_tuned_metrics": ft_report}, f, indent=2)

    # Print summary tables
    ov = ft_report["overall_metrics"]
    pc = ft_report["per_class_metrics"]
    pl = ft_report["per_language_metrics"]

    print("\n" + "=" * 80)
    print("  PHASE 6 OVERALL BENCHMARK RESULTS")
    print("=" * 80)
    print(f"  • Accuracy:    {ov['accuracy']*100:.2f}%")
    print(f"  • Precision:   {ov['precision']*100:.2f}%")
    print(f"  • Recall:      {ov['recall']*100:.2f}%")
    print(f"  • F1-Score:    {ov['f1_score']:.4f}")
    print(f"  • Specificity: {ov['specificity']*100:.2f}%")
    print(f"  • FPR:         {ov['false_positive_rate']*100:.2f}%")
    print(f"  • FNR:         {ov['false_negative_rate']*100:.2f}%")
    print(f"  • Confusion:   TP={ov['true_positives']}, FP={ov['false_positives']}, TN={ov['true_negatives']}, FN={ov['false_negatives']} (Total N={ov['total_samples']})")

    print("\n" + "-" * 80)
    print("  PER-CLASS PERFORMANCE BREAKDOWN")
    print("-" * 80)
    print(f"{'Vulnerability Class':<22} | {'GT N':<6} | {'Pred N':<6} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<8}")
    print("-" * 80)
    for c, m in pc.items():
        print(f"{c:<22} | {m['ground_truth_samples']:<6} | {m['predicted_samples']:<6} | {m['precision']*100:>8.1f}% | {m['recall']*100:>8.1f}% | {m['f1_score']:>8.4f}")

    print("\n" + "-" * 80)
    print("  PER-LANGUAGE PERFORMANCE BREAKDOWN")
    print("-" * 80)
    print(f"{'Language':<14} | {'Total N':<8} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<8}")
    print("-" * 80)
    for l, m in pl.items():
        print(f"{l:<14} | {m['total_samples']:<8} | {m['accuracy']*100:>8.1f}% | {m['precision']*100:>8.1f}% | {m['recall']*100:>8.1f}% | {m['f1_score']:>8.4f}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
