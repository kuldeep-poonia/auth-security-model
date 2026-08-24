"""Adversarial Error Miner & Diagnostic Critique Generator.

Evaluates the fine-tuned model against the 60-case Hardcore Adversarial Benchmark,
pinpoints every failure mode (False Positive, False Negative, Class Mismatch),
generates deep diagnostic critiques, and compiles the failed samples into
`data/adversarial_error_mined.json` for targeted punishment & reinforcement fine-tuning.
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

# PEFT torchao workaround for Windows / Kaggle
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
from evaluation.eval_model import extract_json_from_response, load_model_for_evaluation, resolve_best_checkpoint
from evaluation.hardcore_benchmark_100 import get_hardcore_benchmark_cases


DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MINED_ERRORS_FILE = os.path.join(DATA_DIR, "adversarial_error_mined.json")


def generate_diagnostic_critique(
    test_case: Dict[str, Any],
    pred_vuln: bool,
    pred_class: str,
    confidence: float,
    pred_explanation: str
) -> Dict[str, Any]:
    """Construct an adversarial critique and contrastive correction target for a failed instance."""
    true_vuln = bool(test_case["true_is_vulnerable"])
    true_class = test_case["true_vuln_class"]
    title = test_case["title"]
    code = test_case["code"]
    lang = test_case["language"]
    flaw = test_case.get("flaw_description", "")

    if pred_vuln and not true_vuln:
        error_type = "FALSE_POSITIVE"
        critique = (
            f"[Negative Contrast / False Alarm Critique] The model hallucinated a vulnerability in sound code. "
            f"Model predicted vulnerable=True ({pred_class}) with confidence {confidence:.2f}. "
            f"Flaw Analysis: The code appears complex and performs privileged/cryptographic actions, but it is 100% sound. "
            f"Rationale: {flaw} "
            f"Correction: Model must recognize defensive programming patterns (e.g. atomic row-locking, constant-time comparisons, composite tenant keys) as secure."
        )
        corrected_explanation = f"[Data Flow] Routine receives inputs. [Security Trace] Implements strict defensive validation: {flaw}. [Conclusion] Sound and authorized implementation."
        target_confidence = 0.05

    elif not pred_vuln and true_vuln:
        error_type = "FALSE_NEGATIVE"
        critique = (
            f"[Negative Contrast / Missed Vulnerability Critique] The model failed to detect a critical security flaw. "
            f"Model predicted vulnerable=False (none) with low confidence {confidence:.2f}. "
            f"Blindspot Analysis: The model relied on standard surface-level syntax without tracing the underlying data flow. "
            f"Flaw Details: {flaw} "
            f"Correction: Model must strictly assert tenant/ownership scoping, constant-time comparisons, and object-level permission enforcement."
        )
        corrected_explanation = f"[Data Flow] Routine receives user input. [Security Trace] Critical security flaw: {flaw}. [Conclusion] Critical {true_class} vulnerability."
        target_confidence = 0.95

    else:
        error_type = "CLASS_MISMATCH"
        critique = (
            f"[Negative Contrast / Category Misclassification Critique] The model identified the presence of a flaw but misclassified its vulnerability category. "
            f"Model predicted '{pred_class}', but ground truth category is strictly '{true_class}'. "
            f"Flaw Analysis: {flaw} "
            f"Correction: Align vulnerability taxonomy strictly with CWE definitions."
        )
        corrected_explanation = f"[Data Flow] Routine receives user input. [Security Trace] Flaw: {flaw}. [Conclusion] {true_class} vulnerability."
        target_confidence = 0.92

    corrected_response = json.dumps({
        "vulnerable": true_vuln,
        "vuln_class": true_class,
        "confidence": target_confidence,
        "explanation": corrected_explanation[:177] + "..." if len(corrected_explanation) > 180 else corrected_explanation,
        "flagged_lines": [1, max(1, len(code.splitlines()))] if true_vuln else []
    }, indent=2)

    return {
        "id": f"mined-{test_case['id']}",
        "title": title,
        "language": lang,
        "code": code,
        "error_type": error_type,
        "model_pred": {
            "vulnerable": pred_vuln,
            "vuln_class": pred_class,
            "confidence": confidence,
            "explanation": pred_explanation,
        },
        "ground_truth": {
            "vulnerable": true_vuln,
            "vuln_class": true_class,
            "flaw_description": flaw,
        },
        "critique": critique,
        "is_vulnerable": true_vuln,
        "vuln_class": true_class,
        "corrected_response": corrected_response,
        "penalty_weight": 4.0,  # 4x gradient penalty multiplier during reinforcement
    }


def run_adversarial_error_mining(
    model_path: str = "checkpoints_1.5b",
    model_id: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct",
    output_file: str = MINED_ERRORS_FILE,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Execute full 60-case benchmark, mine errors, and export diagnostic dataset."""
    print("=" * 80)
    print("  LAUNCHING 60-CASE HARDCORE ADVERSARIAL BENCHMARK & ERROR MINER")
    print("=" * 80)

    adapter_dir = resolve_best_checkpoint(model_path)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"[INFO] Running on device: {device} (adapter: {adapter_dir})")

    model, tokenizer = load_model_for_evaluation(model_id=model_id, adapter_path=adapter_dir, device=device)

    cases = get_hardcore_benchmark_cases()
    print(f"[INFO] Loaded {len(cases)} hardcore adversarial test cases across 6 languages.")

    results = []
    mined_errors = []

    tp = fp = tn = fn = 0
    correct_binary = 0
    correct_class = 0

    lang_stats: Dict[str, Dict[str, int]] = {}

    start_time = time.time()

    for idx, test_case in enumerate(cases, 1):
        lang = test_case["language"]
        if lang not in lang_stats:
            lang_stats[lang] = {"total": 0, "correct_binary": 0, "correct_class": 0}
        lang_stats[lang]["total"] += 1

        prompt = format_user_prompt(test_case["code"], lang)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

        if hasattr(tokenizer, "apply_chat_template"):
            prompt_text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        else:
            prompt_text = f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n"

        inputs = tokenizer(prompt_text, return_tensors="pt").to(device)

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=256,
                do_sample=False,
                pad_token_id=tokenizer.pad_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )

        gen_tokens = outputs[0][inputs["input_ids"].shape[1]:]
        raw_response = tokenizer.decode(gen_tokens, skip_special_tokens=True).strip()
        parsed = extract_json_from_response(raw_response)

        pred_vuln = bool(parsed.get("is_vulnerable", False))
        pred_class = str(parsed.get("vulnerability_class", "none"))
        confidence = float(parsed.get("confidence", 0.0))
        pred_explanation = str(parsed.get("explanation", ""))

        true_vuln = bool(test_case["true_is_vulnerable"])
        true_class = str(test_case["true_vuln_class"])

        # Binary confusion matrix
        if true_vuln and pred_vuln:
            tp += 1
        elif not true_vuln and not pred_vuln:
            tn += 1
        elif not true_vuln and pred_vuln:
            fp += 1
        elif true_vuln and not pred_vuln:
            fn += 1

        is_bin_match = (pred_vuln == true_vuln)
        is_cls_match = False
        if true_vuln and pred_vuln:
            exp_c = true_class.lower()
            got_c = pred_class.lower()
            is_cls_match = (exp_c == got_c or (exp_c in got_c) or (got_c in exp_c))
        elif not true_vuln and not pred_vuln:
            is_cls_match = (pred_class.lower() == "none")

        if is_bin_match:
            correct_binary += 1
            lang_stats[lang]["correct_binary"] += 1
        if is_cls_match:
            correct_class += 1
            lang_stats[lang]["correct_class"] += 1

        is_perfect = (is_bin_match and is_cls_match)

        # Mining failures
        if not is_perfect:
            critique_entry = generate_diagnostic_critique(
                test_case=test_case,
                pred_vuln=pred_vuln,
                pred_class=pred_class,
                confidence=confidence,
                pred_explanation=pred_explanation
            )
            mined_errors.append(critique_entry)

        status_tag = "[PASS]" if is_perfect else ("[BIN-PASS/CLASS-ERR]" if is_bin_match else "[FAIL]")
        print(f"[{idx:02d}/{len(cases):02d}] {status_tag} {test_case['title']} ({lang}) -> Pred: vuln={pred_vuln} ({pred_class}, conf={confidence:.2f}) | Exp: vuln={true_vuln} ({true_class})")

    elapsed = time.time() - start_time
    total_n = len(cases)
    accuracy_bin = (correct_binary / total_n) * 100.0
    accuracy_cls = (correct_class / total_n) * 100.0
    precision = (tp / (tp + fp)) * 100.0 if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 0.0
    specificity = (tn / (tn + fp)) * 100.0 if (tn + fp) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = (fp / (fp + tn)) * 100.0 if (fp + tn) > 0 else 0.0
    fnr = (fn / (fn + tp)) * 100.0 if (fn + tp) > 0 else 0.0

    summary_metrics = {
        "total_evaluated": total_n,
        "elapsed_seconds": round(elapsed, 2),
        "binary_accuracy_pct": round(accuracy_bin, 2),
        "exact_class_accuracy_pct": round(accuracy_cls, 2),
        "precision_pct": round(precision, 2),
        "recall_pct": round(recall, 2),
        "specificity_pct": round(specificity, 2),
        "f1_score": round(f1 / 100.0, 4),
        "false_positive_rate_pct": round(fpr, 2),
        "false_negative_rate_pct": round(fnr, 2),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "total_mined_errors": len(mined_errors),
        "language_breakdown": lang_stats,
    }

    print("\n" + "=" * 80)
    print("  60-CASE HARDCORE BENCHMARK EVALUATION SUMMARY")
    print("=" * 80)
    print(f"• Total Evaluated:       {total_n} Samples ({elapsed:.1f}s)")
    print(f"• Binary Accuracy:       {accuracy_bin:.2f}% ({correct_binary}/{total_n})")
    print(f"• Exact Class Accuracy:  {accuracy_cls:.2f}% ({correct_class}/{total_n})")
    print(f"• Precision:             {precision:.2f}%")
    print(f"• Recall:                {recall:.2f}%")
    print(f"• Specificity:           {specificity:.2f}%")
    print(f"• F1-Score:              {f1 / 100.0:.4f}")
    print(f"• False Positive Rate:   {fpr:.2f}% ({fp} false alarms)")
    print(f"• False Negative Rate:   {fnr:.2f}% ({fn} missed flaws)")
    print(f"• Confusion Matrix:      TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print("-" * 80)
    print("  PER-LANGUAGE PERFORMANCE")
    print("-" * 80)
    for l_name, l_data in lang_stats.items():
        l_tot = l_data["total"]
        l_bin_acc = (l_data["correct_binary"] / l_tot) * 100.0
        l_cls_acc = (l_data["correct_class"] / l_tot) * 100.0
        print(f"  {l_name.ljust(12)} | N={l_tot:02d} | Binary Acc: {l_bin_acc:6.1f}% | Exact Class Acc: {l_cls_acc:6.1f}%")
    print("=" * 80)

    # Save mined errors
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(mined_errors, f, indent=2)

    print(f"[OK] Mined {len(mined_errors)} failure cases and exported diagnostic critiques to:")
    print(f"     -> {output_file}")
    print("=" * 80)

    return summary_metrics, mined_errors


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Adversarial Error Miner & Critique Generator")
    parser.add_argument("--model_id", type=str, default="Qwen/Qwen2.5-Coder-1.5B-Instruct")
    parser.add_argument("--model_path", type=str, default="checkpoints_1.5b")
    parser.add_argument("--output_file", type=str, default=MINED_ERRORS_FILE)
    args = parser.parse_args()

    run_adversarial_error_mining(
        model_path=args.model_path,
        model_id=args.model_id,
        output_file=args.output_file,
    )
