"""Inspect raw model generations and compare teacher-forced vs autoregressive predictions."""

import json
import os
import sys

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def inspect_predictions(predictions_path: str = "evaluation/results/test_predictions_finetuned.jsonl", num_samples: int = 10):
    if not os.path.exists(predictions_path):
        print(f"[WARN] Predictions file not found at: {predictions_path}")
        return

    with open(predictions_path, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f]

    print(f"=== Loaded {len(records)} test predictions from {predictions_path} ===\n")

    # Analyze Confusion
    tp = [r for r in records if r["true_is_vulnerable"] and r["pred_is_vulnerable"]]
    fp = [r for r in records if not r["true_is_vulnerable"] and r["pred_is_vulnerable"]]
    tn = [r for r in records if not r["true_is_vulnerable"] and not r["pred_is_vulnerable"]]
    fn = [r for r in records if r["true_is_vulnerable"] and not r["pred_is_vulnerable"]]

    print(f"Total: {len(records)} | TP: {len(tp)} | FP: {len(fp)} | TN: {len(tn)} | FN: {len(fn)}")
    print(f"Accuracy: {(len(tp)+len(tn))/len(records)*100:.2f}% | Precision: {len(tp)/(len(tp)+len(fp))*100:.2f}% | Recall: {len(tp)/(len(tp)+len(fn))*100:.2f}%\n")

    print("=" * 80)
    print("SAMPLE FALSE POSITIVES (Clean Code falsely predicted Vulnerable):")
    print("=" * 80)
    for i, r in enumerate(fp[:num_samples]):
        print(f"\n--- [FP #{i+1}] ID: {r.get('record_id')} | Language: {r.get('language')} ---")
        print(f"True: {r.get('true_is_vulnerable')} ({r.get('true_vuln_class')}) | Predicted: {r.get('pred_is_vulnerable')} ({r.get('pred_vuln_class')}, conf={r.get('pred_confidence')})")
        print(f"Code Unit:\n{r.get('code_unit', '')[:200]}...")
        print(f"Raw Model Generated Response:\n{r.get('raw_response', '')}")
        print("-" * 60)

    print("\n" + "=" * 80)
    print("SAMPLE TRUE NEGATIVES (Clean Code correctly predicted Clean):")
    print("=" * 80)
    for i, r in enumerate(tn[:5]):
        print(f"\n--- [TN #{i+1}] ID: {r.get('record_id')} | Language: {r.get('language')} ---")
        print(f"True: {r.get('true_is_vulnerable')} | Predicted: {r.get('pred_is_vulnerable')} (conf={r.get('pred_confidence')})")
        print(f"Raw Model Generated Response:\n{r.get('raw_response', '')}")
        print("-" * 60)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "evaluation/results/test_predictions_finetuned.jsonl"
    inspect_predictions(path)
