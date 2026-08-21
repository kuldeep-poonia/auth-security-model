"""Smoke-test script to verify dataset size, record distribution, and loss calculation at weight=1.0 vs 3.7."""

import os
import sys
import torch

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from training.dataset_formatter import load_and_format_dataset

train_items = load_and_format_dataset("data/splits/train.json")
val_items = load_and_format_dataset("data/splits/val.json")

vuln_cnt = sum(1 for r in train_items if bool(r.get("is_vulnerable", False) or ('"is_vulnerable": true' in r["messages"][2]["content"].lower())))
clean_cnt = len(train_items) - vuln_cnt
real_cnt = sum(1 for r in train_items if "hardcore_validated_synthetic" not in str(r.get("source", "")))
synth_cnt = len(train_items) - real_cnt

print("=" * 70)
print(f"DATASET LOAD VERIFICATION:")
print(f"  • Total Train Items: {len(train_items)}")
print(f"  • Real Examples: {real_cnt}")
print(f"  • Synthetic Examples: {synth_cnt}")
print(f"  • Vulnerable Count: {vuln_cnt} ({vuln_cnt/len(train_items)*100:.1f}%)")
print(f"  • Clean Count: {clean_cnt} ({clean_cnt/len(train_items)*100:.1f}%)")
print(f"  • Validation Items: {len(val_items)}")
print("=" * 70)

# Verify loss math
mock_standard_loss = torch.tensor(1.82)
for weight in [1.0, 1.07, 3.7]:
    # 50% chance vulnerable in batch
    scaled_vuln = mock_standard_loss * weight
    scaled_clean = mock_standard_loss * 1.0
    avg_loss = (scaled_vuln + scaled_clean) / 2.0
    print(f"Loss Scaling Sanity Check (weight={weight:4.1f}): Vuln Sample={scaled_vuln.item():.3f} | Clean Sample={scaled_clean.item():.3f} | Batch Avg={avg_loss.item():.3f}")
print("=" * 70)
