"""Rigorous Hash-Based Data Split Leakage Verification Script.

Computes exact and normalized SHA-256 code hashes across Train, Val, and Test splits.
Verifies that:
1. Train <-> Val overlap is 0.
2. Train <-> Test overlap is 0.
3. Val <-> Test overlap is 0.
"""

import os
import sys
import json
import hashlib
import re

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPLITS_DIR = os.path.join(PROJECT_ROOT, "data", "splits")


def normalize_code(code: str) -> str:
    """Normalize whitespace and lowercase for near-duplicate detection."""
    return re.sub(r"\s+", " ", code.strip().lower())


def compute_code_hash(code: str) -> str:
    """Compute SHA-256 hash of normalized code."""
    return hashlib.sha256(normalize_code(code).encode("utf-8")).hexdigest()


def verify_leakage():
    print("=" * 80)
    print("  RIGOROUS HASH-BASED DATA SPLIT LEAKAGE AUDIT")
    print("=" * 80)

    train_path = os.path.join(SPLITS_DIR, "train.json")
    val_path = os.path.join(SPLITS_DIR, "val.json")
    test_path = os.path.join(SPLITS_DIR, "test.json")

    with open(train_path, "r", encoding="utf-8") as f:
        train_data = json.load(f)
    with open(val_path, "r", encoding="utf-8") as f:
        val_data = json.load(f)
    with open(test_path, "r", encoding="utf-8") as f:
        test_data = json.load(f)

    print(f"• Train Samples: {len(train_data)}")
    print(f"• Val Samples:   {len(val_data)}")
    print(f"• Test Samples:  {len(test_data)}")
    print("-" * 80)

    train_exact = {x.get("code", "").strip(): x.get("id") for x in train_data}
    train_norm = {compute_code_hash(x.get("code", "")): x.get("id") for x in train_data}

    val_exact = {x.get("code", "").strip(): x.get("id") for x in val_data}
    val_norm = {compute_code_hash(x.get("code", "")): x.get("id") for x in val_data}

    # 1. Train <-> Val Overlap
    train_val_exact = [x for x in val_data if x.get("code", "").strip() in train_exact]
    train_val_norm = [x for x in val_data if compute_code_hash(x.get("code", "")) in train_norm]

    # 2. Train <-> Test Overlap
    train_test_exact = [x for x in test_data if x.get("code", "").strip() in train_exact]
    train_test_norm = [x for x in test_data if compute_code_hash(x.get("code", "")) in train_norm]

    # 3. Val <-> Test Overlap
    val_test_exact = [x for x in test_data if x.get("code", "").strip() in val_exact]
    val_test_norm = [x for x in test_data if compute_code_hash(x.get("code", "")) in val_norm]

    print(f"1. Train <-> Val Exact Overlap:       {len(train_val_exact)} / {len(val_data)}")
    print(f"   Train <-> Val Normalized Overlap:  {len(train_val_norm)} / {len(val_data)}")
    print(f"2. Train <-> Test Exact Overlap:      {len(train_test_exact)} / {len(test_data)}")
    print(f"   Train <-> Test Normalized Overlap: {len(train_test_norm)} / {len(test_data)}")
    print(f"3. Val <-> Test Exact Overlap:        {len(val_test_exact)} / {len(test_data)}")
    print(f"   Val <-> Test Normalized Overlap:   {len(val_test_norm)} / {len(test_data)}")
    print("=" * 80)

    is_clean = (
        len(train_val_norm) == 0 and
        len(train_test_norm) == 0 and
        len(val_test_norm) == 0
    )

    if is_clean:
        print("[SUCCESS] ZERO DATA LEAKAGE CONFIRMED ACROSS ALL 3 SPLITS!")
    else:
        print("[FAIL] Data leakage detected between splits!")

    print("=" * 80)
    return is_clean


if __name__ == "__main__":
    success = verify_leakage()
    sys.exit(0 if success else 1)
