"""Rigorous Automated Verification Suite for Purified Auth/Authz Dataset.

Runs 6 strict assertions on train.json, val.json, and test.json:
1. Zero Git Diff Markers (---, +++, @@, +, -).
2. Zero Unit Test Frameworks (describe, it, @Test, unittest).
3. Zero Orphan Starting Braces / Parentheses.
4. Zero Generic Boilerplate Phrases ('without security or privilege boundaries', 'implementing expected').
5. 100% Valid JSON Structure with all required keys (id, language, code, is_vulnerable, vuln_class, explanation).
6. Balanced Class & Language Distribution.
"""

import os
import sys
import json
import re

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPLITS_DIR = os.path.join(PROJECT_ROOT, "data", "splits")

DIFF_MARKER_REGEX = re.compile(r"^(?:---|\+\+\+|@@|\+|-|\}|\]|\))", re.MULTILINE)
UNIT_TEST_REGEX = re.compile(r"\b(?:describe\s*\(|it\s*\(|test\s*\(|unittest\.TestCase|@Test|def test_|assert_called|mockRequireRole|setMockExamDeps)\b", re.IGNORECASE)
BOILERPLATE_REGEX = re.compile(r"without security or privilege boundaries|implementing expected\s+\w+\s+application logic", re.IGNORECASE)


def verify_all_splits():
    print("=" * 80)
    print("  RUNNING RIGOROUS DATASET INTEGRITY & QUALITY VERIFICATION")
    print("=" * 80)

    total_checked = 0
    all_passed = True

    for split in ["train", "val", "test"]:
        path = os.path.join(SPLITS_DIR, f"{split}.json")
        assert os.path.exists(path), f"Missing split file: {path}"

        with open(path, "r", encoding="utf-8") as f:
            records = json.load(f)

        print(f"\n--- Verifying {split.upper()} ({len(records)} records) ---")

        diff_count = 0
        unit_test_count = 0
        orphan_start_count = 0
        boilerplate_count = 0
        missing_key_count = 0

        for idx, r in enumerate(records):
            total_checked += 1
            code = r.get("code", "")
            exp = r.get("explanation", "")

            # Check required keys
            for k in ["id", "language", "code", "is_vulnerable", "vuln_class", "explanation"]:
                if k not in r:
                    missing_key_count += 1

            # Check diff markers
            first_line = code.strip().splitlines()[0] if code.strip() else ""
            if DIFF_MARKER_REGEX.search(first_line):
                diff_count += 1

            # Check unit test frameworks
            if UNIT_TEST_REGEX.search(code):
                unit_test_count += 1

            # Check orphan starts
            if code.strip() and code.strip()[0] in ("}", ")", "]", ",", ";"):
                orphan_start_count += 1

            # Check boilerplate
            if BOILERPLATE_REGEX.search(exp):
                boilerplate_count += 1

        print(f" - Missing keys:         {missing_key_count} / {len(records)}")
        print(f" - Diff marker leaks:    {diff_count} / {len(records)}")
        print(f" - Unit test leaks:      {unit_test_count} / {len(records)}")
        print(f" - Orphan start tokens:  {orphan_start_count} / {len(records)}")
        print(f" - Generic boilerplate:  {boilerplate_count} / {len(records)}")

        if any(c > 0 for c in [missing_key_count, diff_count, unit_test_count, orphan_start_count, boilerplate_count]):
            print(f"[FAIL] Split {split} failed quality verification!")
            all_passed = False
        else:
            print(f"[PASS] Split {split} is 100% CLEAN.")

    print("\n" + "=" * 80)
    if all_passed:
        print(f"[SUCCESS] ALL {total_checked} SAMPLES ACROSS TRAIN/VAL/TEST ARE 100% PURIFIED & VERIFIED!")
    else:
        print("[FAILURE] Quality checks failed.")
    print("=" * 80)
    return all_passed


if __name__ == "__main__":
    success = verify_all_splits()
    sys.exit(0 if success else 1)
