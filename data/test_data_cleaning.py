import json
import os
import shutil
import tempfile
import pytest

from data.extract_code_units import extract_code_units_from_diff, is_noise_diff, parse_diff_hunks
from data.clean_and_dedup import map_cwe_to_vuln_class, compute_code_hash, clean_raw_record
from data.source_negative_examples import build_negative_examples_from_fixed_pairs
from data.dataset_validator import assemble_and_validate_cleaned_dataset


def test_map_cwe_to_vuln_class_taxonomy():
    assert map_cwe_to_vuln_class(["CWE-287"]) == "auth_bypass"
    assert map_cwe_to_vuln_class(["CWE-862"]) == "missing_authz_check"
    assert map_cwe_to_vuln_class(["CWE-863"]) == "incorrect_authz"
    assert map_cwe_to_vuln_class(["CWE-639"]) == "IDOR"
    # Multi-CWE resolution (priority order)
    assert map_cwe_to_vuln_class(["CWE-20", "CWE-639"]) == "IDOR"
    assert map_cwe_to_vuln_class(["CWE-862", "CWE-287"]) == "missing_authz_check"


def test_extract_code_units_functional_diff():
    diff_text = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -10,4 +10,6 @@
 def view_invoice(user, invoice_id):
-    return db.get(invoice_id)
+    inv = db.get(invoice_id)
+    if inv.owner_id != user.id: raise Forbidden()
+    return inv
"""
    result = extract_code_units_from_diff(diff_text)
    assert result is not None
    before_code, after_code = result
    assert "return db.get(invoice_id)" in before_code
    assert "if inv.owner_id != user.id: raise Forbidden()" in after_code


def test_extract_code_units_rejects_noise():
    comment_only_diff = """diff --git a/auth.go b/auth.go
--- a/auth.go
+++ b/auth.go
@@ -5,2 +5,3 @@
+// updated documentation for auth helper
 func Authenticate() bool {
"""
    assert extract_code_units_from_diff(comment_only_diff) is None


def test_clean_raw_record_and_deduplication():
    raw_record_1 = {
        "id": "CVE-2023-0001",
        "source": "cvefixes",
        "cwe_ids": ["CWE-862"],
        "language": "python",
        "raw_diff": """diff --git a/routes.py b/routes.py
--- a/routes.py
+++ b/routes.py
@@ -1,2 +1,3 @@
 def delete_account(user_id):
+    check_admin()
     db.delete(user_id)
""",
        "commit_message": "Add admin permission check on account deletion",
        "repo_url": "https://github.com/org/repo-a",
        "commit_hash": "aaaa1111",
        "retrieved_at": "2026-08-19T00:00:00Z",
    }
    raw_record_fork = dict(raw_record_1)
    raw_record_fork["repo_url"] = "https://github.com/fork/repo-b"

    cleaned_1 = clean_raw_record(raw_record_1)
    cleaned_fork = clean_raw_record(raw_record_fork)

    assert cleaned_1 is not None
    assert cleaned_1["vuln_class"] == "missing_authz_check"
    assert cleaned_1["is_vulnerable"] is True

    # Hashes should be identical for deduplication
    hash_1 = compute_code_hash(cleaned_1["vulnerable_code"])
    hash_fork = compute_code_hash(cleaned_fork["vulnerable_code"])
    assert hash_1 == hash_fork


def test_build_negative_examples_from_fixed_pairs():
    positive_records = [
        {
            "id": "CVE-2023-0001",
            "source": "cvefixes",
            "cwe_ids": ["CWE-862"],
            "vuln_class": "missing_authz_check",
            "language": "python",
            "vulnerable_code": "def delete_user(id): db.delete(id)",
            "fixed_code": "def delete_user(id, user): if user.is_admin: db.delete(id)",
            "is_vulnerable": True,
            "provenance": {"repo_url": "https://github.com/org/repo", "commit_hash": "1111"},
        }
    ]
    negatives = build_negative_examples_from_fixed_pairs(positive_records)
    assert len(negatives) == 1
    assert negatives[0]["vuln_class"] == "none"
    assert negatives[0]["is_vulnerable"] is False
    assert "user.is_admin" in negatives[0]["code"]


def test_assemble_and_validate_cleaned_dataset():
    temp_dir = tempfile.mkdtemp()
    try:
        pos_path = os.path.join(temp_dir, "pos.json")
        neg_path = os.path.join(temp_dir, "neg.json")
        out_manifest = os.path.join(temp_dir, "cleaned_manifest.json")
        out_summary = os.path.join(temp_dir, "cleaned_summary.md")

        pos_data = [
            {
                "id": "CVE-2023-0001",
                "source": "cvefixes",
                "cwe_ids": ["CWE-639"],
                "vuln_class": "IDOR",
                "language": "python",
                "vulnerable_code": "def get(id): return db.get(id)",
                "fixed_code": "def get(id, user): return db.get(id, user)",
                "explanation": "Missing ownership check",
                "provenance": {"repo_url": "url", "commit_hash": "sha"},
            }
        ]
        neg_data = [
            {
                "id": "CVE-2023-0001-clean-fix",
                "source": "cvefixes",
                "cwe_ids": [],
                "vuln_class": "none",
                "language": "python",
                "code": "def get(id, user): return db.get(id, user)",
                "explanation": "Clean code",
                "provenance": {"repo_url": "url", "commit_hash": "sha"},
            }
        ]

        with open(pos_path, "w", encoding="utf-8") as f:
            json.dump(pos_data, f)
        with open(neg_path, "w", encoding="utf-8") as f:
            json.dump(neg_data, f)

        stats = assemble_and_validate_cleaned_dataset(
            positives_path=pos_path,
            negatives_path=neg_path,
            output_path=out_manifest,
            summary_path=out_summary,
        )

        assert stats["total_samples"] == 2
        assert stats["positive_count"] == 1
        assert stats["negative_count"] == 1
        assert stats["class_distribution"]["IDOR"] == 1
        assert stats["class_distribution"]["none"] == 1
        assert os.path.exists(out_manifest)
        assert os.path.exists(out_summary)
    finally:
        shutil.rmtree(temp_dir)
