import json
import os
import shutil
import tempfile
import pytest

from data.source_cve_advisories import parse_advisory, extract_commit_urls
from data.fetch_commit_diffs import (
    is_secret_file,
    filter_diff_secrets,
    detect_language,
)
from data.import_benchmark_data import process_benchmark_record, parse_benchmark_cwe
from data.manifest import validate_raw_record, aggregate_raw_staging_manifest


def test_is_secret_file():
    # True positives
    assert is_secret_file(".env")
    assert is_secret_file(".env.production")
    assert is_secret_file("config/.env.local")
    assert is_secret_file("certs/server.pem")
    assert is_secret_file("keys/private.key")
    assert is_secret_file(".aws/credentials")
    assert is_secret_file("config/credentials.json")
    assert is_secret_file("secrets.yaml")
    assert is_secret_file("id_rsa")

    # False positives (should NOT be secret files)
    assert not is_secret_file("src/auth/service.py")
    assert not is_secret_file("controllers/user_controller.js")
    assert not is_secret_file("models/rbac.go")
    assert not is_secret_file("SecurityConfig.java")


def test_filter_diff_secrets_multi_file():
    sample_diff = """diff --git a/.env b/.env
index 1234567..89abcdef 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
-JWT_SECRET=old_secret
+JWT_SECRET=new_secret
diff --git a/src/auth.py b/src/auth.py
index 1111111..2222222 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,3 +10,4 @@
 def check_permission(user, role):
+    if user.is_superadmin: return True
     return role in user.roles
"""
    sanitized, kept, excluded = filter_diff_secrets(sample_diff)
    assert ".env" in excluded
    assert "src/auth.py" in kept
    assert "JWT_SECRET" not in sanitized
    assert "check_permission" in sanitized


def test_secret_only_commit_dropped():
    secret_only_diff = """diff --git a/.env.staging b/.env.staging
--- a/.env.staging
+++ b/.env.staging
@@ -1 +1 @@
-SECRET=1
+SECRET=2
diff --git a/certs/app.pem b/certs/app.pem
--- a/certs/app.pem
+++ b/certs/app.pem
@@ -1 +1 @@
-CERT_OLD
+CERT_NEW
"""
    sanitized, kept, excluded = filter_diff_secrets(secret_only_diff)
    assert len(kept) == 0
    assert len(excluded) == 2
    assert sanitized == ""
    # Check valid source files count
    valid_source = [f for f in kept if detect_language(f) is not None]
    assert len(valid_source) == 0


def test_parse_advisory_auth_filtering():
    valid_advisory = {
        "cve_id": "CVE-2023-12345",
        "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
        "cwes": [{"cwe_id": "CWE-862"}, {"cwe_id": "CWE-20"}],
        "summary": "Missing authorization in user profile API",
        "references": [
            {"url": "https://github.com/example/repo/commit/0123456789abcdef0123456789abcdef01234567"}
        ],
    }
    parsed = parse_advisory(valid_advisory)
    assert parsed is not None
    assert parsed["id"] == "CVE-2023-12345"
    assert parsed["cwe_ids"] == ["CWE-862"]
    assert len(parsed["commits"]) == 1
    assert parsed["commits"][0]["commit_hash"] == "0123456789abcdef0123456789abcdef01234567"

    # Out-of-scope advisory (e.g. SQL Injection CWE-89 only)
    sqli_advisory = {
        "cve_id": "CVE-2023-99999",
        "cwes": [{"cwe_id": "CWE-89"}],
        "summary": "SQL Injection in search query",
        "references": [],
    }
    assert parse_advisory(sqli_advisory) is None


def test_process_benchmark_record():
    authz_record = {
        "cve": "CVE-2022-54321",
        "cwe": ["CWE-639", "CWE-20"],
        "repo_url": "https://github.com/test/repo",
        "commit_hash": "abcdef1234567890abcdef1234567890abcdef12",
        "language": "python",
        "diff": """diff --git a/routes/user.py b/routes/user.py
--- a/routes/user.py
+++ b/routes/user.py
@@ -5,2 +5,3 @@
 def get_doc(doc_id, user):
+    if not user.owns(doc_id): raise Forbidden()
     return db.get(doc_id)
""",
        "commit_message": "Fix IDOR in get_doc",
    }
    processed = process_benchmark_record(authz_record, source_name="primevul")
    assert processed is not None
    assert processed["cwe_ids"] == ["CWE-639"]
    assert processed["language"] == "python"

    # Out of scope record
    xss_record = {
        "cve": "CVE-2022-11111",
        "cwe": ["CWE-79"],
        "language": "javascript",
        "diff": "diff ...",
    }
    assert process_benchmark_record(xss_record, source_name="primevul") is None


def test_real_framework_negatives_provenance():
    clean_path = "data/raw/framework_negatives/real_framework_negatives.json"
    assert os.path.exists(clean_path), "real_framework_negatives.json must exist"
    with open(clean_path, "r", encoding="utf-8") as f:
        records = json.load(f)
    assert len(records) > 0
    # Spot-check first record has valid provenance
    sample = records[0]
    assert sample["source"] == "real_framework_negative"
    assert sample["vuln_class"] == "none"
    assert "provenance" in sample
    assert "raw_github_url" in sample["provenance"]
    assert sample["provenance"]["raw_github_url"].startswith("https://raw.githubusercontent.com/")
    assert sample["language"] in {"python", "javascript", "typescript", "go", "java", "php"}


def test_validate_and_aggregate_manifest():
    temp_dir = tempfile.mkdtemp()
    try:
        manifest_file = os.path.join(temp_dir, "raw_manifest.json")
        summary_file = os.path.join(temp_dir, "raw_summary.md")

        records = [
            {
                "id": "CVE-2023-0001",
                "source": "github_advisories",
                "cwe_ids": ["CWE-287"],
                "repo_url": "https://github.com/org/auth-app",
                "commit_hash": "1111111111111111111111111111111111111111",
                "language": "python",
                "raw_diff": "diff --git a/auth.py b/auth.py\n+check()",
                "commit_message": "Fix login check",
                "retrieved_at": "2026-08-19T10:00:00Z",
            },
            {
                "id": "CVE-2023-0002",
                "source": "primevul",
                "cwe_ids": ["CWE-862"],
                "repo_url": "https://github.com/org/web-service",
                "commit_hash": "2222222222222222222222222222222222222222",
                "language": "javascript",
                "raw_diff": "diff --git a/routes.js b/routes.js\n+guard()",
                "commit_message": "Add middleware guard",
                "retrieved_at": "2026-08-19T10:00:00Z",
            },
            {
                # Invalid record (out of scope CWE)
                "id": "CVE-2023-INVALID",
                "source": "primevul",
                "cwe_ids": ["CWE-89"],
                "repo_url": "https://github.com/org/db",
                "commit_hash": "3333333333333333333333333333333333333333",
                "language": "python",
                "raw_diff": "diff ...",
            },
        ]

        stats = aggregate_raw_staging_manifest(records, manifest_file, summary_file)
        assert stats["total_records"] == 2
        assert stats["rejected_records"] == 1
        assert stats["cwe_distribution"]["CWE-287"] == 1
        assert stats["cwe_distribution"]["CWE-862"] == 1
        assert stats["language_distribution"]["python"] == 1
        assert stats["language_distribution"]["javascript"] == 1
        assert os.path.exists(manifest_file)
        assert os.path.exists(summary_file)
    finally:
        shutil.rmtree(temp_dir)
