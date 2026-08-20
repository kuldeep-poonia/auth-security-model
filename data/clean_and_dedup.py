import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from data.extract_code_units import extract_code_units_from_diff

# Locked deterministic taxonomy per model training spec
CWE_TO_VULN_CLASS = {
    "CWE-287": "auth_bypass",
    "CWE-862": "missing_authz_check",
    "CWE-863": "incorrect_authz",
    "CWE-639": "IDOR",
}

EXPLANATION_TEMPLATES = {
    "auth_bypass": "Improper authentication logic permits unauthorized access or token/session verification bypass.",
    "missing_authz_check": "Endpoint or handler performs state mutation or data access without verifying caller permissions.",
    "incorrect_authz": "Authorization check is improperly configured, allowing privilege escalation or access rule evasion.",
    "IDOR": "Direct object reference accessed via user-controlled key without validating ownership or tenant boundaries.",
    "none": "Clean authorization logic enforcing appropriate authentication and access boundaries.",
}


def map_cwe_to_vuln_class(cwe_ids: List[str]) -> str:
    """Deterministically map a list of CWE IDs to the primary locked vuln_class label."""
    # Priority order if multiple CWEs are tagged
    priority = ["CWE-639", "CWE-862", "CWE-863", "CWE-287"]
    for target in priority:
        if target in cwe_ids:
            return CWE_TO_VULN_CLASS[target]
    for cwe in cwe_ids:
        if cwe in CWE_TO_VULN_CLASS:
            return CWE_TO_VULN_CLASS[cwe]
    return "missing_authz_check"


def compute_code_hash(code_str: str) -> str:
    """Compute a normalized whitespace-invariant hash for deduplication."""
    normalized = re.sub(r"\s+", " ", code_str.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def clean_raw_record(raw_record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Clean and extract code units from a single raw staging record."""
    raw_diff = raw_record.get("raw_diff", "")
    if not raw_diff.strip():
        return None

    code_pair = extract_code_units_from_diff(raw_diff)
    if not code_pair:
        return None

    before_code, after_code = code_pair
    cwe_ids = raw_record.get("cwe_ids", [])
    vuln_class = map_cwe_to_vuln_class(cwe_ids)
    language = raw_record.get("language", "").lower()

    # Short explanation
    custom_explanation = raw_record.get("commit_message", "").strip()
    if not custom_explanation or len(custom_explanation) < 10:
        custom_explanation = EXPLANATION_TEMPLATES.get(vuln_class, "")

    return {
        "id": raw_record.get("id"),
        "source": raw_record.get("source"),
        "cwe_ids": cwe_ids,
        "vuln_class": vuln_class,
        "language": language,
        "vulnerable_code": before_code,
        "fixed_code": after_code,
        "is_vulnerable": True,
        "explanation": custom_explanation,
        "provenance": {
            "repo_url": raw_record.get("repo_url"),
            "commit_hash": raw_record.get("commit_hash"),
            "retrieved_at": raw_record.get("retrieved_at"),
        },
    }


def clean_and_deduplicate_dataset(
    raw_manifest_path: str = "data/raw_staging_manifest.json",
    output_path: str = "data/cleaned_positive_pairs.json",
) -> List[Dict[str, Any]]:
    """Clean all raw records, extract before/after code units, and deduplicate."""
    if not os.path.exists(raw_manifest_path):
        print(f"[WARN] Raw manifest not found at {raw_manifest_path}")
        return []

    with open(raw_manifest_path, "r", encoding="utf-8") as f:
        raw_records = json.load(f)

    cleaned_records = []
    seen_code_hashes: Set[str] = set()
    skipped_noise = 0
    duplicate_count = 0

    for r in raw_records:
        cleaned = clean_raw_record(r)
        if not cleaned:
            skipped_noise += 1
            continue

        # Check content hash of vulnerable code unit
        code_hash = compute_code_hash(cleaned["vulnerable_code"])
        if code_hash in seen_code_hashes:
            duplicate_count += 1
            continue
        seen_code_hashes.add(code_hash)
        cleaned_records.append(cleaned)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(cleaned_records, f, indent=2)

    print(f"[OK] Cleaned {len(cleaned_records)} unique positive pairs (dropped {skipped_noise} noise, {duplicate_count} duplicates).")
    return cleaned_records


if __name__ == "__main__":
    clean_and_deduplicate_dataset()
