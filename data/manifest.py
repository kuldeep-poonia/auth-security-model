import collections
import datetime
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

TARGET_CWES = {"CWE-287", "CWE-862", "CWE-863", "CWE-639"}
REQUIRED_FIELDS = {"id", "source", "cwe_ids", "repo_url", "commit_hash", "language", "raw_diff"}


def validate_raw_record(record: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Verify raw record conforms to provenance schema."""
    required_keys = ["id", "source", "raw_diff", "language"]
    for k in required_keys:
        if k not in record or not record[k]:
            return False, f"Missing required field: {k}"

    is_clean = record.get("vuln_class") == "none" or record.get("is_vulnerable") is False
    cwe_ids = record.get("cwe_ids", [])
    if not is_clean:
        if not cwe_ids or not isinstance(cwe_ids, list):
            return False, "'cwe_ids' must be a non-empty list for vulnerability records"
        invalid_cwes = set(cwe_ids) - TARGET_CWES
        if invalid_cwes:
            return False, f"Record contains out-of-scope CWEs: {invalid_cwes}"

    return True, None


INVALID_LANGUAGES = {"markdown", "yaml", "json", "html", "sql", "shell", "other", "unknown", "ruby"}

def aggregate_raw_staging_manifest(
    records: List[Dict[str, Any]],
    output_path: str = "data/raw_staging_manifest.json",
    summary_path: str = "data/raw_data_summary.md",
) -> Dict[str, Any]:
    """Aggregate, validate, deduplicate, and report raw staging dataset."""
    valid_records = []
    seen_keys = set()
    rejected_count = 0

    for r in records:
        is_valid, reason = validate_raw_record(r)
        if not is_valid:
            rejected_count += 1
            continue

        lang = str(r.get("language", "")).lower()
        if lang in INVALID_LANGUAGES or not lang:
            rejected_count += 1
            continue

        # Dedup key: source + id + commit_hash
        dedup_key = (r["source"], r["id"], str(r.get("commit_hash", "none")))
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)
        valid_records.append(r)

    # Ensure output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(valid_records, f, indent=2)

    # Compute statistics
    cwe_counts = collections.Counter()
    lang_counts = collections.Counter()
    source_counts = collections.Counter()

    for r in valid_records:
        for cwe in r.get("cwe_ids", []):
            cwe_counts[cwe] += 1
        lang_counts[r["language"]] += 1
        source_counts[r["source"]] += 1

    stats = {
        "total_records": len(valid_records),
        "rejected_records": rejected_count,
        "cwe_distribution": dict(cwe_counts),
        "language_distribution": dict(lang_counts),
        "source_distribution": dict(source_counts),
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    # Generate Markdown Summary Report
    summary_content = f"""# Raw Data Staging Summary (Phase 1)

**Generated:** {stats['generated_at']}
**Total Staged Records:** {stats['total_records']}
**Rejected/Invalid Records:** {stats['rejected_records']}

---

## 1. CWE Distribution (Auth/Authz Scope)

| CWE Identifier | Description | Raw Count |
| :--- | :--- | :--- |
| `CWE-287` | Improper Authentication | {stats['cwe_distribution'].get('CWE-287', 0)} |
| `CWE-862` | Missing Authorization | {stats['cwe_distribution'].get('CWE-862', 0)} |
| `CWE-863` | Incorrect Authorization | {stats['cwe_distribution'].get('CWE-863', 0)} |
| `CWE-639` | Authorization Bypass Through User-Controlled Key (IDOR) | {stats['cwe_distribution'].get('CWE-639', 0)} |

---

## 2. Language Distribution

| Programming Language | Raw Examples |
| :--- | :--- |
"""
    for lang, count in lang_counts.most_common():
        summary_content += f"| `{lang}` | {count} |\n"

    summary_content += """
---

## 3. Source Origin Breakdown

| Source Origin | Records Contributed |
| :--- | :--- |
"""
    for src, count in source_counts.most_common():
        summary_content += f"| `{src}` | {count} |\n"

    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(summary_content)

    print(f"[OK] Staging manifest written: {len(valid_records)} items to {output_path}")
    print(f"[OK] Summary report written to {summary_path}")

    return stats


def build_raw_staging_dataset():
    """Load and aggregate all available raw sources into staging manifest."""
    raw_records = []

    # 1. Load benchmark datasets (DiverseVul, CVEfixes, BigVul)
    benchmark_dir = "data/raw/benchmarks"
    if os.path.exists(benchmark_dir):
        for f in os.listdir(benchmark_dir):
            if f.endswith(".json"):
                path = os.path.join(benchmark_dir, f)
                with open(path, "r", encoding="utf-8") as fp:
                    items = json.load(fp)
                    if isinstance(items, list):
                        raw_records.extend(items)

    # 2. Load fetched advisory commits (NVD & GHSA)
    commits_path = "data/raw/commits/fetched_commits.json"
    if os.path.exists(commits_path):
        with open(commits_path, "r", encoding="utf-8") as fp:
            items = json.load(fp)
            if isinstance(items, list):
                for c in items:
                    raw_records.append({
                        "id": c.get("cve_id") or f"commit-{c['commit_hash'][:10]}",
                        "source": "github_advisories",
                        "certainty": "high",
                        "cwe_ids": c.get("cwe_ids", []),
                        "repo_url": f"https://github.com/{c['owner']}/{c['repo']}",
                        "commit_hash": c["commit_hash"],
                        "language": c["language"],
                        "raw_diff": c["raw_diff"],
                        "commit_message": c.get("commit_message", ""),
                        "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    })

    # 3. Load pattern-mined commits
    mined_path = "data/raw/pattern_mined/pattern_mined_commits.json"
    if os.path.exists(mined_path):
        with open(mined_path, "r", encoding="utf-8") as fp:
            items = json.load(fp)
            if isinstance(items, list):
                raw_records.extend(items)

    # 4. Load security disclosure platform reports
    disclosures_path = "data/raw/disclosures/disclosed_reports.json"
    if os.path.exists(disclosures_path):
        with open(disclosures_path, "r", encoding="utf-8") as fp:
            items = json.load(fp)
            if isinstance(items, list):
                raw_records.extend(items)

    # 5. Load genuine real-world framework negatives
    clean_path = "data/raw/framework_negatives/real_framework_negatives.json"
    if os.path.exists(clean_path):
        with open(clean_path, "r", encoding="utf-8") as fp:
            items = json.load(fp)
            if isinstance(items, list):
                raw_records.extend(items)

    print(f"[INFO] Total candidate raw records collected across all sources: {len(raw_records)}")
    stats = aggregate_raw_staging_manifest(raw_records)
    return stats


if __name__ == "__main__":
    build_raw_staging_dataset()
