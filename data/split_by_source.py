import collections
import json
import os
import random
import re
import sys
from typing import Any, Dict, List, Set, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def extract_source_key(record: Dict[str, Any]) -> str:
    """Extract a canonical source cluster key (repo, CVE ID, or benchmark row) for split-by-source discipline."""
    prov = record.get("provenance", {})
    repo_url = prov.get("repo_url") or prov.get("raw_github_url") or ""
    if "github.com/" in repo_url:
        match = re.search(r"github\.com/([^/]+/[^/]+)", repo_url)
        if match:
            repo_name = match.group(1).lower()
            if repo_name.endswith(".git"):
                repo_name = repo_name[:-4]
            return f"repo-{repo_name}"

    rec_id = str(record.get("id", "")).lower()
    cve_match = re.match(r"(cve-\d+-\d+)", rec_id)
    if cve_match:
        return f"cve-{cve_match.group(1)}"

    cv_match = re.match(r"(crossvul-\d+)", rec_id)
    if cv_match:
        return f"cv-{cv_match.group(1)}"

    pm_match = re.match(r"(pattern-mined-[^-]+-[^-]+)", rec_id)
    if pm_match:
        return pm_match.group(1)

    if "framework" in prov:
        return f"framework-{prov['framework']}".lower()

    if repo_url and repo_url not in ("crossvul", "cvefixes"):
        return f"repo-{repo_url.lower()}"

    return f"item-{rec_id}"


def partition_dataset_by_source(
    manifest_path: str = "data/cleaned_dataset_manifest.json",
    output_dir: str = "data/splits",
    train_ratio: float = 0.80,
    val_ratio: float = 0.10,
    test_ratio: float = 0.10,
    seed: int = 42,
) -> Dict[str, Any]:
    """Partition real cleaned records by source repository/CVE cluster to prevent data leakage."""
    random.seed(seed)

    if not os.path.exists(manifest_path):
        raise FileNotFoundError(f"Cleaned dataset manifest not found: {manifest_path}")

    with open(manifest_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    # Group records by source key
    source_clusters: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    for r in records:
        key = extract_source_key(r)
        source_clusters[key].append(r)

    cluster_keys = sorted(list(source_clusters.keys()))
    random.shuffle(cluster_keys)

    # Distribute clusters
    train_clusters: Set[str] = set()
    val_clusters: Set[str] = set()
    test_clusters: Set[str] = set()

    total_records = len(records)
    target_train = int(total_records * train_ratio)
    target_val = int(total_records * val_ratio)

    current_train_count = 0
    current_val_count = 0

    for key in cluster_keys:
        cluster_size = len(source_clusters[key])
        if current_train_count + cluster_size <= target_train:
            train_clusters.add(key)
            current_train_count += cluster_size
        elif current_val_count + cluster_size <= target_val:
            val_clusters.add(key)
            current_val_count += cluster_size
        else:
            test_clusters.add(key)

    # If test is empty or too small, ensure balance
    if not test_clusters and len(cluster_keys) > 2:
        reassigned = cluster_keys.pop()
        test_clusters.add(reassigned)
        train_clusters.discard(reassigned)
        val_clusters.discard(reassigned)

    train_records = []
    val_records = []
    test_records = []

    for key, items in source_clusters.items():
        if key in train_clusters:
            train_records.extend(items)
        elif key in val_clusters:
            val_records.extend(items)
        else:
            test_records.extend(items)

    # Verification: Assert zero source overlap
    assert not (train_clusters & val_clusters), "Train and Val clusters overlap!"
    assert not (train_clusters & test_clusters), "Train and Test clusters overlap!"
    assert not (val_clusters & test_clusters), "Val and Test clusters overlap!"

    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "train_seed.json"), "w", encoding="utf-8") as f:
        json.dump(train_records, f, indent=2)
    with open(os.path.join(output_dir, "val_seed.json"), "w", encoding="utf-8") as f:
        json.dump(val_records, f, indent=2)
    with open(os.path.join(output_dir, "test.json"), "w", encoding="utf-8") as f:
        json.dump(test_records, f, indent=2)

    stats = {
        "total_records": total_records,
        "total_unique_sources": len(cluster_keys),
        "train_sources": len(train_clusters),
        "val_sources": len(val_clusters),
        "test_sources": len(test_clusters),
        "train_seed_records": len(train_records),
        "val_seed_records": len(val_records),
        "test_records": len(test_records),
        "train_pos": sum(1 for r in train_records if r["is_vulnerable"]),
        "train_neg": sum(1 for r in train_records if not r["is_vulnerable"]),
        "val_pos": sum(1 for r in val_records if r["is_vulnerable"]),
        "val_neg": sum(1 for r in val_records if not r["is_vulnerable"]),
        "test_pos": sum(1 for r in test_records if r["is_vulnerable"]),
        "test_neg": sum(1 for r in test_records if not r["is_vulnerable"]),
    }

    print(f"[OK] Source-First Split Completed ({len(cluster_keys)} source clusters):")
    print(f"  - Train Seed: {stats['train_seed_records']} records ({stats['train_sources']} sources | {stats['train_pos']} pos, {stats['train_neg']} neg)")
    print(f"  - Val Seed:   {stats['val_seed_records']} records ({stats['val_sources']} sources | {stats['val_pos']} pos, {stats['val_neg']} neg)")
    print(f"  - Test Set:   {stats['test_records']} records ({stats['test_sources']} sources | {stats['test_pos']} pos, {stats['test_neg']} neg [100% Real])")

    return stats


if __name__ == "__main__":
    partition_dataset_by_source()
