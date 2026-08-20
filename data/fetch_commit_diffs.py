import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from data.source_cve_advisories import get_github_token

SECRET_PATH_PATTERNS = [
    re.compile(r"(^|/)\.env(\.[a-zA-Z0-9_-]+)?$", re.IGNORECASE),
    re.compile(r"\.(pem|key|pfx|pkcs12|keystore)$", re.IGNORECASE),
    re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)(.*)$", re.IGNORECASE),
    re.compile(r"(^|/)\.(aws|ssh|gnupg|gcp)/", re.IGNORECASE),
    re.compile(r"(^|/)credentials\.json$", re.IGNORECASE),
    re.compile(r"(^|/)secrets?\.(json|ya?ml|toml)$", re.IGNORECASE),
]

LANGUAGE_EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".php": "php",
    ".rb": "ruby",
}


def is_secret_file(file_path: str) -> bool:
    """Check if file path matches secret or credential file patterns."""
    normalized_path = file_path.strip().replace("\\", "/")
    for pattern in SECRET_PATH_PATTERNS:
        if pattern.search(normalized_path):
            return True
    return False


def detect_language(file_path: str) -> Optional[str]:
    """Detect language from file extension for supported languages."""
    _, ext = os.path.splitext(file_path.lower())
    return LANGUAGE_EXTENSION_MAP.get(ext)


def split_diff_by_file(raw_diff: str) -> List[Tuple[str, str]]:
    """Split a multi-file unified git diff into individual (file_path, file_diff) pairs."""
    file_diffs: List[Tuple[str, str]] = []
    # Match headers like diff --git a/path/to/file.py b/path/to/file.py
    chunks = re.split(r"(?=diff --git )", raw_diff)
    for chunk in chunks:
        if not chunk.strip():
            continue
        header_match = re.search(r"diff --git a/(.*?) b/(.*?)(?:\n|$)", chunk)
        if header_match:
            file_path = header_match.group(2)
            file_diffs.append((file_path, chunk))
        else:
            file_diffs.append(("unknown", chunk))
    return file_diffs


def filter_diff_secrets(raw_diff: str) -> Tuple[str, List[str], List[str]]:
    """Apply file-level secret filtering to a git diff.
    
    Returns:
        (sanitized_diff, kept_files, excluded_secret_files)
    """
    file_chunks = split_diff_by_file(raw_diff)
    kept_chunks = []
    kept_files = []
    excluded_secret_files = []

    for file_path, chunk in file_chunks:
        if is_secret_file(file_path):
            excluded_secret_files.append(file_path)
        else:
            kept_chunks.append(chunk)
            kept_files.append(file_path)

    sanitized_diff = "".join(kept_chunks)
    return sanitized_diff, kept_files, excluded_secret_files


def fetch_github_commit_diff(
    owner: str,
    repo: str,
    commit_hash: str,
    github_token: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Fetch raw commit patch and metadata from GitHub API."""
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_hash}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Auth-Authz-Security-Scanner-DataPipeline",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    try:
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code != 200:
            return None
        data = resp.json()

        commit_message = data.get("commit", {}).get("message", "")
        files_data = data.get("files", [])
        
        # Build unified patch from file patches
        raw_diff_parts = []
        for f in files_data:
            filename = f.get("filename", "")
            patch = f.get("patch", "")
            if patch:
                raw_diff_parts.append(
                    f"diff --git a/{filename} b/{filename}\n--- a/{filename}\n+++ b/{filename}\n{patch}\n"
                )
        raw_diff = "\n".join(raw_diff_parts)

        # Apply file-level secret filtering
        sanitized_diff, kept_files, excluded_secrets = filter_diff_secrets(raw_diff)

        # If commit touched only secret files, drop it entirely
        valid_source_files = [f for f in kept_files if detect_language(f) is not None]
        if not valid_source_files:
            return None

        primary_language = detect_language(valid_source_files[0])

        return {
            "owner": owner,
            "repo": repo,
            "commit_hash": commit_hash,
            "commit_url": f"https://github.com/{owner}/{repo}/commit/{commit_hash}",
            "commit_message": commit_message,
            "raw_diff": sanitized_diff,
            "language": primary_language,
            "modified_files": valid_source_files,
            "excluded_secrets": excluded_secrets,
        }
    except requests.RequestException:
        return None


def fetch_all_advisory_commits(
    advisories: List[Dict[str, Any]],
    output_dir: str = "data/raw/commits",
    github_token: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch all commits referenced in advisories with secret filtering."""
    os.makedirs(output_dir, exist_ok=True)
    fetched_commits = []
    seen_commits = set()

    for adv in advisories:
        cve_id = adv.get("id")
        cwe_ids = adv.get("cwe_ids", [])
        commits = adv.get("commits", [])

        for c_ref in commits:
            key = (c_ref["owner"].lower(), c_ref["repo"].lower(), c_ref["commit_hash"])
            if key in seen_commits:
                continue
            seen_commits.add(key)

            print(f"[INFO] Fetching commit {c_ref['owner']}/{c_ref['repo']}@{c_ref['commit_hash'][:8]}...")
            commit_data = fetch_github_commit_diff(
                c_ref["owner"], c_ref["repo"], c_ref["commit_hash"], github_token=github_token
            )
            if commit_data:
                commit_data["cve_id"] = cve_id
                commit_data["cwe_ids"] = cwe_ids
                fetched_commits.append(commit_data)

    output_path = os.path.join(output_dir, "fetched_commits.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(fetched_commits, f, indent=2)

    print(f"[OK] Fetched and filtered {len(fetched_commits)} valid commit diffs to {output_path}")
    return fetched_commits


if __name__ == "__main__":
    advisory_path = "data/raw/advisories/advisories_manifest.json"
    if os.path.exists(advisory_path):
        with open(advisory_path, "r", encoding="utf-8") as f:
            advs = json.load(f)
        token = get_github_token()
        fetch_all_advisory_commits(advs, github_token=token)
    else:
        print(f"[WARN] Advisory manifest not found at {advisory_path}")
