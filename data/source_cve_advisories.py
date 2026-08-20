import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional
import requests

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

TARGET_CWES = {"CWE-287", "CWE-862", "CWE-863", "CWE-639"}
TARGET_ECOSYSTEMS = [None, "pip", "npm", "maven", "go", "rubygems", "composer", "nuget"]
GITHUB_ADVISORY_API = "https://api.github.com/advisories"
COMMIT_URL_REGEX = re.compile(
    r"https?://github\.com/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+)/commit/([0-9a-fA-F]{40})"
)


def extract_commit_urls(references: List[Any]) -> List[Dict[str, str]]:
    """Extract GitHub commit references (owner, repo, commit_hash) from advisory reference URLs."""
    commits = []
    seen = set()
    for ref in references:
        if isinstance(ref, dict):
            url = ref.get("url", "")
        elif isinstance(ref, str):
            url = ref
        else:
            continue

        match = COMMIT_URL_REGEX.match(url)
        if match:
            owner, repo, commit_hash = match.groups()
            key = (owner.lower(), repo.lower(), commit_hash)
            if key not in seen:
                seen.add(key)
                commits.append({
                    "owner": owner,
                    "repo": repo,
                    "commit_hash": commit_hash,
                    "url": url,
                })
    return commits


def parse_advisory(advisory: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse raw GitHub advisory item into standardized record if it matches target CWEs."""
    cwe_items = advisory.get("cwes", [])
    cwe_ids = [cwe.get("cwe_id") for cwe in cwe_items if isinstance(cwe, dict) and cwe.get("cwe_id")]
    matched_cwes = [cwe for cwe in cwe_ids if cwe in TARGET_CWES]

    if not matched_cwes:
        return None

    cve_id = advisory.get("cve_id")
    ghsa_id = advisory.get("ghsa_id")
    identifier = cve_id or ghsa_id
    if not identifier:
        return None

    references = advisory.get("references", [])
    commit_refs = extract_commit_urls(references)

    return {
        "id": identifier,
        "cve_id": cve_id,
        "ghsa_id": ghsa_id,
        "source": "github_advisories",
        "cwe_ids": matched_cwes,
        "summary": advisory.get("summary", ""),
        "description": advisory.get("description", ""),
        "severity": advisory.get("severity", "unknown"),
        "published_at": advisory.get("published_at", ""),
        "commits": commit_refs,
    }


def get_github_token() -> Optional[str]:
    """Retrieve GitHub token from environment or gh CLI if available."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token.strip()
    try:
        import subprocess
        res = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    return None


def fetch_advisories_for_cwe(
    cwe_id: str,
    ecosystem: Optional[str] = None,
    max_pages: int = 15,
    per_page: int = 100,
    github_token: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Query GitHub Advisory API for a specific CWE category and optional ecosystem."""
    token = github_token or get_github_token()
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Auth-Authz-Security-Scanner-DataPipeline",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    advisories = []
    for page in range(1, max_pages + 1):
        params: Dict[str, Any] = {"cwe": cwe_id, "per_page": per_page, "page": page}
        if ecosystem:
            params["ecosystem"] = ecosystem

        try:
            resp = requests.get(GITHUB_ADVISORY_API, headers=headers, params=params, timeout=20)
            if resp.status_code == 403:
                print(f"[WARN] GitHub API rate limit reached for {cwe_id} ({ecosystem}) on page {page}.")
                break
            if resp.status_code != 200:
                print(f"[WARN] HTTP {resp.status_code} for {cwe_id} ({ecosystem}) page {page}")
                break

            page_data = resp.json()
            if not isinstance(page_data, list) or len(page_data) == 0:
                break

            for item in page_data:
                parsed = parse_advisory(item)
                if parsed:
                    advisories.append(parsed)

            if len(page_data) < per_page:
                break

            time.sleep(0.1)
        except requests.RequestException as e:
            print(f"[WARN] Request failed for {cwe_id} {ecosystem}: {e}")
            break

    return advisories


def collect_all_target_cves(
    output_dir: str = "data/raw/advisories",
    github_token: Optional[str] = None,
    max_pages: int = 15,
) -> List[Dict[str, Any]]:
    """Query all target auth/authz CWEs across ecosystems and save raw advisory manifests."""
    token = github_token or get_github_token()
    if token:
        print("[INFO] Authenticated with GitHub token.")
    else:
        print("[WARN] No GitHub token found; running unauthenticated.")

    os.makedirs(output_dir, exist_ok=True)
    all_advisories = []
    seen_ids = set()

    for cwe in sorted(TARGET_CWES):
        print(f"[INFO] Collecting {cwe} across target ecosystems...")
        for eco in TARGET_ECOSYSTEMS:
            results = fetch_advisories_for_cwe(
                cwe, ecosystem=eco, max_pages=max_pages, github_token=token
            )
            for item in results:
                if item["id"] not in seen_ids:
                    seen_ids.add(item["id"])
                    all_advisories.append(item)

    manifest_path = os.path.join(output_dir, "advisories_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(all_advisories, f, indent=2)

    print(f"[OK] Saved {len(all_advisories)} unique raw advisory records to {manifest_path}")
    return all_advisories


if __name__ == "__main__":
    token = os.environ.get("GITHUB_TOKEN")
    collect_all_target_cves(github_token=token)
