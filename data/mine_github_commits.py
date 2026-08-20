import datetime
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

from data.source_cve_advisories import get_github_token
from data.fetch_commit_diffs import filter_diff_secrets, detect_language, fetch_github_commit_diff

SEARCH_COMMITS_API = "https://api.github.com/search/commits"

LOCKED_LANGUAGES = {"python", "javascript", "typescript", "go", "java", "php"}

SEARCH_QUERIES = [
    # --- CWE-862: Missing Authorization (12 queries) ---
    ("fix missing authorization", ["CWE-862"]),
    ("fix missing permission check", ["CWE-862"]),
    ("add permission check", ["CWE-862"]),
    ("add authorization check", ["CWE-862"]),
    ("require authorization", ["CWE-862"]),
    ("add role check", ["CWE-862"]),
    ("fix unauthorized access vulnerability", ["CWE-862"]),
    ("fix missing role check", ["CWE-862"]),
    ("check user permissions", ["CWE-862"]),
    ("add @PreAuthorize", ["CWE-862"]),
    ("add CanAccess check", ["CWE-862"]),
    ("security: missing authz", ["CWE-862"]),

    # --- CWE-863: Incorrect Authorization / Broken Access Control (14 queries) ---
    ("fix authorization bypass", ["CWE-863"]),
    ("fix broken access control", ["CWE-863"]),
    ("fix privilege escalation", ["CWE-863"]),
    ("prevent privilege escalation", ["CWE-863"]),
    ("fix horizontal privilege escalation", ["CWE-863"]),
    ("fix vertical privilege escalation", ["CWE-863"]),
    ("fix RBAC check", ["CWE-863"]),
    ("fix tenant isolation", ["CWE-863"]),
    ("prevent cross tenant access", ["CWE-863"]),
    ("fix role bypass", ["CWE-863"]),
    ("fix permission bypass", ["CWE-863"]),
    ("fix ACL bypass", ["CWE-863"]),
    ("security: enforce tenant boundary", ["CWE-863"]),
    ("fix access control bypass", ["CWE-863"]),

    # --- CWE-639: IDOR / Broken Object Level Authorization (10 queries) ---
    ("fix IDOR", ["CWE-639"]),
    ("fix IDOR vulnerability", ["CWE-639"]),
    ("insecure direct object reference fix", ["CWE-639"]),
    ("prevent IDOR", ["CWE-639"]),
    ("fix object level authorization", ["CWE-639"]),
    ("check object ownership", ["CWE-639"]),
    ("prevent accessing other user data", ["CWE-639"]),
    ("fix BOLA vulnerability", ["CWE-639"]),
    ("broken object level authorization fix", ["CWE-639"]),
    ("fix user id tampering", ["CWE-639"]),

    # --- CWE-287: Improper Authentication (10 queries) ---
    ("fix authentication bypass", ["CWE-287"]),
    ("fix improper authentication", ["CWE-287"]),
    ("JWT verification bypass fix", ["CWE-287"]),
    ("fix JWT signature bypass", ["CWE-287"]),
    ("fix token validation bypass", ["CWE-287"]),
    ("fix session fixation", ["CWE-287"]),
    ("fix MFA bypass", ["CWE-287"]),
    ("fix login bypass", ["CWE-287"]),
    ("validate auth token properly", ["CWE-287"]),
    ("fix password reset token bypass", ["CWE-287"]),
]


def search_github_commits_for_pattern(
    query_text: str,
    cwe_ids: List[str],
    max_pages: int = 3,
    per_page: int = 30,
    github_token: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Search GitHub public commits for security-fix messages and retrieve commit diffs."""
    token = github_token or get_github_token()
    headers = {
        "Accept": "application/vnd.github.cloak-preview+json",
        "User-Agent": "Auth-Authz-Security-Scanner-PatternMiner",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    results = []
    seen_hashes = set()

    for page in range(1, max_pages + 1):
        params = {"q": query_text, "per_page": per_page, "page": page, "sort": "committer-date"}
        try:
            resp = requests.get(SEARCH_COMMITS_API, headers=headers, params=params, timeout=20)
            if resp.status_code in (403, 429):
                print(f"[WARN] GitHub Search API rate limit hit on page {page} for query '{query_text}'. Sleeping 30s...")
                time.sleep(30.0)
                # Retry once
                resp = requests.get(SEARCH_COMMITS_API, headers=headers, params=params, timeout=20)
                if resp.status_code in (403, 429):
                    print(f"[WARN] Rate limit persisted. Moving to next query.")
                    break
            if resp.status_code != 200:
                print(f"[WARN] HTTP {resp.status_code} on page {page} for query '{query_text}'")
                break

            data = resp.json()
            items = data.get("items", [])
            if not items:
                break

            for item in items:
                commit_sha = item.get("sha")
                repo_info = item.get("repository", {})
                owner = repo_info.get("owner", {}).get("login")
                repo_name = repo_info.get("name")

                if not (commit_sha and owner and repo_name):
                    continue

                key = (owner.lower(), repo_name.lower(), commit_sha)
                if key in seen_hashes:
                    continue
                seen_hashes.add(key)

                # Fetch full commit diff with secret sanitization
                diff_data = fetch_github_commit_diff(owner, repo_name, commit_sha, github_token=token)
                if not diff_data:
                    continue

                # Enforce locked 6 target languages
                lang = diff_data.get("language", "")
                if lang not in LOCKED_LANGUAGES:
                    continue

                rec_id = f"pattern-mined-{owner}-{repo_name}-{commit_sha[:8]}"
                results.append({
                    "id": rec_id,
                    "source": "github_pattern_mining",
                    "certainty": "lower",
                    "cwe_ids": cwe_ids,
                    "repo_url": f"https://github.com/{owner}/{repo_name}",
                    "commit_hash": commit_sha,
                    "language": lang,
                    "raw_diff": diff_data["raw_diff"],
                    "commit_message": diff_data["commit_message"],
                    "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                })

            time.sleep(2.5)  # Respect search API rate limits (30 req/min)
        except requests.RequestException as e:
            print(f"[WARN] Search query '{query_text}' failed on page {page}: {e}")
            break

    return results


def mine_all_security_patterns(
    output_path: str = "data/raw/pattern_mined/pattern_mined_commits.json",
    max_pages_per_query: int = 3,
) -> List[Dict[str, Any]]:
    """Mine public GitHub commits across all defined auth/authz query patterns."""
    token = get_github_token()
    if not token:
        print("[WARN] No GitHub token found. Pattern mining requires an authenticated token.")
        return []

    print(f"[INFO] Starting CVE-independent GitHub commit pattern mining across {len(SEARCH_QUERIES)} queries...")
    
    # Load existing mined commits so we accumulate rather than overwrite
    all_mined = []
    seen_ids = set()
    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
                if isinstance(existing, list):
                    for item in existing:
                        all_mined.append(item)
                        seen_ids.add(item["id"])
            print(f"[INFO] Loaded {len(all_mined)} existing pattern-mined records.")
        except Exception:
            pass

    for i, (query, cwes) in enumerate(SEARCH_QUERIES, start=1):
        print(f"[INFO] [{i}/{len(SEARCH_QUERIES)}] Searching GitHub for: '{query}' -> {cwes}...")
        mined = search_github_commits_for_pattern(
            query_text=query,
            cwe_ids=cwes,
            max_pages=max_pages_per_query,
            github_token=token,
        )
        new_count = 0
        for item in mined:
            if item["id"] not in seen_ids:
                seen_ids.add(item["id"])
                all_mined.append(item)
                new_count += 1
        print(f"  Yielded {len(mined)} commits ({new_count} new unique) for '{query}'")

        # Save progress incrementally
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(all_mined, f, indent=2)

    print(f"[OK] Total pattern-mined commits saved: {len(all_mined)} to {output_path}")
    return all_mined


if __name__ == "__main__":
    mine_all_security_patterns()
