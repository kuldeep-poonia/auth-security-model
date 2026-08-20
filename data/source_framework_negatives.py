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

# Real framework repositories and their exact auth/authz source file paths
REAL_FRAMEWORK_SOURCES = [
    # 1. Python - Django Auth & Permissions
    {
        "repo": "django/django",
        "branch": "main",
        "language": "python",
        "files": [
            "django/contrib/auth/mixins.py",
            "django/contrib/auth/decorators.py",
            "django/contrib/auth/backends.py",
            "django/contrib/auth/middleware.py",
            "django/contrib/auth/models.py",
        ],
    },
    # 2. Python - FastAPI Security
    {
        "repo": "tiangolo/fastapi",
        "branch": "master",
        "language": "python",
        "files": [
            "fastapi/security/oauth2.py",
            "fastapi/security/http.py",
            "fastapi/security/api_key.py",
            "fastapi/security/base.py",
        ],
    },
    # 3. Go - Casbin RBAC Core & Engine
    {
        "repo": "casbin/casbin",
        "branch": "master",
        "language": "go",
        "files": [
            "enforcer.go",
            "enforcer_synced.go",
            "rbac_api.go",
            "rbac_api_with_domains.go",
            "internal_api.go",
            "management_api.go",
        ],
    },
    # 4. Go - Kubernetes RBAC & Authorization
    {
        "repo": "kubernetes/kubernetes",
        "branch": "master",
        "language": "go",
        "files": [
            "staging/src/k8s.io/apiserver/pkg/authorization/authorizer/interfaces.go",
            "plugin/pkg/auth/authorizer/rbac/rbac.go",
            "plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go",
        ],
    },
    # 5. PHP - Laravel Authorization Gate & Session Guard
    {
        "repo": "laravel/framework",
        "branch": "11.x",
        "language": "php",
        "files": [
            "src/Illuminate/Auth/Access/Gate.php",
            "src/Illuminate/Auth/Access/Response.php",
            "src/Illuminate/Auth/SessionGuard.php",
            "src/Illuminate/Auth/TokenGuard.php",
            "src/Illuminate/Auth/Middleware/Authorize.php",
            "src/Illuminate/Auth/Middleware/Authenticate.php",
        ],
    },
    # 6. Java - Spring Security Core & Access Control
    {
        "repo": "spring-projects/spring-security",
        "branch": "main",
        "language": "java",
        "files": [
            "core/src/main/java/org/springframework/security/access/prepost/PreAuthorize.java",
            "core/src/main/java/org/springframework/security/access/intercept/AbstractSecurityInterceptor.java",
            "core/src/main/java/org/springframework/security/authorization/AuthenticatedAuthorizationManager.java",
            "core/src/main/java/org/springframework/security/authorization/AuthorityAuthorizationManager.java",
            "web/src/main/java/org/springframework/security/web/access/intercept/AuthorizationFilter.java",
        ],
    },
    # 7. TypeScript - NestJS Guards & Execution Context
    {
        "repo": "nestjs/nest",
        "branch": "master",
        "language": "typescript",
        "files": [
            "packages/common/guards/can-activate.interface.ts",
            "packages/common/decorators/http/guards.decorator.ts",
            "packages/core/guards/guards-consumer.ts",
            "packages/core/guards/guards-context-creator.ts",
        ],
    },
    # 8. JavaScript - Passport.js Authentication Strategies
    {
        "repo": "jaredhanson/passport",
        "branch": "master",
        "language": "javascript",
        "files": [
            "lib/authenticator.js",
            "lib/middleware/authenticate.js",
            "lib/middleware/initialize.js",
            "lib/strategies/session.js",
        ],
    },
]


def extract_code_blocks_from_source(source_code: str, language: str, min_lines: int = 5, max_lines: int = 60) -> List[str]:
    """Extract individual top-level functions, methods, or class blocks from real source code."""
    lines = source_code.splitlines()
    blocks = []
    current_block = []

    # Simple heuristic to split source files into logical functional units
    for line in lines:
        stripped = line.strip()
        # Detect function / method definitions across languages
        is_def_start = False
        if language == "python" and (stripped.startswith("def ") or stripped.startswith("class ")):
            is_def_start = True
        elif language in ("javascript", "typescript") and (
            stripped.startswith("function ") or stripped.startswith("export function ") or
            stripped.startswith("export class ") or stripped.startswith("async ") or
            re.match(r"^(public|private|protected)?\s*(async\s+)?\w+\s*\(.*\)\s*[{:]", stripped)
        ):
            is_def_start = True
        elif language == "go" and (stripped.startswith("func ") or stripped.startswith("type ")):
            is_def_start = True
        elif language == "php" and (
            stripped.startswith("public function ") or stripped.startswith("protected function ") or
            stripped.startswith("private function ") or stripped.startswith("class ")
        ):
            is_def_start = True
        elif language == "java" and (
            stripped.startswith("public ") or stripped.startswith("protected ") or
            stripped.startswith("private ") or stripped.startswith("@")
        ):
            is_def_start = True

        if is_def_start and current_block:
            if min_lines <= len(current_block) <= max_lines:
                blocks.append("\n".join(current_block))
            current_block = []

        current_block.append(line)

    if current_block and min_lines <= len(current_block) <= max_lines:
        blocks.append("\n".join(current_block))

    return blocks


def fetch_real_framework_negatives(
    output_path: str = "data/raw/framework_negatives/real_framework_negatives.json",
) -> List[Dict[str, Any]]:
    """Fetch and extract real negative examples from official framework auth repositories."""
    token = get_github_token()
    headers = {"User-Agent": "Auth-Authz-Security-Framework-Extractor"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    all_negatives = []
    seen_hashes = set()

    for spec in REAL_FRAMEWORK_SOURCES:
        repo = spec["repo"]
        branch = spec["branch"]
        lang = spec["language"]
        for file_path in spec["files"]:
            raw_url = f"https://raw.githubusercontent.com/{repo}/{branch}/{file_path}"
            print(f"[INFO] Fetching real source: {raw_url}...")
            try:
                resp = requests.get(raw_url, headers=headers, timeout=20)
                if resp.status_code != 200:
                    print(f"  [WARN] HTTP {resp.status_code} fetching {raw_url}")
                    continue

                source_text = resp.text
                if not source_text or len(source_text.strip()) < 50:
                    continue

                # Extract individual code units from the real source file
                code_units = extract_code_blocks_from_source(source_text, lang)
                print(f"  [OK] Extracted {len(code_units)} real code units from {file_path}")

                for idx, unit in enumerate(code_units, 1):
                    unit_hash = hash(unit.strip())
                    if unit_hash in seen_hashes:
                        continue
                    seen_hashes.add(unit_hash)

                    unit_id = f"real-framework-{repo.replace('/', '-')}-{os.path.basename(file_path)}-unit{idx:02d}"
                    synthetic_diff = f"diff --git a/{file_path} b/{file_path}\n--- a/{file_path}\n+++ b/{file_path}\n@@ -1,5 +1,5 @@\n{unit}"

                    all_negatives.append({
                        "id": unit_id,
                        "source": "real_framework_negative",
                        "certainty": "high",
                        "cwe_ids": [],
                        "vuln_class": "none",
                        "language": lang,
                        "raw_diff": synthetic_diff,
                        "commit_message": f"Real production authorization code from {repo}:{file_path}",
                        "provenance": {
                            "repo_url": f"https://github.com/{repo}",
                            "file_path": file_path,
                            "raw_github_url": raw_url,
                            "branch": branch,
                            "type": "real_repository_source",
                        },
                        "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    })
                time.sleep(0.5)
            except Exception as e:
                print(f"  [WARN] Failed to fetch {raw_url}: {e}")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_negatives, f, indent=2)

    print(f"[OK] Harvested {len(all_negatives)} genuine real-world negative examples to {output_path}")
    return all_negatives


if __name__ == "__main__":
    fetch_real_framework_negatives()
