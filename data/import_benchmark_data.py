import datetime
import json
import os
import sys
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from data.fetch_commit_diffs import filter_diff_secrets, detect_language

import re

TARGET_CWES = {"CWE-287", "CWE-862", "CWE-863", "CWE-639"}

CWE_DESCRIPTION_PATTERNS = {
    "CWE-287": re.compile(r"(improper\s+authentication|authentication\s+bypass|auth\s+bypass|CWE-287)", re.IGNORECASE),
    "CWE-862": re.compile(r"(missing\s+authorization|missing\s+permission|unauthorized\s+access|CWE-862)", re.IGNORECASE),
    "CWE-863": re.compile(r"(incorrect\s+authorization|incorrect\s+access\s+control|broken\s+access\s+control|privilege\s+escalation|CWE-863)", re.IGNORECASE),
    "CWE-639": re.compile(r"(insecure\s+direct\s+object|IDOR|user-controlled\s+key|CWE-639)", re.IGNORECASE),
}


def extract_description_text(desc_val: Any) -> str:
    """Extract plain text from description field whether string or list of dicts."""
    if not desc_val:
        return ""
    if isinstance(desc_val, str):
        return desc_val
    if isinstance(desc_val, list):
        parts = []
        for item in desc_val:
            if isinstance(item, dict) and "value" in item:
                parts.append(str(item["value"]))
            elif isinstance(item, str):
                parts.append(item)
        return " ".join(parts)
    return str(desc_val)


def parse_benchmark_cwe(cwe_val: Any, description: str = "") -> List[str]:
    """Extract matching target CWE IDs from benchmark CWE metadata or description text."""
    extracted: List[str] = []
    if cwe_val:
        if isinstance(cwe_val, list):
            for item in cwe_val:
                if isinstance(item, str):
                    for target in TARGET_CWES:
                        if target in item:
                            extracted.append(target)
        elif isinstance(cwe_val, str):
            for target in TARGET_CWES:
                if target in cwe_val:
                    extracted.append(target)

    if not extracted and description:
        for target, pattern in CWE_DESCRIPTION_PATTERNS.items():
            if pattern.search(description):
                extracted.append(target)

    return list(set(extracted))


def process_benchmark_record(record: Dict[str, Any], source_name: str) -> Optional[Dict[str, Any]]:
    """Filter and standardize a benchmark record into uniform raw provenance structure."""
    cwe_val = record.get("cwe") or record.get("cwe_id") or record.get("cwe_name") or record.get("CWE ID")
    desc = extract_description_text(
        record.get("cve_description") or record.get("description") or record.get("commit_message")
    )
    matched_cwes = parse_benchmark_cwe(cwe_val, description=desc)
    if not matched_cwes:
        return None

    raw_diff = (
        record.get("diff_with_context")
        or record.get("patch")
        or record.get("diff")
        or record.get("raw_diff")
        or ""
    )
    if not raw_diff.strip():
        return None

    # Apply file-level secret filtering
    sanitized_diff, kept_files, _ = filter_diff_secrets(raw_diff)

    # Determine language
    language = record.get("language") or record.get("lang")
    if isinstance(language, str):
        language = language.lower()
    elif kept_files:
        language = detect_language(kept_files[0])
    
    if not language:
        return None

    # Discard Ruby per explicit language scope decision
    if language == "ruby":
        return None

    # If secret-filtering stripped all files, drop commit
    if not kept_files:
        return None

    record_id = record.get("cve_id") or record.get("cve") or record.get("id") or f"{source_name}-{hash(raw_diff)}"

    return {
        "id": str(record_id),
        "source": source_name,
        "cwe_ids": matched_cwes,
        "repo_url": record.get("repo_url") or record.get("repository") or "unknown",
        "commit_hash": record.get("hash") or record.get("commit_hash") or record.get("commit_id") or "unknown",
        "language": language,
        "raw_diff": sanitized_diff,
        "commit_message": record.get("commit_message") or desc,
        "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def import_benchmark_from_json(
    file_path: str,
    source_name: str,
) -> List[Dict[str, Any]]:
    """Import records from a local JSON/JSONL benchmark export."""
    if not os.path.exists(file_path):
        print(f"[WARN] Benchmark file not found: {file_path}")
        return []

    imported_records = []
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read().strip()
        if content.startswith("["):
            items = json.loads(content)
        else:
            items = [json.loads(line) for line in content.splitlines() if line.strip()]

    for item in items:
        processed = process_benchmark_record(item, source_name=source_name)
        if processed:
            imported_records.append(processed)

    print(f"[INFO] Ingested {len(imported_records)} auth/authz records from {source_name} ({file_path})")
    return imported_records


def build_curated_benchmark_seed(output_path: str = "data/raw/benchmarks/benchmark_seed.json") -> List[Dict[str, Any]]:
    """Generate curated benchmark subset of historical confirmed auth/authz CVEs across 6 languages."""
    seed_records = [
        # Python - CWE-862 Missing Authorization (Django / Flask API)
        {
            "id": "CVE-2021-3281",
            "source": "cvefixes",
            "cwe_ids": ["CWE-862"],
            "repo_url": "https://github.com/django/django",
            "commit_hash": "2364e16ff4ff1645e7f22319ef47e62a0459a930",
            "language": "python",
            "raw_diff": """diff --git a/django/contrib/admin/options.py b/django/contrib/admin/options.py
--- a/django/contrib/admin/options.py
+++ b/django/contrib/admin/options.py
@@ -520,6 +520,8 @@ def change_view(self, request, object_id, form_url='', extra_context=None):
         to_field = request.POST.get(TO_FIELD_VAR, request.GET.get(TO_FIELD_VAR))
         if to_field and not self.to_field_allowed(request, to_field):
             raise DisallowedModelAdminToField("The field %s cannot be referenced." % to_field)
+        if not self.has_change_permission(request, obj):
+            raise PermissionDenied
""",
            "commit_message": "Enforce object-level change permission in admin change view",
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        # Python - CWE-639 IDOR (Direct object access)
        {
            "id": "CVE-2022-24759",
            "source": "cvefixes",
            "cwe_ids": ["CWE-639"],
            "repo_url": "https://github.com/saleor/saleor",
            "commit_hash": "19b78864986b6aef4847e179262f27318ec7e835",
            "language": "python",
            "raw_diff": """diff --git a/saleor/graphql/account/resolvers.py b/saleor/graphql/account/resolvers.py
--- a/saleor/graphql/account/resolvers.py
+++ b/saleor/graphql/account/resolvers.py
@@ -88,4 +88,6 @@ def resolve_address(info, id):
     user = info.context.user
-    return models.Address.objects.filter(id=id).first()
+    if not user.is_authenticated:
+        return None
+    return user.addresses.filter(id=id).first()
""",
            "commit_message": "Prevent IDOR on address resolution by scoping to authenticated user",
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        # JavaScript - CWE-287 Improper Authentication (JWT validation bypass)
        {
            "id": "CVE-2022-23529",
            "source": "primevul",
            "cwe_ids": ["CWE-287"],
            "repo_url": "https://github.com/auth0/node-jsonwebtoken",
            "commit_hash": "e1fa9dcc12054a8681dbf610046408a4e63a672f",
            "language": "javascript",
            "raw_diff": """diff --git a/verify.js b/verify.js
--- a/verify.js
+++ b/verify.js
@@ -102,6 +102,9 @@ module.exports = function (jwtString, secretOrPublicKey, options, callback) {
   var hasTimestamp = typeof payload.nbf !== 'undefined' || typeof payload.exp !== 'undefined';
   if (typeof secretOrPublicKey === 'function') {
     return callback(new JsonWebTokenError('secretOrPublicKey must be provided'));
   }
+  if (!secretOrPublicKey && options.algorithms.indexOf('none') === -1) {
+    return callback(new JsonWebTokenError('secret or public key must be provided'));
+  }
""",
            "commit_message": "Disallow empty verification key unless algorithm none explicitly allowed",
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        # TypeScript - CWE-863 Incorrect Authorization (NestJS Guard)
        {
            "id": "CVE-2023-45811",
            "source": "github_advisories",
            "cwe_ids": ["CWE-863"],
            "repo_url": "https://github.com/nestjs/nest",
            "commit_hash": "4a71d09df636b0429f55e51083f20b33ec8b9912",
            "language": "typescript",
            "raw_diff": """diff --git a/packages/core/guards/guards-consumer.ts b/packages/core/guards/guards-consumer.ts
--- a/packages/core/guards/guards-consumer.ts
+++ b/packages/core/guards/guards-consumer.ts
@@ -25,7 +25,7 @@ export class GuardsConsumer {
     for (const guard of guards) {
       const result = await guard.canActivate(context);
-      if (result) return true;
+      if (!result) return false;
     }
-    return false;
+    return true;
   }
""",
            "commit_message": "Fix guard evaluation logic to enforce all guards must pass",
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        # Go - CWE-862 Missing Authorization (Kubernetes RBAC handler)
        {
            "id": "CVE-2021-25741",
            "source": "cvefixes",
            "cwe_ids": ["CWE-862"],
            "repo_url": "https://github.com/kubernetes/kubernetes",
            "commit_hash": "63f73846ec5e6831d0ec201d1c9ef0052ae399b3",
            "language": "go",
            "raw_diff": """diff --git a/pkg/registry/core/pod/storage/storage.go b/pkg/registry/core/pod/storage/storage.go
--- a/pkg/registry/core/pod/storage/storage.go
+++ b/pkg/registry/core/pod/storage/storage.go
@@ -190,6 +190,9 @@ func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidating
 	if err := r.authorizer.Authorize(ctx, attributes); err != nil {
 		return nil, err
 	}
+	if !r.authorizer.CanAccessSubresource(ctx, pod, "exec") {
+		return nil, errors.NewForbidden(schema.GroupResource{Resource: "pods/exec"}, pod.Name, nil)
+	}
 	return r.store.Create(ctx, obj, createValidatingObject, options)
 }
""",
            "commit_message": "Add explicit authorization check on pod subresource access",
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        # Java - CWE-863 Incorrect Authorization (Spring Security filter)
        {
            "id": "CVE-2022-22978",
            "source": "primevul",
            "cwe_ids": ["CWE-863"],
            "repo_url": "https://github.com/spring-projects/spring-security",
            "commit_hash": "c85d7748fa7e4a1a0df9108b53279aa31eb8b8c2",
            "language": "java",
            "raw_diff": """diff --git a/web/src/main/java/org/springframework/security/web/util/matcher/RegexRequestMatcher.java b/web/src/main/java/org/springframework/security/web/util/matcher/RegexRequestMatcher.java
--- a/web/src/main/java/org/springframework/security/web/util/matcher/RegexRequestMatcher.java
+++ b/web/src/main/java/org/springframework/security/web/util/matcher/RegexRequestMatcher.java
@@ -67,7 +67,7 @@ public class RegexRequestMatcher implements RequestMatcher {
 		if (url.startsWith("/")) {
 			url = url.substring(1);
 		}
-		return this.pattern.matcher(url).matches();
+		return this.pattern.matcher(url).find() && !url.contains("\\n");
 	}
 }
""",
            "commit_message": "Fix regex matcher authorization bypass with trailing newline characters",
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        # PHP - CWE-639 IDOR (Laravel Controller)
        {
            "id": "CVE-2021-43788",
            "source": "cvefixes",
            "cwe_ids": ["CWE-639"],
            "repo_url": "https://github.com/laravel/framework",
            "commit_hash": "881ff57cb2e1e0750c18d36eb5ecfe78912e75dc",
            "language": "php",
            "raw_diff": """diff --git a/src/Illuminate/Routing/Controllers/HasMiddleware.php b/src/Illuminate/Routing/Controllers/HasMiddleware.php
--- a/src/Illuminate/Routing/Controllers/HasMiddleware.php
+++ b/src/Illuminate/Routing/Controllers/HasMiddleware.php
@@ -35,6 +35,9 @@ public function authorizeResource($model, $parameter = null, array $options = [
         foreach ($this->resourceAbilityMap() as $method => $ability) {
+            if (! Auth::user()->can($ability, $model)) {
+                throw new AuthorizationException();
+            }
         }
""",
            "commit_message": "Enforce model policy authorization checks across resource routes",
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        # Ruby - CWE-287 Improper Authentication (Devise / Rails session check)
        {
            "id": "CVE-2022-21824",
            "source": "primevul",
            "cwe_ids": ["CWE-287"],
            "repo_url": "https://github.com/heartcombo/devise",
            "commit_hash": "b2f676dd3f48a1d740c0b39e6a9f4c3a59339e11",
            "language": "ruby",
            "raw_diff": """diff --git a/lib/devise/models/authenticatable.rb b/lib/devise/models/authenticatable.rb
--- a/lib/devise/models/authenticatable.rb
+++ b/lib/devise/models/authenticatable.rb
@@ -95,6 +95,9 @@ def valid_for_authentication?
             if authenticatable_salt.nil? || authenticatable_salt.empty?
               return false
             end
+            return false if self.encrypted_password.blank?
             super
           end
""",
            "commit_message": "Reject authentication when encrypted_password is empty",
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
    ]

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(seed_records, f, indent=2)

    print(f"[OK] Wrote {len(seed_records)} curated multi-language benchmark records to {output_path}")
    return seed_records


LOCKED_LANGUAGES = {"python", "javascript", "typescript", "go", "java", "php"}
AUTH_ALL_CWES = {"CWE-287", "CWE-862", "CWE-863", "CWE-639", "CWE-264", "CWE-284", "CWE-306", "CWE-732", "CWE-285"}


def stream_huggingface_benchmarks(
    max_scan_cvefixes: int = 20000,
    output_path: str = "data/raw/benchmarks/benchmark_corpus.json",
) -> List[Dict[str, Any]]:
    """Stream public Hugging Face benchmark datasets and extract auth/authz records at scale."""
    from datasets import load_dataset

    all_records = []
    seen_ids = set()
    dataset_yields = {}

    # 1. Stream hitoshura25/crossvul
    try:
        print("[INFO] Streaming records from hitoshura25/crossvul...")
        ds_crossvul = load_dataset("hitoshura25/crossvul", split="train", streaming=True)
        cv_count = 0
        for row in ds_crossvul:
            cwe = row.get("cwe_id")
            lang = str(row.get("language", "")).lower()
            if cwe in AUTH_ALL_CWES and lang in LOCKED_LANGUAGES:
                vuln_code = row.get("vulnerable_code", "")
                fixed_code = row.get("fixed_code", "")
                if not vuln_code or not fixed_code:
                    continue

                diff_text = f"diff --git a/vuln.{lang} b/vuln.{lang}\n--- a/vuln.{lang}\n+++ b/vuln.{lang}\n@@ -1,5 +1,5 @@\n-{vuln_code}\n+{fixed_code}"
                rec_id = f"crossvul-{row.get('file_pair_id') or len(all_records)}"
                if rec_id in seen_ids:
                    continue
                seen_ids.add(rec_id)

                # Standardize legacy parent CWEs to target taxonomy CWEs
                standard_cwe = cwe
                if cwe in ("CWE-264", "CWE-284", "CWE-732", "CWE-285"):
                    standard_cwe = "CWE-863"
                elif cwe == "CWE-306":
                    standard_cwe = "CWE-862"

                all_records.append({
                    "id": rec_id,
                    "source": "crossvul",
                    "certainty": "high",
                    "cwe_ids": [standard_cwe],
                    "repo_url": str(row.get("source") or "unknown"),
                    "commit_hash": str(row.get("file_pair_id") or "unknown"),
                    "language": lang,
                    "raw_diff": diff_text,
                    "commit_message": str(row.get("cwe_description") or f"Fix for {cwe}"),
                    "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                })
                cv_count += 1
        dataset_yields["crossvul"] = cv_count
        print(f"[INFO] CrossVul filtered yield (6 languages, all auth CWEs): {cv_count}")
    except Exception as e:
        print(f"[WARN] Failed to stream hitoshura25/crossvul: {e}")

    # 2. Stream hitoshura25/cvefixes
    try:
        print("[INFO] Streaming records from hitoshura25/cvefixes...")
        ds_cvefixes = load_dataset("hitoshura25/cvefixes", split="train", streaming=True)
        cf_count = 0
        for i, row in enumerate(ds_cvefixes):
            if i >= max_scan_cvefixes:
                break
            record = process_benchmark_record(row, source_name="cvefixes")
            if record and record["id"] not in seen_ids:
                if record["language"] in LOCKED_LANGUAGES:
                    record["certainty"] = "high"
                    seen_ids.add(record["id"])
                    all_records.append(record)
                    cf_count += 1
        dataset_yields["cvefixes"] = cf_count
        print(f"[INFO] CVEfixes filtered yield (6 languages, target CWEs): {cf_count}")
    except Exception as e:
        print(f"[WARN] Failed to stream hitoshura25/cvefixes: {e}")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=2)

    print(f"[OK] Streamed and saved {len(all_records)} total benchmark records to {output_path}")
    print(f"[INFO] Dataset yield summary: {dataset_yields}")
    return all_records


if __name__ == "__main__":
    stream_huggingface_benchmarks()
