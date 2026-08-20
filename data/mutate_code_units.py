import collections
import copy
import hashlib
import json
import os
import random
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from data.clean_and_dedup import compute_code_hash


# ---------------------------------------------------------------------------
# 1. Missing Authorization Check Mutators (CWE-862)
# ---------------------------------------------------------------------------

MISSING_AUTH_PATTERNS = [
    # Decorators & annotations
    (r"@(?:login_required|permission_required|user_passes_test|PreAuthorize|Secured|RolesAllowed|UseGuards|Roles|RequirePermission)(?:\([^)]*\))?\s*\n?", "authorization decorator / annotation"),
    # Python guard clauses
    (r"if\s+not\s+(?:request\.user|user)\.is_authenticated\s*:\s*\n(?:\s+raise[^\n]+\n|\s+return[^\n]+\n)", "user authentication guard"),
    (r"if\s+not\s+(?:request\.user|user)\.has_perm\([^)]+\)\s*:\s*\n(?:\s+raise[^\n]+\n|\s+return[^\n]+\n)", "permission verification check"),
    (r"if\s+not\s+(?:is_admin|has_permission|can_access)\([^)]*\)\s*:\s*\n(?:\s+raise[^\n]+\n|\s+return[^\n]+\n)", "access evaluation check"),
    (r"self\.check_permissions\(request\)\s*\n?", "DRF check_permissions call"),
    (r"check_admin\(\)\s*\n?", "admin privilege assertion"),
    # JS/TS guard clauses & middleware
    (r"(?:passport\.authenticate|requireAuth|requireRole|checkPermission|verifyAuth)\([^)]*\),?\s*\n?", "authorization middleware invocation"),
    (r"if\s*\(!req\.user(?:Role|\.role|\.isAdmin)?\)\s*\{\s*return\s+res\.status\((?:401|403)\)[^}]+\}\s*\n?", "session authentication guard"),
    (r"if\s*\(!user\.hasPermission\([^)]+\)\)\s*\{\s*return\s+res\.status\(403\)[^}]+\}\s*\n?", "user permission guard"),
    # Go assertions
    (r"if\s+(?:ok|allowed),\s*_\s*:=\s*(?:e|enforcer)\.Enforce\([^)]+\);\s*!(?:ok|allowed)\s*\{[^}]+\}\s*\n?", "Casbin policy enforcement guard"),
    (r"if\s*!user\.(?:HasPermission|IsAdmin|IsAuthorized)\([^)]*\)\s*\{[^}]+\}\s*\n?", "user authorization check"),
    (r"if\s*user\s*==\s*nil\s*\{[^}]+\}\s*\n?", "authenticated user presence check"),
    # PHP checks
    (r"\$this->authorize\([^)]+\);?\s*\n?", "$this->authorize policy assertion"),
    (r"Gate::(?:authorize|allows|check)\([^)]+\);?\s*\n?", "Gate authorization check"),
    (r"if\s*\(!Auth::check\(\)\)\s*\{[^}]+\}\s*\n?", "Auth::check verification"),
    (r"if\s*\(!Auth::user\(\)->can\([^)]+\)\)\s*\{[^}]+\}\s*\n?", "user policy check"),
]


def mutate_missing_authz(code: str, lang: str) -> Optional[Tuple[str, str]]:
    """Strip authorization guards, decorators, and middleware invocations from real code."""
    for pat, desc in MISSING_AUTH_PATTERNS:
        if re.search(pat, code, flags=re.IGNORECASE):
            mutated = re.sub(pat, "", code, count=1, flags=re.IGNORECASE).strip()
            if mutated and mutated != code:
                return mutated, f"Missing authorization check: stripped {desc}, permitting unprivileged execution."

    # Generic fallback: strip first if-statement that evaluates permission/role/auth
    generic_guard = re.search(
        r"(if\s+(?:!|not\s+)?(?:request\.)?(?:user|auth|perm|role|admin|token|session)[a-zA-Z0-9_.]*\s*(?:==|!=|in|===|!==|\().*?:\s*\n(?:\s+[^\n]+\n)+)",
        code,
        flags=re.IGNORECASE,
    )
    if generic_guard:
        mutated = code.replace(generic_guard.group(1), "").strip()
        if mutated and mutated != code:
            return mutated, "Missing authorization check: removed conditional privilege verification guard."

    return None


# ---------------------------------------------------------------------------
# 2. Incorrect Authorization Mutators (CWE-863)
# ---------------------------------------------------------------------------

INCORRECT_AUTH_PATTERNS = [
    (r'role\s*==\s*["\']admin["\']', 'role != "admin"', "inverting administrative role check"),
    (r'role\s*===\s*["\']admin["\']', 'role !== "admin"', "inverting administrative role check"),
    (r'role\s*==\s*["\']superuser["\']', 'role != "superuser"', "inverting superuser check"),
    (r'is_admin\s*==\s*True', 'is_admin == False', "flipping is_admin boolean requirement"),
    (r'isAdmin\s*===\s*true', 'isAdmin === false', "flipping isAdmin boolean requirement"),
    (r'user\.role\s*==\s*Role\.ADMIN', 'user.role != Role.ADMIN', "inverting enum ADMIN check"),
    (r'hasRole\(["\']ADMIN["\']\)', '!hasRole("ADMIN")', "inverting Spring Security hasRole check"),
    (r'clearance\s*>=\s*REQUIRED_LEVEL', 'clearance >= 0', "weakening clearance level requirement"),
    (r'user\.TenantID\s*!=\s*tenantID', 'false /* bypassed tenant check */', "bypassing multi-tenant isolation check"),
    (r'tenant_id\s*==\s*request\.user\.tenant_id', 'True', "short-circuiting tenant boundary check"),
    (r'has_permission\s*=\s*check_perm\([^)]+\)', 'has_permission = True', "forcing permission resolution to true"),
    (r'\b(is_admin|isAdmin|is_superuser|has_role)\b\s*==\s*(?:True|true|1)', r'\1 == false', "inverting administrative boolean check"),
    (r'user\.role\s*in\s*\[([^\]]+)\]', r'user.role not in [\1]', "inverting role whitelist containment check"),
    (r'user\.role\s*!==\s*["\']admin["\']', 'false', "bypassing role inequality assertion"),
    (r'return\s+user\.id\s*==\s*target\.owner_id', 'return True /* bypassed */', "short-circuiting ownership predicate"),
]


def mutate_incorrect_authz(code: str, lang: str) -> Optional[Tuple[str, str]]:
    """Mutate role/permission conditionals to introduce privilege escalation or access rule bypass."""
    for pat, rep, desc in INCORRECT_AUTH_PATTERNS:
        if re.search(pat, code, flags=re.IGNORECASE):
            mutated = re.sub(pat, rep, code, count=1, flags=re.IGNORECASE).strip()
            if mutated and mutated != code:
                return mutated, f"Incorrect authorization logic: introduced {desc}, permitting unauthorized callers to evade access boundaries."

    # Generic conditional inversion on role/perm checks
    match = re.search(r'(if\s+[^:\n{]+(?:role|perm|admin|access|level)[^:\n{]+)(==|===|!=|!==|>=|<=)', code, flags=re.IGNORECASE)
    if match:
        full_line = match.group(0)
        op = match.group(2)
        inv_op = "!=" if op == "==" else ("!==" if op == "===" else ("==" if op == "!=" else "==="))
        mutated = code.replace(full_line, full_line[:-len(op)] + inv_op, 1).strip()
        if mutated and mutated != code:
            return mutated, "Incorrect authorization logic: inverted access control boolean operator, causing privilege check bypass."

    return None


# ---------------------------------------------------------------------------
# 3. IDOR / Broken Object-Level Authorization Mutators (CWE-639)
# ---------------------------------------------------------------------------

IDOR_PATTERNS = [
    (r"get_object_or_404\(([^,]+),\s*id=([^,]+),\s*user=request\.user\)", r"get_object_or_404(\1, id=\2)", "removing request.user object ownership filter"),
    (r"filter\(id=([^,]+),\s*user_id=([^)]+)\)", r"filter(id=\1)", "removing user_id query scoping"),
    (r"if\s+([a-zA-Z0-9_]+)\.owner_id\s*!=\s*(?:request\.)?user\.id:\s*\n(?:\s+[^\n]+\n)+", "", "removing owner_id validation guard"),
    (r"if\s+([a-zA-Z0-9_]+)\.user\s*!=\s*(?:request\.)?user:\s*\n(?:\s+[^\n]+\n)+", "", "removing user ownership comparison"),
    (r"where:\s*\{\s*id:([^,]+),\s*userId:([^}]+)\s*\}", r"where: { id:\1 }", "removing userId scoping in database query"),
    (r"if\s*\(([a-zA-Z0-9_]+)\.ownerId\s*!==\s*req\.user\.id\)\s*\{[^}]+\}\s*\n?", "", "stripping ownerId check before resource mutation"),
    (r"if\s+([a-zA-Z0-9_]+)\.OwnerID\s*!=\s*user\.ID\s*\{[^}]+\}\s*\n?", "", "removing resource OwnerID check"),
    (r"WHERE id = \? AND user_id = \?", "WHERE id = ?", "removing user_id predicate in SQL query"),
    (r"if\s*\(\$([a-zA-Z0-9_]+)->user_id\s*!==\s*Auth::id\(\)\)\s*\{[^}]+\}\s*\n?", "", "removing user_id validation guard"),
    (r"where\(['\"]user_id['\"],\s*Auth::id\(\)\)->", "", "removing user_id query scope"),
    (r"\.where\(['\"]user_id['\"]\s*,\s*[^)]+\)", "", "stripping user_id scoping condition"),
    (r"findByUserAndId\(([^,]+),\s*([^)]+)\)", r"findById(\2)", "replacing scoped findByUserAndId with unscoped findById"),
    (r"findByOwnerAndId\(([^,]+),\s*([^)]+)\)", r"findById(\2)", "replacing scoped findByOwnerAndId with unscoped findById"),
]


def mutate_idor(code: str, lang: str) -> Optional[Tuple[str, str]]:
    """Strip ownership and tenant scoping in direct object access queries."""
    for pat, rep, desc in IDOR_PATTERNS:
        if re.search(pat, code, flags=re.IGNORECASE):
            mutated = re.sub(pat, rep, code, count=1, flags=re.IGNORECASE).strip()
            if mutated and mutated != code:
                return mutated, f"Insecure Direct Object Reference (IDOR): {desc}, allowing callers to access or modify records by guessing IDs."

    # Generic IDOR: strip user/owner comparison
    match = re.search(r"(if\s+[^:\n{]*(?:owner|author|creator|account_id|user_id)[^:\n{]*(?:!=|!==|==)\s*[^:\n{]*(?:user|caller|principal)[^:\n{]*:\s*\n(?:\s+[^\n]+\n)+)", code, flags=re.IGNORECASE)
    if match:
        mutated = code.replace(match.group(1), "").strip()
        if mutated and mutated != code:
            return mutated, "Insecure Direct Object Reference (IDOR): stripped object ownership comparison before returning resource."

    return None


# ---------------------------------------------------------------------------
# 4. Authentication Bypass Mutators (CWE-287)
# ---------------------------------------------------------------------------

AUTH_BYPASS_PATTERNS = [
    (r"jwt\.verify\(([^,]+),\s*([^,]+),\s*\{[^}]*\}\)", r"jwt.decode(\1)", "replacing jwt.verify with unverified jwt.decode"),
    (r"algorithms=\[[\"']HS256[\"']\]", r"algorithms=['none', 'HS256']", "permitting unauthenticated 'none' JWT algorithm"),
    (r"verify=True", r"verify=False", "disabling cryptographic signature verification"),
    (r"options=\{[\"']verify_exp[\"']:\s*True\}", r"options={'verify_exp': False}", "disabling token expiration verification"),
    (r"password_verify\(([^,]+),\s*([^)]+)\)", r"true /* bypassed hash check */", "forcing password_verify to return true"),
    (r"bcrypt\.compare\(([^,]+),\s*([^,]+)\)", r"Promise.resolve(true)", "forcing bcrypt.compare to succeed"),
    (r"if\s*!bcrypt\.CompareHashAndPassword\([^)]+\)\s*==\s*nil\s*\{[^}]+\}\s*\n?", "", "removing bcrypt hash failure rejection"),
    (r"if\s*not\s*session\.get\(auth_key\):.*?\n\s*return.*?\n", "", "stripping session authentication guard"),
    (r"if\s*req\.session\.mfaVerified\s*!==\s*true\s*\{[^}]+\}\s*\n?", "", "bypassing mandatory MFA verification check"),
    (r"token\.isValid\(\)", "true /* bypassed */", "forcing token validity to always return true"),
    (r"token\.Valid", "true", "forcing token validity property to true"),
    (r"if\s*\(!token\)\s*\{\s*return\s+[^}]+\}\s*\n?", "", "removing token presence assertion"),
    (r"if\s*not\s*token\s*:\s*\n(?:\s+[^\n]+\n)+", "", "removing token existence validation"),
    (r"hash_equals\(([^,]+),\s*([^)]+)\)", "true", "forcing hash_equals check to succeed"),
]


def mutate_auth_bypass(code: str, lang: str) -> Optional[Tuple[str, str]]:
    """Introduce authentication bypasses in token, session, or signature verification routines."""
    for pat, rep, desc in AUTH_BYPASS_PATTERNS:
        if re.search(pat, code, flags=re.IGNORECASE):
            mutated = re.sub(pat, rep, code, count=1, flags=re.IGNORECASE).strip()
            if mutated and mutated != code:
                return mutated, f"Authentication bypass: {desc}, allowing requests with invalid, expired, or missing credentials to succeed."

    # Generic token / session bypass
    match = re.search(r"(if\s+[^:\n{]*(?:token|jwt|session|signature|credential)[^:\n{]*(?:is\s+None|==\s*null|==\s*nil|!\s*valid|!\s*check).*?:\s*\n(?:\s+[^\n]+\n)+)", code, flags=re.IGNORECASE)
    if match:
        mutated = code.replace(match.group(1), "").strip()
        if mutated and mutated != code:
            return mutated, "Authentication bypass: removed credential verification block, permitting unauthenticated execution."

    return None


# ---------------------------------------------------------------------------
# 5. Permutation Schemes for Clean Negatives and Positive Seeds
# ---------------------------------------------------------------------------

RENAME_SCHEMES = [
    [(r"\buser\b", "currentUser"), (r"\breq\b", "httpRequest"), (r"\btoken\b", "authToken")],
    [(r"\buser\b", "authUser"), (r"\bctx\b", "requestCtx"), (r"\brole\b", "userRole")],
    [(r"\buser\b", "requestUser"), (r"\bauth\b", "authContext"), (r"\bperm\b", "permission")],
    [(r"\buser\b", "caller"), (r"\baccount\b", "userAccount"), (r"\btoken\b", "bearerToken")],
    [(r"\buser\b", "principal"), (r"\btenant\b", "tenantEntity"), (r"\bsession\b", "userSession")],
    [(r"\breq\b", "incomingReq"), (r"\brole\b", "callerRole"), (r"\bperm\b", "requiredPerm")],
    [(r"\bctx\b", "ctxObj"), (r"\bauth\b", "authService"), (r"\bresource\b", "targetResource")],
    [(r"\buser\b", "subject"), (r"\btoken\b", "accessToken"), (r"\bperm\b", "actionRight")],
    [(r"\brequest\b", "clientRequest"), (r"\baccount\b", "accountEntity"), (r"\btoken\b", "jwtToken")],
    [(r"\buser\b", "actor"), (r"\brole\b", "assignedRole"), (r"\bsession\b", "activeSession")],
    [(r"\buser\b", "authorizedUser"), (r"\btoken\b", "sessionToken"), (r"\bctx\b", "securityCtx")],
    [(r"\brequest\b", "incomingRequest"), (r"\buser\b", "sessionUser"), (r"\brole\b", "securityRole")],
]

DOC_VARIATIONS_PY = [
    '"""Evaluates authentication credentials and enforces resource access policies."""\n',
    '"""Handles secure request dispatch with permission and role validation."""\n',
    '"""Core access control check for authenticated callers and tenant scoping."""\n',
    '"""Validates session state and authorization boundaries prior to execution."""\n',
    '"""Enforces principle of least privilege for inbound request handling."""\n',
    '# Verified authorization validation routine\n',
    '# Core security handler for role and permission boundaries\n',
    '# Access control verification step\n',
    '# Enforces authentication state and caller permissions\n',
    '# Validated authorization handler\n',
]

DOC_VARIATIONS_CSTYLE = [
    '/**\n * Evaluates authentication credentials and enforces resource access policies.\n */\n',
    '/**\n * Handles secure request dispatch with permission and role validation.\n */\n',
    '/**\n * Core access control check for authenticated callers and tenant scoping.\n */\n',
    '/**\n * Validates session state and authorization boundaries prior to execution.\n */\n',
    '/**\n * Enforces principle of least privilege for inbound request handling.\n */\n',
    '// Verified authorization validation routine\n',
    '// Core security handler for role and permission boundaries\n',
    '// Access control verification step\n',
    '// Enforces authentication state and caller permissions\n',
    '// Validated authorization handler\n',
]


def augment_clean_negative(code: str, lang: str, variation_index: int = 0) -> Optional[Tuple[str, str]]:
    """Generate realistic syntactic variations of clean code (refactoring, identifier renaming, docstrings)."""
    mutated = code
    applied = 0

    scheme = RENAME_SCHEMES[variation_index % len(RENAME_SCHEMES)]
    for old_w, new_w in scheme:
        if re.search(old_w, mutated):
            mutated = re.sub(old_w, new_w, mutated)
            applied += 1

    # Attach doc variation based on variation_index
    doc_idx = (variation_index // len(RENAME_SCHEMES))
    if lang == "python":
        doc = DOC_VARIATIONS_PY[doc_idx % len(DOC_VARIATIONS_PY)]
        if not mutated.startswith(('"""', "#")):
            mutated = f"{doc}{mutated}"
    else:
        doc = DOC_VARIATIONS_CSTYLE[doc_idx % len(DOC_VARIATIONS_CSTYLE)]
        if not mutated.startswith(("/**", "//")):
            mutated = f"{doc}{mutated}"

    if mutated.strip() != code.strip():
        explanation = "Clean authorization logic enforcing appropriate authentication and access boundaries."
        return mutated.strip(), explanation

    return None


def augment_positive_variation(code: str, lang: str, variation_index: int = 0) -> Optional[Tuple[str, str]]:
    """Generate realistic identifier/formatting variations of real vulnerable seed code."""
    mutated = code
    applied = 0

    scheme = RENAME_SCHEMES[variation_index % len(RENAME_SCHEMES)]
    for old_w, new_w in scheme:
        if re.search(old_w, mutated):
            mutated = re.sub(old_w, new_w, mutated)
            applied += 1

    # Attach subtle doc variation based on variation_index
    doc_idx = (variation_index // len(RENAME_SCHEMES))
    if doc_idx > 0:
        if lang == "python":
            doc = DOC_VARIATIONS_PY[doc_idx % len(DOC_VARIATIONS_PY)]
            if not mutated.startswith(('"""', "#")):
                mutated = f"{doc}{mutated}"
        else:
            doc = DOC_VARIATIONS_CSTYLE[doc_idx % len(DOC_VARIATIONS_CSTYLE)]
            if not mutated.startswith(("/**", "//")):
                mutated = f"{doc}{mutated}"

    if mutated.strip() != code.strip():
        return mutated.strip(), "Semantic variation of verified authorization vulnerability pattern."

    return None


# ---------------------------------------------------------------------------
# Scaled Mutation Orchestrator (Strict Real-Majority / 50:50 Balance)
# ---------------------------------------------------------------------------

def generate_train_mutations(
    train_seed_path: str = "data/splits/train_seed.json",
    output_path: str = "data/splits/train_mutated.json",
    target_pos_mutations: int = 1271,
    target_neg_augmentations: int = 605,
    seed: int = 42,
) -> List[Dict[str, Any]]:
    """Generate deterministic, realistic mutations exclusively from train-split seed code units."""
    random.seed(seed)

    if not os.path.exists(train_seed_path):
        raise FileNotFoundError(f"Train seed not found at {train_seed_path}")

    with open(train_seed_path, "r", encoding="utf-8") as f:
        train_seed = json.load(f)

    mutated_records = []
    seen_hashes = {compute_code_hash(r["code"]) for r in train_seed}

    clean_pool = [r for r in train_seed if not r["is_vulnerable"]]
    pos_pool = [r for r in train_seed if r["is_vulnerable"]]

    print(f"[INFO] Starting scaled deterministic mutation engine from train seed ({len(clean_pool)} clean, {len(pos_pool)} pos)...")

    # 1. Target ~1040 per positive CWE class (total 4,161)
    target_per_class = target_pos_mutations // 4
    mutation_targets = {
        "missing_authz_check": (mutate_missing_authz, ["CWE-862"], target_per_class),
        "incorrect_authz": (mutate_incorrect_authz, ["CWE-863"], target_per_class),
        "IDOR": (mutate_idor, ["CWE-639"], target_per_class),
        "auth_bypass": (mutate_auth_bypass, ["CWE-287"], target_pos_mutations - 3 * target_per_class),
    }

    for vuln_class, (mut_fn, cwes, target_count) in mutation_targets.items():
        generated = 0
        
        # Step A: Direct guard/check mutations on clean pool
        for parent in clean_pool:
            if generated >= target_count:
                break
            res = mut_fn(parent["code"], parent["language"])
            if not res:
                continue

            mut_code, explanation = res
            h = compute_code_hash(mut_code)
            if h not in seen_hashes:
                seen_hashes.add(h)
                rec_id = f"mutated-{parent['id']}-{vuln_class}-{generated + 1:04d}"
                mutated_records.append({
                    "id": rec_id,
                    "source": "real_code_mutation",
                    "is_synthetic": True,
                    "cwe_ids": cwes,
                    "vuln_class": vuln_class,
                    "language": parent["language"],
                    "code": mut_code,
                    "is_vulnerable": True,
                    "confidence_target": 1.0,
                    "explanation": explanation,
                    "provenance": {
                        "derived_from": parent["id"],
                        "source_repo": parent.get("provenance", {}).get("repo_url", "unknown"),
                        "mutation_type": vuln_class,
                        "base_type": "real_code_mutation",
                    },
                })
                generated += 1

            # Also generate variations of this mutated code
            for var_idx in range(1, 12):
                if generated >= target_count:
                    break
                var_res = augment_positive_variation(mut_code, parent["language"], var_idx)
                if not var_res:
                    continue
                var_code, _ = var_res
                vh = compute_code_hash(var_code)
                if vh not in seen_hashes:
                    seen_hashes.add(vh)
                    rec_id = f"mutated-var-{parent['id']}-{vuln_class}-{generated + 1:04d}"
                    mutated_records.append({
                        "id": rec_id,
                        "source": "real_code_mutation",
                        "is_synthetic": True,
                        "cwe_ids": cwes,
                        "vuln_class": vuln_class,
                        "language": parent["language"],
                        "code": var_code,
                        "is_vulnerable": True,
                        "confidence_target": 1.0,
                        "explanation": explanation,
                        "provenance": {
                            "derived_from": parent["id"],
                            "source_repo": parent.get("provenance", {}).get("repo_url", "unknown"),
                            "mutation_type": f"{vuln_class}_var",
                            "base_type": "real_code_mutation",
                        },
                    })
                    generated += 1

        # Step B: Semantic variations of matching real positive examples
        class_pos = [r for r in pos_pool if r.get("vuln_class") == vuln_class] or pos_pool
        var_round = 0
        while generated < target_count and class_pos and var_round < 60:
            var_round += 1
            for parent in class_pos:
                if generated >= target_count:
                    break
                res = augment_positive_variation(parent["code"], parent["language"], var_round)
                if not res:
                    continue
                mut_code, expl = res
                h = compute_code_hash(mut_code)
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    rec_id = f"mutated-posseed-{parent['id']}-{vuln_class}-{generated + 1:04d}"
                    mutated_records.append({
                        "id": rec_id,
                        "source": "real_code_mutation",
                        "is_synthetic": True,
                        "cwe_ids": cwes,
                        "vuln_class": vuln_class,
                        "language": parent["language"],
                        "code": mut_code,
                        "is_vulnerable": True,
                        "confidence_target": 1.0,
                        "explanation": parent.get("explanation", expl),
                        "provenance": {
                            "derived_from": parent["id"],
                            "source_repo": parent.get("provenance", {}).get("repo_url", "unknown"),
                            "mutation_type": f"{vuln_class}_seed_variation",
                            "base_type": "real_code_mutation",
                        },
                    })
                    generated += 1

        print(f"  - Generated {generated}/{target_count} mutated records for {vuln_class}")

    # 2. Generate Clean Negative Augmentations (Target 3,495)
    neg_generated = 0
    var_round = 0

    while neg_generated < target_neg_augmentations and clean_pool and var_round < 60:
        var_round += 1
        for parent in clean_pool:
            if neg_generated >= target_neg_augmentations:
                break
            res = augment_clean_negative(parent["code"], parent["language"], var_round)
            if not res:
                continue

            mut_code, explanation = res
            h = compute_code_hash(mut_code)
            if h in seen_hashes:
                continue
            seen_hashes.add(h)

            rec_id = f"augmented-clean-{parent['id']}-{neg_generated + 1:04d}"
            mutated_records.append({
                "id": rec_id,
                "source": "real_code_mutation",
                "is_synthetic": True,
                "cwe_ids": [],
                "vuln_class": "none",
                "language": parent["language"],
                "code": mut_code,
                "is_vulnerable": False,
                "confidence_target": 0.0,
                "explanation": explanation,
                "provenance": {
                    "derived_from": parent["id"],
                    "source_repo": parent.get("provenance", {}).get("repo_url", "unknown"),
                    "mutation_type": "clean_refactoring",
                    "base_type": "real_code_mutation",
                },
            })
            neg_generated += 1

    print(f"  - Generated {neg_generated}/{target_neg_augmentations} augmented clean negative records")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(mutated_records, f, indent=2)

    print(f"[OK] Saved {len(mutated_records)} total mutated training records to {output_path}")
    return mutated_records


if __name__ == "__main__":
    generate_train_mutations()
