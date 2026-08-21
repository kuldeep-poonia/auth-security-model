"""High-Volume Deterministic Synthetic Mutation Generator.

Generates realistic, AST-grounded variants from 2,550+ verified functional base units
across all 6 target languages: Python, JavaScript, TypeScript, PHP, Go, Java.
"""

import ast
import json
import os
import random
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def extract_primary_function_name(code: str) -> Optional[str]:
    m = re.search(r"(?:def|function|func|public\s+(?:void|\w+))\s+(\w+)\s*\(", code)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# 1. IDOR Mutators
# ---------------------------------------------------------------------------

def generate_idor_variants(code: str, lang: str) -> List[Tuple[str, str]]:
    variants = []
    fn_name = extract_primary_function_name(code)
    fn_str = f"Function `{fn_name}()`" if fn_name else "Method"

    # Pattern A: Django / ORM user scoping removal
    if re.search(r"get_object_or_404\([^)]*user=request\.user[^)]*\)", code):
        m1 = re.sub(r",\s*user=request\.user", "", code)
        m1 = re.sub(r"user=request\.user,\s*", "", m1)
        if m1 != code:
            variants.append((m1, f"{fn_str} retrieves model instance directly without filtering by `request.user` (CWE-639 IDOR)."))

    # Pattern B: Scoped query filter parameter removal
    for param in ["user_id", "owner_id", "tenant_id", "account_id", "userId", "ownerId", "tenantId"]:
        if param in code:
            m2 = re.sub(rf"(?:,\s*)?{param}\s*[:=]\s*[^,\s)]+", "", code, flags=re.IGNORECASE)
            m2 = re.sub(rf"\.where\(['\"]{param}['\"],\s*[^)]+\)", "", m2, flags=re.IGNORECASE)
            m2 = re.sub(rf"(\band\s+{param}\s*=\s*[^;\n)]+)", "", m2, flags=re.IGNORECASE)
            if m2 != code:
                variants.append((m2, f"{fn_str} executes database lookup directly by ID without scoping to caller's `{param}` (CWE-639 IDOR)."))

    # Pattern C: Strip explicit ownership comparison guard
    owner_guard = re.search(
        r"(if\s+[^:\n{]*(?:owner_id|user_id|tenant_id|ownerId|userId|OwnerID)[^:\n{]*(?:!=|!==|==)\s*[^:\n{]*(?:user|caller|principal|Auth::id)[^:\n{]*:\s*\n(?:\s+[^\n]+\n)+)",
        code, flags=re.IGNORECASE
    )
    if owner_guard:
        m3 = code.replace(owner_guard.group(0), "").strip()
        if m3 and m3 != code:
            variants.append((m3, f"{fn_str} strips resource `owner_id` verification before returning sensitive object (CWE-639 IDOR)."))

    return variants


# ---------------------------------------------------------------------------
# 2. Missing Authorization Mutators
# ---------------------------------------------------------------------------

def generate_missing_authz_variants(code: str, lang: str) -> List[Tuple[str, str]]:
    variants = []
    fn_name = extract_primary_function_name(code)
    fn_str = f"Method `{fn_name}()`" if fn_name else "Handler"

    # Pattern A: Decorators & Annotations
    decorators = re.findall(r"@(?:login_required|permission_required|user_passes_test|PreAuthorize|Secured|RolesAllowed|UseGuards|RequirePermission)(?:\([^)]*\))?\s*\n", code, re.IGNORECASE)
    for dec in decorators:
        m1 = code.replace(dec, "").strip()
        if m1 != code:
            variants.append((m1, f"{fn_str} executes sensitive action without `{dec.strip()}` authorization guard (CWE-862)."))

    # Pattern B: Policy assertions
    if "$this->authorize" in code or "Gate::authorize" in code:
        m2 = re.sub(r"(?:\$this->authorize|Gate::authorize)\([^)]+\);\s*\n?", "", code)
        if m2 != code:
            variants.append((m2, f"{fn_str} mutates resource without invoking `$this->authorize()` policy check (CWE-862)."))

    # Pattern C: Python / JS Guard clauses
    guard_match = re.search(
        r"(if\s+(?:not\s+|!)?(?:request\.user|user|req\.user|Auth::user\(\))\.(?:is_authenticated|has_perm|hasPermission|can|isAdmin|is_admin)\([^)]*\)\s*:\s*\n(?:\s+raise[^\n]+\n|\s+return[^\n]+\n))",
        code, flags=re.IGNORECASE
    )
    if guard_match:
        m3 = code.replace(guard_match.group(0), "").strip()
        if m3 != code:
            variants.append((m3, f"{fn_str} executes sensitive logic without verifying caller `is_authenticated` state (CWE-862)."))

    # Pattern D: DRF check_permissions
    if "self.check_permissions(request)" in code:
        m4 = code.replace("self.check_permissions(request)", "")
        variants.append((m4, f"{fn_str} omits `self.check_permissions(request)` invocation before processing action (CWE-862)."))

    return variants


# ---------------------------------------------------------------------------
# 3. Incorrect Authorization Mutators
# ---------------------------------------------------------------------------

def generate_incorrect_authz_variants(code: str, lang: str) -> List[Tuple[str, str]]:
    variants = []
    fn_name = extract_primary_function_name(code)
    fn_str = f"Logic in `{fn_name}()`" if fn_name else "Authorization logic"

    inversion_pairs = [
        (r'role\s*==\s*["\']admin["\']', 'role != "admin"', "inverting `role != 'admin'` check"),
        (r'role\s*===\s*["\']admin["\']', 'role !== "admin"', "inverting `role !== 'admin'` equality"),
        (r'role\s*==\s*["\']superuser["\']', 'role != "superuser"', "inverting superuser check"),
        (r'is_admin\s*==\s*True', 'is_admin == False', "flipping `is_admin == False` requirement"),
        (r'is_admin\s*==\s*true', 'is_admin == false', "flipping `is_admin == false` requirement"),
        (r'isAdmin\s*===\s*true', 'isAdmin === false', "flipping `isAdmin === false` requirement"),
        (r'user\.role\s*==\s*Role\.ADMIN', 'user.role != Role.ADMIN', "inverting `user.role != Role.ADMIN` check"),
        (r'clearance\s*>=\s*REQUIRED_LEVEL', 'clearance >= 0', "weakening clearance check to `clearance >= 0`"),
        (r'clearance\s*>=\s*\d+', 'clearance >= 0', "weakening clearance check to `clearance >= 0`"),
        (r'hasRole\(["\']ADMIN["\']\)', '!hasRole("ADMIN")', "inverting `!hasRole('ADMIN')` check"),
        (r'hasRole\(["\']ROLE_ADMIN["\']\)', '!hasRole("ROLE_ADMIN")', "inverting `!hasRole('ROLE_ADMIN')` check"),
        (r'has_perm\([^)]+\)', 'True', "forcing `has_perm()` to unconditionally return True"),
        (r'can\([^)]+\)', 'true', "forcing `$user->can()` to unconditionally return true"),
    ]

    for pat, rep, desc in inversion_pairs:
        if re.search(pat, code, flags=re.IGNORECASE):
            m1 = re.sub(pat, rep, code, count=1, flags=re.IGNORECASE).strip()
            if m1 != code:
                variants.append((m1, f"{fn_str} contains flawed access control check ({desc}), permitting unauthorized privilege escalation (CWE-863)."))

    return variants


# ---------------------------------------------------------------------------
# 4. Authentication Bypass Mutators
# ---------------------------------------------------------------------------

def generate_auth_bypass_variants(code: str, lang: str) -> List[Tuple[str, str]]:
    variants = []
    fn_name = extract_primary_function_name(code)
    fn_str = f"Handler `{fn_name}()`" if fn_name else "Authentication handler"

    # Pattern A: Timing attack on comparisons
    if "constant_time_compare(" in code:
        m1 = re.sub(r"constant_time_compare\(([^,]+),\s*([^)]+)\)", r"\1 == \2", code)
        if m1 != code:
            variants.append((m1, f"{fn_str} replaces timing-safe `constant_time_compare()` with standard `==`, vulnerable to side-channel timing attacks (CWE-287)."))

    if "hash_equals(" in code:
        m2 = re.sub(r"hash_equals\(([^,]+),\s*([^)]+)\)", r"\1 === \2", code)
        if m2 != code:
            variants.append((m2, f"{fn_str} replaces timing-safe `hash_equals()` with non-constant-time `===` (CWE-287)."))

    if "subtle.ConstantTimeCompare" in code:
        m3 = re.sub(r"subtle\.ConstantTimeCompare\(([^,]+),\s*([^)]+)\)\s*==\s*1", r"\1 == \2", code)
        if m3 != code:
            variants.append((m3, f"{fn_str} replaces timing-safe Go `subtle.ConstantTimeCompare` with standard comparison (CWE-287)."))

    # Pattern B: JWT unverified decode
    if "jwt.verify(" in code:
        m4 = re.sub(r"jwt\.verify\(([^,]+),[^)]+\)", r"jwt.decode(\1)", code)
        if m4 != code:
            variants.append((m4, f"{fn_str} replaces cryptographic `jwt.verify()` with unverified `jwt.decode()`, bypassing signature verification (CWE-287)."))

    # Pattern C: Algorithm none in JWT
    if re.search(r"algorithms=\[['\"]HS256['\"]\]", code):
        m5 = re.sub(r"algorithms=\[['\"]HS256['\"]\]", "algorithms=['none', 'HS256']", code)
        if m5 != code:
            variants.append((m5, f"{fn_str} permits insecure `none` algorithm in JWT verification whitelist (CWE-287)."))

    return variants


# ---------------------------------------------------------------------------
# 5. Clean Remediation Mutators
# ---------------------------------------------------------------------------

def generate_clean_remediations(code: str, vuln_class: str, lang: str) -> List[Tuple[str, str]]:
    variants = []
    fn_name = extract_primary_function_name(code)
    fn_str = f"Function `{fn_name}()`" if fn_name else "Method"

    if vuln_class == "idor" or "get_object_or_404" in code:
        if "get_object_or_404(" in code and "user=" not in code:
            m1 = re.sub(r"get_object_or_404\(([^,]+),\s*id=([^)]+)\)", r"get_object_or_404(\1, id=\2, user=request.user)", code)
            if m1 != code:
                variants.append((m1, f"{fn_str} scopes database lookup via `get_object_or_404(..., user=request.user)` to enforce tenant ownership boundaries."))

    elif vuln_class == "missing_authz" or "def " in code:
        if lang == "python" and "def " in code and "is_authenticated" not in code:
            lines = code.splitlines()
            def_idx = [i for i, l in enumerate(lines) if l.strip().startswith("def ")][:1]
            if def_idx:
                lines_copy = list(lines)
                indent = "    "
                inject_stmt = f"{indent}if not request.user.is_authenticated:\n{indent}    raise PermissionDenied('Authentication required')"
                lines_copy.insert(def_idx[0] + 1, inject_stmt)
                m2 = "\n".join(lines_copy)
                variants.append((m2, f"{fn_str} enforces caller authentication via `request.user.is_authenticated` guard before processing request."))

    elif vuln_class == "auth_bypass" or " == " in code:
        if " == " in code and ("token" in code.lower() or "secret" in code.lower() or "key" in code.lower()) and "constant_time_compare" not in code:
            m3 = re.sub(r"(\w+)\s*==\s*(\w+)", r"constant_time_compare(\1, \2)", code, count=1)
            if m3 != code:
                variants.append((m3, f"{fn_str} enforces timing-safe credential verification using `constant_time_compare()`."))

    return variants
