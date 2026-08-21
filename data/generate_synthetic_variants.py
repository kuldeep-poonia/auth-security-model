"""High-Scale Multi-Strategy Deterministic Synthetic Mutation Generator.

Generates thousands of realistic, AST-grounded variants across all 4 vulnerability classes
and clean remediations across all 6 languages (Python, JavaScript, TypeScript, PHP, Go, Java):
- idor: Tenant/owner filter removal, parameter tampering, unscoped direct lookups.
- missing_authz: Decorator/annotation stripping, policy check omission, prologue guard deletion.
- incorrect_authz: Role/clearance comparison inversion, boolean logic weakening, short-circuit bypass.
- auth_bypass: Timing-safe comparison degradation, unverified JWT decode, none-algorithm, hash bypass.
- clean_remediation: Effective precedence-ordered guards, ownership filters, timing-safe compare.
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
# 1. High-Volume IDOR Mutators
# ---------------------------------------------------------------------------

def generate_idor_variants(code: str, lang: str) -> List[Tuple[str, str]]:
    variants = []
    fn_name = extract_primary_function_name(code)
    fn_str = f"Function `{fn_name}()`" if fn_name else "Method"

    # Strategy 1: Django get_object_or_404 user/owner scoping removal
    if "get_object_or_404" in code:
        for user_pat in [
            r",\s*user=request\.user\b", r"\buser=request\.user\s*,\s*",
            r",\s*user_id=request\.user\.id\b", r"\buser_id=request\.user\.id\s*,\s*",
            r",\s*owner=request\.user\b", r"\bowner=request\.user\s*,\s*",
            r",\s*author=request\.user\b", r"\bauthor=request\.user\s*,\s*",
        ]:
            if re.search(user_pat, code):
                m1 = re.sub(user_pat, "", code)
                if m1 != code:
                    variants.append((m1, f"{fn_str} retrieves model instance directly without filtering by `request.user` (CWE-639 IDOR)."))

    # Strategy 2: ORM filter parameter removal across tenant/user fields
    owner_params = [
        "user_id", "owner_id", "tenant_id", "account_id", "org_id", "company_id", "workspace_id", "author_id",
        "userId", "ownerId", "tenantId", "accountId", "orgId", "companyId", "workspaceId", "authorId"
    ]
    for param in owner_params:
        if param in code:
            m2 = re.sub(rf",\s*{param}\s*[:=]\s*[^,\s)]+", "", code, flags=re.IGNORECASE)
            m2 = re.sub(rf"\b{param}\s*[:=]\s*[^,\s)]+\s*,\s*", "", m2, flags=re.IGNORECASE)
            m2 = re.sub(rf"\.where\(['\"]{param}['\"],\s*[^)]+\)", "", m2, flags=re.IGNORECASE)
            m2 = re.sub(rf"\.filter\([^)]*{param}\s*=\s*[^)]*\)", "", m2, flags=re.IGNORECASE)
            m2 = re.sub(rf"(\band\s+{param}\s*=\s*[^;\n)]+)", "", m2, flags=re.IGNORECASE)
            if m2 != code and len(m2.strip()) > 25:
                variants.append((m2, f"{fn_str} executes database lookup directly by ID without scoping to caller's `{param}` (CWE-639 IDOR)."))

    # Strategy 3: Strip explicit ownership comparison guard
    owner_guards = re.findall(
        r"(?:if\s*\([^)]*(?:owner|user|tenant|author|account)[^)]*(?:!=|!==|==)[^)]*\)\s*\{[^}]+\}|if\s+[^:\n{]*(?:owner_id|user_id|tenant_id|ownerId|userId|OwnerID)[^:\n{]*(?:!=|!==|==)\s*[^:\n{]*(?:user|caller|principal|Auth::id)[^:\n{]*:\s*\n(?:\s+[^\n]+\n)+)",
        code, flags=re.IGNORECASE
    )
    for og in owner_guards:
        m3 = code.replace(og, "").strip()
        if m3 and m3 != code and len(m3) > 25:
            variants.append((m3, f"{fn_str} strips resource `owner_id` verification before returning sensitive object (CWE-639 IDOR)."))

    # Strategy 4: Method call replacement findByOwnerAndId -> findById
    if any(k in code for k in ("findByOwnerAndId", "findByUserAndId", "findByTenantAndId", "findByAccountAndId")):
        m4 = re.sub(r"findBy(?:Owner|User|Tenant|Account)AndId\(([^,]+),\s*([^)]+)\)", r"findById(\2)", code)
        if m4 != code:
            variants.append((m4, f"{fn_str} replaces scoped query method with unscoped `findById` (CWE-639 IDOR)."))

    return variants


# ---------------------------------------------------------------------------
# 2. High-Volume Missing Authorization Mutators
# ---------------------------------------------------------------------------

def generate_missing_authz_variants(code: str, lang: str) -> List[Tuple[str, str]]:
    variants = []
    fn_name = extract_primary_function_name(code)
    fn_str = f"Method `{fn_name}()`" if fn_name else "Handler"

    # Strategy 1: Decorator removal
    decorators = re.findall(r"@(?:login_required|permission_required|user_passes_test|PreAuthorize|Secured|RolesAllowed|UseGuards|RequirePermission|has_permission)(?:\([^)]*\))?\s*\n", code, re.IGNORECASE)
    for dec in decorators:
        m1 = code.replace(dec, "").strip()
        if m1 != code:
            variants.append((m1, f"{fn_str} executes sensitive action without `{dec.strip()}` authorization guard (CWE-862)."))

    # Strategy 2: Policy assertions
    if any(k in code for k in ("$this->authorize", "Gate::authorize", "Gate::allows", "Gate::deny", "authorize(")):
        m2 = re.sub(r"(?:\$this->authorize|Gate::authorize|Gate::allows|authorize)\([^)]+\);\s*\n?", "", code)
        if m2 != code:
            variants.append((m2, f"{fn_str} mutates resource without invoking `$this->authorize()` policy check (CWE-862)."))

    # Strategy 3: Guard clauses
    guard_match = re.findall(
        r"(?:if\s*\([^)]*(?:is_authenticated|has_perm|hasPermission|can|isAdmin|is_admin|checkPermission)[^)]*\)\s*\{[^}]+\}|if\s+(?:not\s+|!)?(?:request\.user|user|req\.user|Auth::user\(\))\.(?:is_authenticated|has_perm|hasPermission|can|isAdmin|is_admin)\([^)]*\)\s*:\s*\n(?:\s+raise[^\n]+\n|\s+return[^\n]+\n))",
        code, flags=re.IGNORECASE
    )
    for gm in guard_match:
        m3 = code.replace(gm, "").strip()
        if m3 != code and len(m3) > 25:
            variants.append((m3, f"{fn_str} executes sensitive logic without verifying caller `is_authenticated` state (CWE-862)."))

    # Strategy 4: Framework permission checks
    for chk in ["self.check_permissions(request)", "self.check_object_permissions(request, obj)", "check_permissions()"]:
        if chk in code:
            m4 = code.replace(chk, "")
            variants.append((m4, f"{fn_str} omits `{chk}` invocation before processing action (CWE-862)."))

    return variants


# ---------------------------------------------------------------------------
# 3. High-Volume Incorrect Authorization Mutators
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
        (r'hasAuthority\(["\']ADMIN["\']\)', '!hasAuthority("ADMIN")', "inverting authority check"),
        (r'has_perm\([^)]+\)', 'True', "forcing `has_perm()` to unconditionally return True"),
        (r'can\([^)]+\)', 'true', "forcing `$user->can()` to unconditionally return true"),
        (r'user\.is_staff\s*and\s*user\.is_active', 'user.is_staff or user.is_active', "relaxing `and` to `or` conjunction"),
        (r'isAdmin\s*&&\s*isOwner', 'isAdmin || isOwner', "relaxing `&&` to `||` conjunction"),
        (r'hasRole\("ADMIN"\)\s*&&\s*hasRole\("AUDIT"\)', 'hasRole("ADMIN") || hasRole("AUDIT")', "relaxing role requirements with `||`"),
    ]

    for pat, rep, desc in inversion_pairs:
        if re.search(pat, code, flags=re.IGNORECASE):
            m1 = re.sub(pat, rep, code, count=1, flags=re.IGNORECASE).strip()
            if m1 != code:
                variants.append((m1, f"{fn_str} contains flawed access control check ({desc}), permitting unauthorized privilege escalation (CWE-863)."))

    return variants


# ---------------------------------------------------------------------------
# 4. High-Volume Authentication Bypass Mutators
# ---------------------------------------------------------------------------

def generate_auth_bypass_variants(code: str, lang: str) -> List[Tuple[str, str]]:
    variants = []
    fn_name = extract_primary_function_name(code)
    fn_str = f"Handler `{fn_name}()`" if fn_name else "Authentication handler"

    # Strategy 1: Timing attacks
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

    if "MessageDigest.isEqual" in code:
        m3b = re.sub(r"MessageDigest\.isEqual\(([^,]+),\s*([^)]+)\)", r"Arrays.equals(\1, \2)", code)
        if m3b != code:
            variants.append((m3b, f"{fn_str} replaces timing-safe `MessageDigest.isEqual` with non-constant-time `Arrays.equals` (CWE-287)."))

    # Strategy 2: JWT unverified decode
    if "jwt.verify(" in code:
        m4 = re.sub(r"jwt\.verify\(([^,]+),[^)]+\)", r"jwt.decode(\1)", code)
        if m4 != code:
            variants.append((m4, f"{fn_str} replaces cryptographic `jwt.verify()` with unverified `jwt.decode()`, bypassing signature verification (CWE-287)."))

    # Strategy 3: Algorithm none in JWT
    if re.search(r"algorithms=\[['\"]HS256['\"]\]", code):
        m5 = re.sub(r"algorithms=\[['\"]HS256['\"]\]", "algorithms=['none', 'HS256']", code)
        if m5 != code:
            variants.append((m5, f"{fn_str} permits insecure `none` algorithm in JWT verification whitelist (CWE-287)."))

    # Strategy 4: Password hash verification bypass
    if "password_verify(" in code:
        m6 = re.sub(r"password_verify\([^)]+\)", "true /* bypassed */", code)
        if m6 != code:
            variants.append((m6, f"{fn_str} forces `password_verify()` to unconditionally return true, allowing arbitrary password bypass (CWE-287)."))

    if "bcrypt.compare(" in code:
        m7 = re.sub(r"bcrypt\.compare\([^)]+\)", "Promise.resolve(true)", code)
        if m7 != code:
            variants.append((m7, f"{fn_str} forces `bcrypt.compare()` to resolve true without verifying password hash (CWE-287)."))

    # Strategy 5: Insecure default secret keys
    if "os.getenv('SECRET_KEY')" in code or "process.env.SECRET_KEY" in code:
        m8 = re.sub(r"(os\.getenv\(['\"]SECRET_KEY['\"])\)", r"\1, 'insecure_default_secret_key')", code)
        m8 = re.sub(r"(process\.env\.SECRET_KEY)", r"(\1 || 'insecure_default_secret_key')", m8)
        if m8 != code:
            variants.append((m8, f"{fn_str} introduces insecure hardcoded fallback secret key (CWE-287)."))

    return variants


# ---------------------------------------------------------------------------
# 5. High-Volume Clean Remediation Mutators
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
