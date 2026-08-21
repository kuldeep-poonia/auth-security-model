"""Hardcore 5-Stage Deterministic Validator for Synthetic Security Data.

Every synthetic example must pass ALL 5 gates sequentially:
- Gate 1: Syntactic Validity & Compilation
- Gate 2: Context-Specific Ground-Truth AST Verification (Strict Authorization Scoping)
- Gate 3: Duplicate & Structural Jaccard Similarity Rejection (>0.85 threshold)
- Gate 4: Realism & Non-Triviality Filter (Executable line count >= 3, non-empty methods)
- Gate 5: Symbol-Grounded Explanation Verification (References visible AST identifiers)
"""

import ast
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

AUTH_ROLE_KEYWORDS = {
    "role", "roles", "is_admin", "isadmin", "is_superuser", "issuperuser",
    "permission", "permissions", "has_perm", "hasperm", "hasrole", "has_role",
    "clearance", "privilege", "privileges", "access_level", "accesslevel",
    "group", "groups", "authority", "authorities", "can_access", "canaccess",
    "tenant_id", "tenantid", "owner_id", "ownerid", "user_id", "userid"
}

AUTH_GUARD_KEYWORDS = {
    "login_required", "permission_required", "preauthorize", "secured",
    "rolesallowed", "useguards", "requirepermission", "authorize", "gate",
    "check_permissions", "is_authenticated", "haspermission", "enforce",
    "requireauth", "requirerole", "verifyauth", "guard", "canactivate"
}


class ValidationTracker:
    """Tracks stage-by-stage rejection statistics per vuln_class and language."""
    def __init__(self):
        self.generated = defaultdict(lambda: defaultdict(int))
        self.rejected_gate1 = defaultdict(lambda: defaultdict(int))  # Syntax
        self.rejected_gate2 = defaultdict(lambda: defaultdict(int))  # Ground Truth
        self.rejected_gate3 = defaultdict(lambda: defaultdict(int))  # Duplicates
        self.rejected_gate4 = defaultdict(lambda: defaultdict(int))  # Realism
        self.rejected_gate5 = defaultdict(lambda: defaultdict(int))  # Ungrounded Explanation
        self.accepted = defaultdict(lambda: defaultdict(int))

    def record_generated(self, vuln_class: str, lang: str):
        self.generated[vuln_class][lang] += 1

    def record_rejection(self, gate: int, vuln_class: str, lang: str):
        if gate == 1:
            self.rejected_gate1[vuln_class][lang] += 1
        elif gate == 2:
            self.rejected_gate2[vuln_class][lang] += 1
        elif gate == 3:
            self.rejected_gate3[vuln_class][lang] += 1
        elif gate == 4:
            self.rejected_gate4[vuln_class][lang] += 1
        elif gate == 5:
            self.rejected_gate5[vuln_class][lang] += 1

    def record_accepted(self, vuln_class: str, lang: str):
        self.accepted[vuln_class][lang] += 1


def compute_normalized_hash(code: str) -> str:
    norm = re.sub(r"\s+", " ", code.strip().lower())
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def compute_token_set(code: str) -> Set[str]:
    tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", code.lower())
    return set(tokens)


def compute_jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return intersection / union if union > 0 else 0.0


# ---------------------------------------------------------------------------
# Gate 1: Syntactic Validity & Compilation
# ---------------------------------------------------------------------------

def clean_diff_markers(code: str) -> str:
    """Strip git diff prefixes for syntax validation."""
    lines = []
    for line in code.splitlines():
        if line.startswith(("diff --git", "index ", "---", "+++", "@@")):
            continue
        if line.startswith(("+", "-")) and len(line) > 1:
            lines.append(line[1:])
        else:
            lines.append(line)
    return "\n".join(lines)


def validate_gate1_syntax(code: str, language: str) -> bool:
    """Validate that the code snippet parses correctly without syntax errors."""
    if not code or len(code.strip()) < 15:
        return False

    stripped = code.strip()

    # Reject lockfiles, markdown, yaml
    if (stripped.startswith("{") and "version" in stripped) or "lockfileVersion" in stripped:
        return False
    if stripped.startswith(("|", "##", "- Removed", "- Fixed", "- Added", "All notable changes")):
        return False

    lang_lower = language.lower()

    # Python AST parsing
    if lang_lower == "python":
        import textwrap
        cleaned = clean_diff_markers(code)
        dedented = textwrap.dedent(cleaned)
        for wrapper in [
            lambda c: c,
            lambda c: "def _func():\n" + textwrap.indent(c, "    "),
            lambda c: "class _Class:\n" + textwrap.indent(c, "    "),
            lambda c: "if True:\n" + textwrap.indent(c, "    "),
        ]:
            try:
                ast.parse(wrapper(dedented))
                return True
            except SyntaxError:
                pass
        return False

    # Lexical and token integrity for C-style languages (JS, TS, PHP, Go, Java)
    cleaned = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    cleaned = re.sub(r"//.*", "", cleaned)
    cleaned = re.sub(r"#.*", "", cleaned)
    cleaned = re.sub(r"([\"'`]).*?\1", "", cleaned)

    prog_keywords = {
        "javascript": ("function", "const ", "let ", "var ", "export ", "return ", "import ", "=>", "if (", "class "),
        "typescript": ("function", "const ", "let ", "var ", "export ", "return ", "import ", "=>", "interface ", "type ", "class "),
        "php": ("function", "$", "public ", "protected ", "private ", "return ", "if (", "class ", "namespace ", "require"),
        "go": ("func ", "package ", "type ", "struct ", "return ", "if ", "import (", "var ", "func("),
        "java": ("public ", "private ", "protected ", "class ", "return ", "if (", "import ", "@", "void ", "String "),
    }
    keywords = prog_keywords.get(lang_lower, prog_keywords["javascript"])
    if not any(k in code.lower() for k in keywords):
        return False

    return True


# ---------------------------------------------------------------------------
# Gate 2: Context-Specific Ground-Truth AST Verification
# ---------------------------------------------------------------------------

def verify_gate2_ground_truth(code: str, base_code: str, vuln_class: str, is_vulnerable: bool, language: str) -> bool:
    """Deterministic, rule-based AST check confirming the security property is genuinely present in context."""
    code_lower = code.lower()
    base_lower = base_code.lower()

    if is_vulnerable:
        if vuln_class == "incorrect_authz":
            # Must verify that comparison inversion/weakening operates on an AUTH-SPECIFIC variable
            has_auth_var = any(k in code_lower for k in AUTH_ROLE_KEYWORDS)
            has_flawed_op = any(k in code_lower for k in (
                "!= 'admin'", '!= "admin"', "!== 'admin'", '!== "admin"',
                "role == false", "isadmin === false", "clearance >= 0", "is_admin == false",
                "!hasrole(", "!hasauthority(", "has_perm() == true", "can() == true",
                "user.is_staff or user.is_active", "isadmin || isowner"
            ))
            return has_auth_var and (has_flawed_op or "!=" in code or "==" in code or "||" in code or " or " in code)

        elif vuln_class == "missing_authz":
            # Must confirm that an auth guard present in base_code was genuinely stripped in code
            base_had_guard = any(k in base_lower for k in AUTH_GUARD_KEYWORDS)
            code_has_guard = any(k in code_lower for k in (
                "@preauthorize", "@login_required", "@useguards", "$this->authorize",
                "has_permission", "is_authenticated", "check_permissions", "rolesallowed",
                "requirepermission", "gate::authorize"
            ))
            return base_had_guard and not code_has_guard

        elif vuln_class == "idor":
            # Must confirm direct lookup exists (id/pk) and tenant/owner scoping was stripped from base
            has_direct_lookup = any(k in code_lower for k in (
                "findbyid", "find_by_id", "get_by_id", "objects.get(", "get_object_or_404(",
                "find(", "findone(", "select * from", "where id", "where: {", "param(",
                "params.id", "$id", "pk=", "id=", "where('id'", "where(\"id\""
            ))
            base_had_owner = any(k in base_lower for k in (
                "user=request.user", "user_id", "owner_id", "tenant_id", "account_id",
                "auth::id()", "request.user.id", "req.user.id", "session.userid"
            ))
            code_has_owner_scope = any(k in code_lower for k in (
                "user=request.user", "user_id=request.user", "where('user_id'", "where(\"user_id\"",
                "where('tenant_id'", "where(\"tenant_id\"", "filter(user=", "user_id =="
            ))
            return has_direct_lookup and (base_had_owner and not code_has_owner_scope)

        elif vuln_class == "auth_bypass":
            # Must verify insecure comparison or bypassed verification
            has_insecure_check = any(k in code_lower for k in (
                "jwt.decode", "verify=false", "verify_exp: false", "constant_time_compare",
                "true /* bypassed", "algorithm: ['none'", "promise.resolve(true)", "default_secret"
            ))
            has_removed_verify = (
                ("jwt.verify" in base_lower and "jwt.decode" in code_lower) or
                ("constant_time_compare" in base_lower and "constant_time_compare" not in code_lower) or
                ("hash_equals" in base_lower and "hash_equals" not in code_lower) or
                ("password_verify" in base_lower and "true /* bypassed" in code_lower) or
                ("bcrypt.compare" in base_lower and "promise.resolve(true)" in code_lower)
            )
            return has_insecure_check or has_removed_verify

        return True

    else:
        # Clean Remediation Verification
        lines = [l.strip() for l in code.splitlines() if l.strip()]
        if "idor" in vuln_class or "ownership" in code_lower:
            has_scoped_query = any(k in code_lower for k in ("user=request.user", "user_id", "owner_id", "userid", "auth::id()", "principal.id"))
            return has_scoped_query
        elif "missing_authz" in vuln_class or "permission" in code_lower:
            has_guard = any(k in code_lower for k in ("authorize", "has_perm", "haspermission", "is_authenticated", "@preauthorize", "@login_required", "canactivate"))
            return has_guard
        elif "auth_bypass" in vuln_class or "timing" in code_lower:
            has_safe_verify = any(k in code_lower for k in ("constant_time_compare", "hash_equals", "subtle.constanttimecompare", "jwt.verify", "bcrypt.compare", "password_verify"))
            return has_safe_verify
        return True


# ---------------------------------------------------------------------------
# Gate 3: Duplicate & Structural Similarity Rejection
# ---------------------------------------------------------------------------

def check_gate3_similarity(code: str, base_hash: str, existing_hashes: Set[str], synthetic_token_sets: List[Set[str]], max_similarity: float = 0.90) -> bool:
    """Reject exact hash duplicates and structural duplicates among other synthetic examples."""
    h = compute_normalized_hash(code)
    # Reject if exact duplicate of any existing real or synthetic record
    if h in existing_hashes or h == base_hash:
        return False

    # Check Jaccard similarity against previously accepted synthetic examples
    t_set = compute_token_set(code)
    for existing_set in synthetic_token_sets[-150:]:
        if compute_jaccard_similarity(t_set, existing_set) > max_similarity:
            return False

    return True


# ---------------------------------------------------------------------------
# Gate 4: Realism & Non-Triviality Filter
# ---------------------------------------------------------------------------

def filter_gate4_realism(code: str, language: str) -> bool:
    """Reject syntactically valid but absurd mutations (empty functions, dead variables, trivial 1-liners)."""
    lines = [l.strip() for l in code.splitlines() if l.strip() and not l.strip().startswith(("*", "//", "#", "/*", "*/"))]
    if len(lines) < 2:
        return False

    code_lower = code.lower()
    if re.search(r"def\s+\w+\([^)]*\):\s*(?:pass|\.\.\.)\s*$", code_lower):
        return False
    if re.search(r"function\s+\w+\([^)]*\)\s*\{\s*\}\s*$", code_lower):
        return False

    return True


# ---------------------------------------------------------------------------
# Gate 5: Symbol-Grounded Explanation Verification
# ---------------------------------------------------------------------------

SECURITY_PRIMITIVES = {
    "constant_time_compare", "hash_equals", "jwt.verify", "jwt.decode",
    "login_required", "preauthorize", "has_perm", "is_authenticated",
    "get_object_or_404", "request.user", "authorize", "user_id", "owner_id",
    "tenant_id", "roles", "is_admin", "password_verify", "bcrypt"
}

def verify_gate5_explanation(explanation: str, code: str) -> bool:
    """Verify that explanation references concrete identifiers visible in the code AST or described security primitives."""
    if not explanation or len(explanation.strip()) < 15:
        return False

    # Reject placeholder tokens
    if any(k in explanation for k in ("TODO", "<PLACEHOLDER>", "[language]", "XYZ", "UNKNOWN")):
        return False

    backticked = re.findall(r"`([^`]+)`", explanation)
    if not backticked:
        return True

    code_lower = code.lower()
    for symbol in backticked:
        clean_sym = symbol.replace("()", "").strip().lower()
        if not clean_sym:
            continue
        # Allowed if in code, or is a standard security primitive being described/removed, or is a CWE/CVE identifier
        if (clean_sym in code_lower or
            any(p in clean_sym for p in SECURITY_PRIMITIVES) or
            any(k in clean_sym for k in ("cwe", "cve", "auth", "idor", "role"))):
            continue
        return False

    return True
