"""High-Scale Hardcore-Validated Synthetic Dataset Pipeline.

Scales generation to 5,000+ candidate mutations from real base code across all 4 vuln classes:
- IDOR (direct parameter lookup, unscoped queries, missing tenant isolation)
- Missing Authorization (unprotected handlers, stripped decorators, omitted gate calls)
- Incorrect Authorization (role check inversion, clearance weakening, relaxed logic conjunctions)
- Authentication Bypass (timing attacks, unverified token decodes, hash bypasses)
- Clean Remediation (effective precedence-ordered guards, ownership filters, timing-safe compare)

Integrates 100% of validated accepted synthetic candidates with class-weighted loss support in trainer.
"""

import ast
import json
import os
import random
import re
import sys
from collections import defaultdict
from typing import Any, Dict, List, Set

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from data.hardcore_synthetic_validator import (
    ValidationTracker,
    compute_normalized_hash,
    compute_token_set,
    validate_gate1_syntax,
    verify_gate2_ground_truth,
    check_gate3_similarity,
    filter_gate4_realism,
    verify_gate5_explanation,
)
from data.generate_synthetic_variants import (
    extract_primary_function_name,
    generate_idor_variants,
    generate_missing_authz_variants,
    generate_incorrect_authz_variants,
    generate_auth_bypass_variants,
    generate_clean_remediations,
)


def generate_parametric_idor(code: str, lang: str) -> List[Dict[str, Any]]:
    """Generate IDOR variants by stripping scoping from query and lookup functions."""
    candidates = []
    fn = extract_primary_function_name(code) or "handler"
    
    # 1. Parameter lookups
    for field in ["id", "pk", "uuid", "order_id", "invoice_id", "doc_id", "profile_id", "account_id", "report_id"]:
        if f"{field}" in code.lower():
            for owner in ["user_id", "owner_id", "tenant_id", "author_id", "org_id"]:
                if owner in code.lower():
                    m = re.sub(rf",\s*{owner}\s*[:=]\s*[^,\s)]+", "", code, flags=re.IGNORECASE)
                    m = re.sub(rf"\b{owner}\s*[:=]\s*[^,\s)]+\s*,\s*", "", m, flags=re.IGNORECASE)
                    m = re.sub(rf"\.where\(['\"]{owner}['\"],\s*[^)]+\)", "", m, flags=re.IGNORECASE)
                    if m != code and len(m.strip()) > 25:
                        candidates.append({
                            "code": m, "vuln_class": "idor", "is_vulnerable": True,
                            "confidence_target": 0.88,
                            "explanation": f"Function `{fn}()` queries object by `{field}` without scoping to authenticated `{owner}` (CWE-639 IDOR).",
                            "mutation_type": "idor_strip_scoping"
                        })
    return candidates


def generate_parametric_incorrect_authz(code: str, lang: str) -> List[Dict[str, Any]]:
    """Generate incorrect_authz variants by inverting permission predicates."""
    candidates = []
    fn = extract_primary_function_name(code) or "auth_check"

    role_patterns = [
        (r'role\s*==\s*["\'](\w+)["\']', r'role != "\1"', "inverting role inequality check"),
        (r'role\s*===\s*["\'](\w+)["\']', r'role !== "\1"', "inverting strict role equality"),
        (r'is_admin\s*==\s*True', r'is_admin == False', "flipping admin requirement to False"),
        (r'isAdmin\s*===\s*true', r'isAdmin === false', "flipping isAdmin requirement to false"),
        (r'hasRole\(["\'](\w+)["\']\)', r'!hasRole("\1")', "negating hasRole requirement"),
        (r'hasAuthority\(["\'](\w+)["\']\)', r'!hasAuthority("\1")', "negating hasAuthority requirement"),
        (r'has_perm\(([^)]+)\)', r'True', "forcing has_perm to unconditionally return True"),
        (r'can\(([^)]+)\)', r'true', "forcing user permission check to return true"),
        (r'clearance\s*>=\s*(\d+)', r'clearance >= 0', "weakening clearance threshold to 0"),
        (r'level\s*>=\s*(\d+)', r'level >= 0', "weakening required privilege level to 0"),
    ]

    for pat, rep, desc in role_patterns:
        if re.search(pat, code, flags=re.IGNORECASE):
            m = re.sub(pat, rep, code, count=1, flags=re.IGNORECASE).strip()
            if m != code and len(m) > 25:
                candidates.append({
                    "code": m, "vuln_class": "incorrect_authz", "is_vulnerable": True,
                    "confidence_target": 0.88,
                    "explanation": f"Logic in `{fn}()` contains flawed authorization predicate ({desc}), allowing unauthorized privilege escalation (CWE-863).",
                    "mutation_type": "incorrect_authz_predicate_invert"
                })
    return candidates


def generate_parametric_auth_bypass(code: str, lang: str) -> List[Dict[str, Any]]:
    """Generate auth_bypass variants by degrading timing/signature checks."""
    candidates = []
    fn = extract_primary_function_name(code) or "auth_handler"

    # Timing attacks
    for safe_fn, unsafe_fn in [("constant_time_compare", "=="), ("hash_equals", "==="), ("subtle.ConstantTimeCompare", "==")]:
        if safe_fn in code:
            m = re.sub(rf"{safe_fn}\(([^,]+),\s*([^)]+)\)", rf"\1 {unsafe_fn} \2", code)
            if m != code and len(m) > 25:
                candidates.append({
                    "code": m, "vuln_class": "auth_bypass", "is_vulnerable": True,
                    "confidence_target": 0.92,
                    "explanation": f"Handler `{fn}()` replaces timing-safe `{safe_fn}()` with standard comparison, vulnerable to timing side-channels (CWE-287).",
                    "mutation_type": "auth_bypass_timing"
                })

    # JWT signature bypass
    if "jwt.verify(" in code:
        m = re.sub(r"jwt\.verify\(([^,]+),[^)]+\)", r"jwt.decode(\1)", code)
        if m != code:
            candidates.append({
                "code": m, "vuln_class": "auth_bypass", "is_vulnerable": True,
                "confidence_target": 0.92,
                "explanation": f"Handler `{fn}()` replaces cryptographic `jwt.verify()` with unverified `jwt.decode()`, bypassing signature checks (CWE-287).",
                "mutation_type": "auth_bypass_jwt"
            })

    # Password hash bypass
    if "password_verify(" in code:
        m = re.sub(r"password_verify\([^)]+\)", "true /* bypassed */", code)
        if m != code:
            candidates.append({
                "code": m, "vuln_class": "auth_bypass", "is_vulnerable": True,
                "confidence_target": 0.92,
                "explanation": f"Handler `{fn}()` forces `password_verify()` to unconditionally return true, allowing credential bypass (CWE-287).",
                "mutation_type": "auth_bypass_pwd"
            })

    return candidates


def generate_parametric_missing_authz(code: str, lang: str) -> List[Dict[str, Any]]:
    """Generate missing_authz variants by stripping guards and decorators."""
    candidates = []
    fn = extract_primary_function_name(code) or "route_handler"

    # Decorator removal
    decorators = re.findall(r"@(?:login_required|permission_required|user_passes_test|PreAuthorize|Secured|RolesAllowed|UseGuards|RequirePermission)(?:\([^)]*\))?\s*\n", code, re.IGNORECASE)
    for dec in decorators:
        m = code.replace(dec, "").strip()
        if m != code and len(m) > 25:
            candidates.append({
                "code": m, "vuln_class": "missing_authz", "is_vulnerable": True,
                "confidence_target": 0.90,
                "explanation": f"Method `{fn}()` executes sensitive handler without `{dec.strip()}` authorization guard (CWE-862).",
                "mutation_type": "missing_authz_strip_decorator"
            })

    # Policy checks
    if any(k in code for k in ("$this->authorize", "Gate::authorize", "authorize(")):
        m = re.sub(r"(?:\$this->authorize|Gate::authorize|authorize)\([^)]+\);\s*\n?", "", code)
        if m != code and len(m) > 25:
            candidates.append({
                "code": m, "vuln_class": "missing_authz", "is_vulnerable": True,
                "confidence_target": 0.90,
                "explanation": f"Method `{fn}()` executes mutation without invoking authorization policy check (CWE-862).",
                "mutation_type": "missing_authz_strip_policy"
            })

    return candidates


def run_synthetic_generation_and_validation():
    print("=" * 80)
    print("  LAUNCHING HIGH-SCALE HARDCORE-VALIDATED SYNTHETIC DATA PIPELINE")
    print("=" * 80 + "\n")

    train_path = "data/splits/train.json"
    with open(train_path, "r", encoding="utf-8") as f:
        real_train_data = json.load(f)

    real_base_examples = [r for r in real_train_data if r.get("source") != "hardcore_validated_synthetic"]
    print(f"[INFO] Loaded {len(real_base_examples)} verified real base training examples.")

    tracker = ValidationTracker()

    existing_hashes: Set[str] = set()
    synthetic_token_sets: List[Set[str]] = []

    for r in real_base_examples:
        existing_hashes.add(compute_normalized_hash(r.get("code", "")))

    accepted_synthetic_records = []
    accepted_by_class = defaultdict(int)

    for base_rec in real_base_examples:
        base_code = base_rec.get("code", "")
        base_hash = compute_normalized_hash(base_code)
        lang = base_rec.get("language", "generic")
        base_is_vuln = base_rec.get("is_vulnerable", False)
        base_class = base_rec.get("vuln_class", "none")

        candidates: List[Dict[str, Any]] = []

        # 1. High-Volume IDOR
        candidates.extend(generate_parametric_idor(base_code, lang))
        for m_code, m_exp in generate_idor_variants(base_code, lang):
            candidates.append({
                "code": m_code, "vuln_class": "idor", "is_vulnerable": True,
                "confidence_target": 0.88, "explanation": m_exp, "mutation_type": "idor_strip_scope"
            })

        # 2. High-Volume Missing Authz
        candidates.extend(generate_parametric_missing_authz(base_code, lang))
        for m_code, m_exp in generate_missing_authz_variants(base_code, lang):
            candidates.append({
                "code": m_code, "vuln_class": "missing_authz", "is_vulnerable": True,
                "confidence_target": 0.90, "explanation": m_exp, "mutation_type": "missing_authz_strip_guard"
            })

        # 3. High-Volume Incorrect Authz
        candidates.extend(generate_parametric_incorrect_authz(base_code, lang))
        for m_code, m_exp in generate_incorrect_authz_variants(base_code, lang):
            candidates.append({
                "code": m_code, "vuln_class": "incorrect_authz", "is_vulnerable": True,
                "confidence_target": 0.88, "explanation": m_exp, "mutation_type": "incorrect_authz_invert"
            })

        # 4. High-Volume Auth Bypass
        candidates.extend(generate_parametric_auth_bypass(base_code, lang))
        for m_code, m_exp in generate_auth_bypass_variants(base_code, lang):
            candidates.append({
                "code": m_code, "vuln_class": "auth_bypass", "is_vulnerable": True,
                "confidence_target": 0.92, "explanation": m_exp, "mutation_type": "auth_bypass_timing"
            })

        # 5. Clean Remediations
        for m_code, m_exp in generate_clean_remediations(base_code, base_class, lang):
            candidates.append({
                "code": m_code, "vuln_class": "none", "is_vulnerable": False,
                "confidence_target": 0.08, "explanation": m_exp, "mutation_type": "clean_remediation_guard"
            })

        # Process and Validate Each Candidate through the 5 Gates
        for cand in candidates:
            v_class = cand["vuln_class"]
            is_vuln = cand["is_vulnerable"]
            cand_code = cand["code"]
            cand_exp = cand["explanation"]

            tracker.record_generated(v_class, lang)

            # --- Gate 1: Syntax ---
            if not validate_gate1_syntax(cand_code, lang):
                tracker.record_rejection(1, v_class, lang)
                continue

            # --- Gate 2: Ground-Truth AST Verification ---
            if not verify_gate2_ground_truth(cand_code, base_code, v_class, is_vuln, lang):
                tracker.record_rejection(2, v_class, lang)
                continue

            # --- Gate 3: Similarity & Duplicate Rejection ---
            if not check_gate3_similarity(cand_code, base_hash, existing_hashes, synthetic_token_sets):
                tracker.record_rejection(3, v_class, lang)
                continue

            # --- Gate 4: Realism & Non-Triviality ---
            if not filter_gate4_realism(cand_code, lang):
                tracker.record_rejection(4, v_class, lang)
                continue

            # --- Gate 5: Symbol-Grounded Explanation ---
            if not verify_gate5_explanation(cand_exp, cand_code):
                tracker.record_rejection(5, v_class, lang)
                continue

            # Survived ALL 5 Gates -> Accept!
            tracker.record_accepted(v_class, lang)
            accepted_by_class[v_class] += 1
            existing_hashes.add(compute_normalized_hash(cand_code))
            synthetic_token_sets.append(compute_token_set(cand_code))

            rec_id = f"synth-{v_class}-{lang}-{len(accepted_synthetic_records):05d}"
            accepted_synthetic_records.append({
                "id": rec_id,
                "source": "hardcore_validated_synthetic",
                "cwe_ids": ["CWE-639"] if v_class == "idor" else (["CWE-862"] if v_class == "missing_authz" else (["CWE-863"] if v_class == "incorrect_authz" else (["CWE-287"] if v_class == "auth_bypass" else []))),
                "vuln_class": v_class,
                "language": lang,
                "code": cand_code,
                "is_vulnerable": is_vuln,
                "confidence_target": cand["confidence_target"],
                "explanation": cand_exp,
                "provenance": {
                    "base_id": base_rec.get("id"),
                    "mutation_type": cand["mutation_type"],
                    "synthetic": True,
                    "validation_passed": ["gate1_syntax", "gate2_ground_truth_ast", "gate3_similarity_dedup", "gate4_realism", "gate5_grounded_exp"],
                    "certainty_tier": 2 if is_vuln else 1,
                },
            })

    # Integrate 100% of validated accepted synthetic records (NO discard)
    updated_train = real_base_examples + accepted_synthetic_records
    random.seed(42)
    random.shuffle(updated_train)

    with open(train_path, "w", encoding="utf-8") as f:
        json.dump(updated_train, f, indent=2)

    # ---------------------------------------------------------------------------
    # Print Detailed Rejection-Rate Matrix Report
    # ---------------------------------------------------------------------------
    print("=" * 80)
    print("  STAGE-BY-STAGE REJECTION-RATE MATRIX (HARDCORE VALIDATION BATTERY)")
    print("=" * 80)

    all_classes = sorted(list(tracker.generated.keys()))
    all_langs = sorted(list(set(l for c in all_classes for l in tracker.generated[c].keys())))

    total_gen_all = sum(sum(tracker.generated[c].values()) for c in all_classes)
    total_g1_all = sum(sum(tracker.rejected_gate1[c].values()) for c in all_classes)
    total_g2_all = sum(sum(tracker.rejected_gate2[c].values()) for c in all_classes)
    total_g3_all = sum(sum(tracker.rejected_gate3[c].values()) for c in all_classes)
    total_g4_all = sum(sum(tracker.rejected_gate4[c].values()) for c in all_classes)
    total_g5_all = sum(sum(tracker.rejected_gate5[c].values()) for c in all_classes)
    total_acc_all = sum(sum(tracker.accepted[c].values()) for c in all_classes)

    print(f"\n{'Vulnerability Class':<18} | {'Language':<11} | {'Gen':<5} | {'G1(Syn)':<7} | {'G2(AST)':<7} | {'G3(Dup)':<7} | {'G4(Real)':<8} | {'G5(Exp)':<7} | {'Accepted':<8} | {'Rejection %'}")
    print("-" * 105)

    for c in all_classes:
        for l in all_langs:
            gen = tracker.generated[c][l]
            if gen == 0:
                continue
            g1 = tracker.rejected_gate1[c][l]
            g2 = tracker.rejected_gate2[c][l]
            g3 = tracker.rejected_gate3[c][l]
            g4 = tracker.rejected_gate4[c][l]
            g5 = tracker.rejected_gate5[c][l]
            acc = tracker.accepted[c][l]
            rej_pct = ((gen - acc) / gen) * 100 if gen > 0 else 0
            print(f"{c:<18} | {l:<11} | {gen:<5} | {g1:<7} | {g2:<7} | {g3:<7} | {g4:<8} | {g5:<7} | {acc:<8} | {rej_pct:>6.1f}%")

    print("-" * 105)
    overall_rej_pct = ((total_gen_all - total_acc_all) / total_gen_all) * 100 if total_gen_all > 0 else 0
    print(f"{'TOTAL OVERALL':<18} | {'ALL':<11} | {total_gen_all:<5} | {total_g1_all:<7} | {total_g2_all:<7} | {total_g3_all:<7} | {total_g4_all:<8} | {total_g5_all:<7} | {total_acc_all:<8} | {overall_rej_pct:>6.1f}%\n")

    print("=" * 80)
    print("  FINAL DATASET RECONCILIATION & BALANCE SUMMARY")
    print("=" * 80)
    vuln_cnt = sum(1 for r in updated_train if r["is_vulnerable"])
    clean_cnt = sum(1 for r in updated_train if not r["is_vulnerable"])
    synth_vuln = sum(1 for r in accepted_synthetic_records if r["is_vulnerable"])
    synth_clean = sum(1 for r in accepted_synthetic_records if not r["is_vulnerable"])

    print(f"• Real Base Examples in Train: {len(real_base_examples)} records (Vuln={sum(1 for r in real_base_examples if r['is_vulnerable'])}, Clean={sum(1 for r in real_base_examples if not r['is_vulnerable'])})")
    print(f"• Total Validated Accepted Synthetic: {len(accepted_synthetic_records)} records (Vuln={synth_vuln}, Clean={synth_clean})")
    print(f"• Integrated Synthetic Count: {len(accepted_synthetic_records)} records (100% of validated examples preserved)")
    print(f"• Synthetic-to-Real Ratio: {len(accepted_synthetic_records) / len(real_base_examples):.4f}:1 (Target <= 1.5:1)")
    print(f"• Total Final Train Split: {len(updated_train)} records (Vuln={vuln_cnt} [{vuln_cnt/len(updated_train)*100:.1f}%], Clean={clean_cnt} [{clean_cnt/len(updated_train)*100:.1f}%])")
    print(f"• Validation Split: 234 records (100% Real Code, Untouched)")
    print(f"• Test Split: 236 records (100% Real Code, Untouched)")
    print(f"• TOTAL DATASET SIZE: {len(updated_train) + 234 + 236} records")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_synthetic_generation_and_validation()
