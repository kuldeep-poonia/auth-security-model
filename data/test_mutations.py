import json
import os
import pytest

from data.mutate_code_units import (
    mutate_missing_authz,
    mutate_incorrect_authz,
    mutate_idor,
    mutate_auth_bypass,
    augment_clean_negative,
)
from data.split_by_source import extract_source_key


def test_mutate_missing_authz_python():
    code = """@login_required\ndef delete_profile(request, id):\n    User.objects.filter(id=id).delete()\n"""
    res = mutate_missing_authz(code, "python")
    assert res is not None
    mut_code, expl = res
    assert "@login_required" not in mut_code
    assert "Missing authorization check" in expl


def test_mutate_missing_authz_java():
    code = """@PreAuthorize("hasRole('ADMIN')")\npublic void deleteAccount(Long id) {\n    accountRepo.deleteById(id);\n}\n"""
    res = mutate_missing_authz(code, "java")
    assert res is not None
    mut_code, expl = res
    assert "@PreAuthorize" not in mut_code


def test_mutate_incorrect_authz():
    code = """def update_settings(user, settings):\n    if user.role == "admin":\n        save(settings)\n"""
    res = mutate_incorrect_authz(code, "python")
    assert res is not None
    mut_code, expl = res
    assert 'role != "admin"' in mut_code
    assert "Incorrect authorization" in expl


def test_mutate_idor():
    code = """def get_document(request, doc_id):\n    doc = get_object_or_404(Document, id=doc_id, user=request.user)\n    return doc\n"""
    res = mutate_idor(code, "python")
    assert res is not None
    mut_code, expl = res
    assert "user=request.user" not in mut_code
    assert "IDOR" in expl


def test_mutate_auth_bypass():
    code = """def verify_token(token):\n    payload = jwt.verify(token, SECRET, { algorithms: ["HS256"] })\n    return payload\n"""
    res = mutate_auth_bypass(code, "javascript")
    assert res is not None
    mut_code, expl = res
    assert "jwt.decode" in mut_code or "none" in mut_code
    assert "Authentication bypass" in expl


def test_augment_clean_negative():
    code = """def check_access(user, resource):\n    if user.id != resource.owner_id:\n        raise Forbidden()\n    return True\n"""
    res = augment_clean_negative(code, "python", variation_index=1)
    assert res is not None
    mut_code, expl = res
    assert "currentUser" in mut_code or "Clean" in expl


def test_zero_train_test_data_leakage():
    train_path = "data/splits/train_seed.json"
    test_path = "data/splits/test.json"
    if not (os.path.exists(train_path) and os.path.exists(test_path)):
        pytest.skip("Splits not generated yet")

    with open(train_path, "r", encoding="utf-8") as f:
        train_data = json.load(f)
    with open(test_path, "r", encoding="utf-8") as f:
        test_data = json.load(f)

    train_sources = {extract_source_key(r) for r in train_data}
    test_sources = {extract_source_key(r) for r in test_data}

    # Verify zero source cluster overlap
    overlap = train_sources & test_sources
    assert len(overlap) == 0, f"Found overlapping source clusters: {overlap}"

    # Verify zero code snippet overlap
    train_code = {r["code"].strip() for r in train_data}
    test_code = {r["code"].strip() for r in test_data}
    code_overlap = train_code & test_code
    assert len(code_overlap) == 0, f"Found {len(code_overlap)} identical code snippets across train and test"


def test_test_set_purity():
    test_path = "data/splits/test.json"
    if not os.path.exists(test_path):
        pytest.skip("Test split not generated yet")

    with open(test_path, "r", encoding="utf-8") as f:
        test_data = json.load(f)

    # Test set must be 100% real (no synthetic/mutated examples)
    synthetic_in_test = [r for r in test_data if r.get("is_synthetic")]
    assert len(synthetic_in_test) == 0, f"Test set contains {len(synthetic_in_test)} synthetic items!"
