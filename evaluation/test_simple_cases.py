"""Simple Finding Test Suite for Auth/Authz Model Verification.

Contains 5 straightforward, textbook authorization/authentication cases:
1. Direct IDOR (Python/Flask) - Unscoped object retrieval via path parameter.
2. Missing Auth Check (JS/Express) - Destructive admin endpoint with no auth.
3. Auth Bypass (Python) - Spoofable client header check without validation.
4. Incorrect Authz (Python) - Inverted privilege boolean check (if user.is_banned: grant_access).
5. Clean Protected Endpoint (Python/FastAPI) - Sound tenant & user ownership scoping.
"""

import os
import sys
import json
import argparse
import torch

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from evaluation.eval_model import load_model_for_evaluation, extract_json_from_response, resolve_best_checkpoint
from training.dataset_formatter import SYSTEM_PROMPT, format_user_prompt

SIMPLE_TEST_CASES = [
    {
        "id": "simple-01-idor",
        "title": "Direct IDOR in Invoice Retrieval (Python/Flask)",
        "language": "python",
        "true_is_vulnerable": True,
        "true_vuln_class": "IDOR",
        "description": "Directly queries invoice by ID parameter from URL without checking if current session user owns the invoice.",
        "code": """@app.route('/api/invoices/<int:invoice_id>', methods=['GET'])
def get_invoice(invoice_id):
    invoice = Invoice.query.filter_by(id=invoice_id).first()
    if not invoice:
        return jsonify({'error': 'Invoice not found'}), 404
    return jsonify(invoice.to_dict()), 200"""
    },
    {
        "id": "simple-02-missing-authz",
        "title": "Missing Auth Check on Destructive Admin Route (JavaScript/Express)",
        "language": "javascript",
        "true_is_vulnerable": True,
        "true_vuln_class": "missing_authz_check",
        "description": "Sensitive administrative database drop route exposed without any session, JWT, or role verification middleware.",
        "code": """app.post('/api/admin/reset-system', async (req, res) => {
    const { confirmation } = req.body;
    if (confirmation === 'CONFIRM_RESET') {
        await database.truncateAllTables();
        return res.json({ status: 'system_reset_complete' });
    }
    return res.status(400).json({ error: 'Confirmation required' });
});"""
    },
    {
        "id": "simple-03-auth-bypass",
        "title": "Spoofable Header Authentication Bypass (Python)",
        "language": "python",
        "true_is_vulnerable": True,
        "true_vuln_class": "auth_bypass",
        "description": "Trusts untrusted X-Internal-Admin header directly from client request without HMAC or secret verification.",
        "code": """def is_authenticated_admin(request):
    internal_header = request.headers.get('X-Internal-Admin')
    if internal_header == 'true':
        return True
    return False"""
    },
    {
        "id": "simple-04-incorrect-authz",
        "title": "Inverted Role Permission Check (Python)",
        "language": "python",
        "true_is_vulnerable": True,
        "true_vuln_class": "incorrect_authz",
        "description": "Inverted boolean logic grants unrestricted access to banned users instead of active admins.",
        "code": """def can_edit_system_settings(user):
    if user.is_banned:
        return True
    return False"""
    },
    {
        "id": "simple-05-clean-endpoint",
        "title": "Clean Properly Scoped Endpoint (Python/FastAPI)",
        "language": "python",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "description": "Correctly enforces authentication dependency and strict document ownership filtering by current_user.id.",
        "code": """@router.get('/documents/{document_id}')
def get_user_document(document_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.query(Document).filter(
        Document.id == document_id,
        Document.owner_id == current_user.id
    ).first()
    if not doc:
        raise HTTPException(status_code=404, detail='Document not found or unauthorized')
    return doc"""
    }
]


def run_simple_test_suite(model_path: str = "checkpoints_3b", model_id: str = "Qwen/Qwen2.5-Coder-3B-Instruct"):
    print("=" * 80)
    print("  SIMPLE AUTHORIZATION / AUTHENTICATION CAPABILITY TEST SUITE")
    print("=" * 80)

    adapter_dir = resolve_best_checkpoint(model_path)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"[INFO] Running on device: {device} (adapter: {adapter_dir})")

    model, tokenizer = load_model_for_evaluation(model_id=model_id, adapter_path=adapter_dir, device=device)

    print("\n" + "=" * 80)
    print("  EVALUATING 5 SIMPLE TEST CASES")
    print("=" * 80 + "\n")

    correct_count = 0
    results = []

    for idx, test_case in enumerate(SIMPLE_TEST_CASES, 1):
        print(f"[{idx}/5] CASE: {test_case['title']}")
        print(f"LANGUAGE: {test_case['language']} | EXPECTED: is_vulnerable={test_case['true_is_vulnerable']}, class={test_case['true_vuln_class']}")
        print(f"DESCRIPTION: {test_case['description']}")
        print("-" * 80)

        prompt = format_user_prompt(test_case["code"], test_case["language"])
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

        if hasattr(tokenizer, "apply_chat_template"):
            prompt_text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        else:
            prompt_text = f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n"

        inputs = tokenizer(prompt_text, return_tensors="pt").to(device)

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=256,
                do_sample=False,
                pad_token_id=tokenizer.pad_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )

        gen_tokens = outputs[0][inputs["input_ids"].shape[1]:]
        raw_response = tokenizer.decode(gen_tokens, skip_special_tokens=True).strip()
        parsed = extract_json_from_response(raw_response)

        pred_is_vuln = bool(parsed.get("is_vulnerable", False))
        pred_class = parsed.get("vulnerability_class", "none")
        pred_conf = parsed.get("confidence", 0.0)
        pred_exp = parsed.get("explanation", "")

        is_correct_binary = (pred_is_vuln == test_case["true_is_vulnerable"])
        if is_correct_binary:
            correct_count += 1
            status_str = "PASSED (CORRECT)"
        else:
            status_str = "FAILED (INCORRECT)"

        print(f"MODEL PREDICTION: is_vulnerable={pred_is_vuln}, class={pred_class}, confidence={pred_conf:.2f}")
        print(f"EXPLANATION: {pred_exp}")
        print(f"STATUS: {status_str}")
        print("=" * 80 + "\n")

        results.append({
            "id": test_case["id"],
            "title": test_case["title"],
            "expected_vuln": test_case["true_is_vulnerable"],
            "predicted_vuln": pred_is_vuln,
            "expected_class": test_case["true_vuln_class"],
            "predicted_class": pred_class,
            "status": status_str
        })

    accuracy = (correct_count / len(SIMPLE_TEST_CASES)) * 100
    print(f"FINAL SIMPLE TEST SCORE: {correct_count} / {len(SIMPLE_TEST_CASES)} ({accuracy:.1f}% Accuracy)")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Simple Auth/Authz Capability Test Suite")
    parser.add_argument("--model_path", type=str, default="checkpoints_1.5b", help="Path to checkpoint/adapter directory")
    parser.add_argument("--model_id", type=str, default="Qwen/Qwen2.5-Coder-1.5B-Instruct", help="Base model ID")
    args = parser.parse_args()

    run_simple_test_suite(model_path=args.model_path, model_id=args.model_id)
