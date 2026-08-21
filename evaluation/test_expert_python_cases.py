"""Expert Python Challenge Suite for Auth Security Model.

Contains 5 realistic, subtle Python authorization & authentication test cases:
1. Subtle IDOR in SQLAlchemy / FastAPI with nested foreign-key query
2. Cryptographic timing attack via pre-computed length mismatch in HMAC
3. Role hierarchy flaw via Enum integer comparison in permission decorator
4. DRF ViewSet get_object() overriding check_object_permissions
5. Complex-looking but 100% SOUND cryptographic token exchange (Clean baseline)
"""

import json
import os
import re
import sys
import time
from typing import Any, Dict, List

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

# Complete torchao bypass for PEFT in all environments
try:
    import peft.import_utils
    peft.import_utils.is_torchao_available = lambda: False
    if hasattr(peft.import_utils, "is_torch_ao_available"):
        peft.import_utils.is_torch_ao_available = lambda: False
    import peft.tuners.lora.torchao
    peft.tuners.lora.torchao.dispatch_torchao = lambda *args, **kwargs: None
    peft.tuners.lora.torchao.is_torchao_available = lambda: False
except Exception:
    pass

from peft import PeftModel
from training.dataset_formatter import format_user_prompt, SYSTEM_PROMPT
from evaluation.eval_model import extract_json_from_response, load_model_for_evaluation


EXPERT_TEST_CASES = [
    {
        "id": "py-expert-01-idor",
        "title": "Nested Foreign-Key Query IDOR (FastAPI + SQLAlchemy)",
        "hidden_flaw": "Directly filters by `document_id` and joins Organization, but fails to assert `Organization.tenant_id == current_user.tenant_id` on the Document join condition, allowing cross-tenant document exfiltration.",
        "true_is_vulnerable": True,
        "true_vuln_class": "idor",
        "code": '''@router.get("/organizations/{org_id}/documents/{doc_id}")
async def get_org_document(
    org_id: UUID,
    doc_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    # Verify caller has membership in the requested organization
    membership = await db.scalar(
        select(OrgMember).where(
            OrgMember.org_id == org_id,
            OrgMember.user_id == current_user.id
        )
    )
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member of this organization")

    # Fetch document directly by primary key
    stmt = (
        select(Document)
        .join(Organization, Document.org_id == Organization.id)
        .where(Document.id == doc_id)
    )
    document = await db.scalar(stmt)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    return document'''
    },
    {
        "id": "py-expert-02-auth-bypass",
        "title": "Pre-Comparison Length Check Timing Attack (HMAC Signature)",
        "hidden_flaw": "Uses `hmac.compare_digest`, but guards it with a fast-fail `len(signature) != len(expected_sig)` standard comparison. This leaks expected signature length and creates a side-channel timing discrepancy on invalid inputs.",
        "true_is_vulnerable": True,
        "true_vuln_class": "auth_bypass",
        "code": '''def verify_webhook_signature(payload: bytes, signature_header: str, secret_key: str) -> bool:
    if not signature_header or not secret_key:
        return False
    
    expected_mac = hmac.new(
        secret_key.encode("utf-8"),
        msg=payload,
        digestmod=hashlib.sha256
    ).hexdigest()
    
    # Fast check: reject mismatched length before constant-time comparison
    if len(signature_header) != len(expected_mac):
        return False
        
    return hmac.compare_digest(signature_header, expected_mac)'''
    },
    {
        "id": "py-expert-03-incorrect-authz",
        "title": "Enum Integer Value Privilege Escalation (Django Decorator)",
        "hidden_flaw": "Compares `user.role_level >= Role.AUDITOR` where `Role.GUEST = 0`, `Role.AUDITOR = 1`, `Role.ADMIN = 2`. Because `Role.SUSPENDED = 3` has a higher numerical enum value, suspended users satisfy the `>= AUDITOR` check.",
        "true_is_vulnerable": True,
        "true_vuln_class": "incorrect_authz",
        "code": '''class UserRole(IntEnum):
    GUEST = 0
    AUDITOR = 1
    ADMIN = 2
    SUSPENDED = 3  # Inactive account state

def require_minimum_clearance(required_role: UserRole):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return HttpResponseForbidden("Authentication required")
            
            # Allow access if user role level meets or exceeds threshold
            if request.user.role >= required_role:
                return view_func(request, *args, **kwargs)
                
            return HttpResponseForbidden("Insufficient permission level")
        return _wrapped_view
    return decorator'''
    },
    {
        "id": "py-expert-04-missing-authz",
        "title": "DRF get_object() Object-Level Permission Omission",
        "hidden_flaw": "Overrides `get_object()` using `get_object_or_404(queryset, pk=pk)` but omits the mandatory DRF call `self.check_object_permissions(self.request, obj)`. Global permission classes run on the view, but object-level permissions (e.g. `IsOwnerOrReadOnly`) are silently bypassed.",
        "true_is_vulnerable": True,
        "true_vuln_class": "missing_authz",
        "code": '''class FinancialReportViewSet(viewsets.ModelViewSet):
    queryset = FinancialReport.objects.all()
    serializer_class = FinancialReportSerializer
    permission_classes = [permissions.IsAuthenticated, IsReportOwnerOrAuditor]

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field
        filter_kwargs = {self.lookup_field: self.kwargs[lookup_url_kwarg]}
        obj = get_object_or_404(queryset, **filter_kwargs)
        # Returns object directly without invoking self.check_object_permissions()
        return obj'''
    },
    {
        "id": "py-expert-05-clean-subtle",
        "title": "Sound Two-Factor Token Exchange (Clean Code Baseline)",
        "hidden_flaw": "None. The code looks complex and performs token exchange, but strictly enforces signature validation, single-use nonce destruction, tenant binding, and expiry verification.",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "code": '''def exchange_pre_auth_token(db: Session, raw_token: str, client_ip: str) -> Tuple[User, str]:
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    
    # Atomic transaction: fetch and immediately invalidate token
    with db.begin():
        record = db.execute(
            select(PreAuthSession)
            .where(
                PreAuthSession.token_hash == token_hash,
                PreAuthSession.is_used == False,
                PreAuthSession.expires_at > datetime.now(timezone.utc)
            )
            .with_for_update()
        ).scalar_one_or_none()
        
        if not record:
            raise InvalidCredentialsException("Invalid or expired session token")
            
        record.is_used = True
        user = record.user
        
        if not user.is_active:
            raise AccountDisabledException("User account is inactive")
            
        session_id = create_authenticated_session(db, user=user, ip=client_ip)
        return user, session_id'''
    }
]


def run_expert_python_challenge(model_path: str = "checkpoints", model_id: str = "Qwen/Qwen2.5-Coder-0.5B-Instruct"):
    print("=" * 80)
    print("  EXPERT PYTHON AUTHORIZATION SECURITY CHALLENGE")
    print("=" * 80)

    # Automatic checkpoint discovery
    adapter_dir = model_path
    if os.path.exists(adapter_dir) and not os.path.exists(os.path.join(adapter_dir, "adapter_config.json")):
        import glob
        subdirs = glob.glob(os.path.join(adapter_dir, "checkpoint-*"))
        if subdirs:
            def get_step(p):
                m = re.search(r"checkpoint-(\d+)", p)
                return int(m.group(1)) if m else -1
            adapter_dir = max(subdirs, key=get_step)
            print(f"[INFO] Selected latest checkpoint: {adapter_dir}")

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"[INFO] Loading fine-tuned model on {device}...")
    model, tokenizer = load_model_for_evaluation(model_id=model_id, adapter_path=adapter_dir, device=device)

    print("\n" + "=" * 80)
    print("  BEGINNING EVALUATION ON 5 HARD EXPERT PYTHON CASES")
    print("=" * 80 + "\n")

    correct_count = 0

    for idx, test_case in enumerate(EXPERT_TEST_CASES, 1):
        print(f"[{idx}/5] CASE ID: {test_case['id']}")
        print(f"TITLE: {test_case['title']}")
        print(f"EXPECTED: is_vulnerable={test_case['true_is_vulnerable']}, class={test_case['true_vuln_class']}")
        print(f"HIDDEN FLAW: {test_case['hidden_flaw']}")
        print("-" * 80)

        prompt = format_user_prompt(test_case["code"], "python")
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
                max_new_tokens=160,
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

        print(f"PREDICTION: is_vulnerable={pred_is_vuln}, class={pred_class}, confidence={pred_conf:.2f}")
        print(f"MODEL EXPLANATION: {pred_exp}")
        print(f"STATUS: {status_str}")
        print("=" * 80 + "\n")

    print(f"FINAL SCORE: {correct_count} / {len(EXPERT_TEST_CASES)} ({correct_count / len(EXPERT_TEST_CASES) * 100:.1f}% Accuracy)\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Expert Python Authorization Challenge")
    parser.add_argument("--model_path", type=str, default="checkpoints")
    parser.add_argument("--model_id", type=str, default="Qwen/Qwen2.5-Coder-0.5B-Instruct")
    args = parser.parse_args()
    run_expert_python_challenge(model_path=args.model_path, model_id=args.model_id)
