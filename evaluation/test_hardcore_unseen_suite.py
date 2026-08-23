"""Hardcore Unseen Multi-Language Security Evaluation Suite.

Contains 10 real-world, complex, diverse test cases across Python, Go, TypeScript/JS, and Java:
1. Multi-Tenant GraphQL Field Resolver IDOR (Python / Strawberry + SQLAlchemy)
2. JWT Algorithm Confusion / 'None' Signature Bypass (Go / Chi + jwt-go)
3. Next.js 14 Server Action Missing Team Admin Check (TypeScript / Next.js + Prisma)
4. Sound Pessimistic Row-Locking Multi-Tenant Asset Transfer (Python / Django - Clean Baseline)
5. Sound Constant-Time Password Reset Token Invalidation (Python / Flask - Clean Baseline)
6. Spring Security SpEL Parameter Mismatch Permission Bypass (Java / Spring Boot)
7. Zero-Bitmask Default Authorization Bypass Middleware (Go / Gin)
8. Sound OAuth2 PKCE Cryptographic Code Exchange (Node.js / Express - Clean Baseline)
9. Bulk Batch Resource Update IDOR (Python / FastAPI + Async SQLAlchemy)
10. Webhook HMAC String Equality Timing Side-Channel Leak (TypeScript / Express + Crypto)
"""

import argparse
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

# PEFT torchao workaround for Windows / Kaggle
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
from evaluation.eval_model import extract_json_from_response, load_model_for_evaluation, resolve_best_checkpoint


HARDCORE_UNSEEN_CASES = [
    {
        "id": "hardcore-01-graphql-idor",
        "title": "GraphQL Field Resolver IDOR (Python / Strawberry + SQLAlchemy)",
        "language": "python",
        "true_is_vulnerable": True,
        "true_vuln_class": "IDOR",
        "flaw_description": "Parent resolver validates tenant access, but child field resolver fetches private AuditLog records directly by log_id without asserting log.tenant_id == current_user.tenant_id.",
        "code": """@strawberry.type
class Query:
    @strawberry.field
    async def organization(self, info: Info, org_id: UUID) -> Optional[OrganizationType]:
        user = info.context.current_user
        db: AsyncSession = info.context.db
        membership = await db.scalar(select(OrgMember).where(OrgMember.org_id == org_id, OrgMember.user_id == user.id))
        if not membership:
            raise PermissionError("Access denied to organization")
        return await db.scalar(select(Organization).where(Organization.id == org_id))

    @strawberry.field
    async def audit_log_entry(self, info: Info, log_id: UUID) -> Optional[AuditLogType]:
        user = info.context.current_user
        if not user.is_authenticated:
            raise PermissionError("Authentication required")
        db: AsyncSession = info.context.db
        # Direct lookup by ID omitting tenant ownership check
        entry = await db.scalar(select(AuditLog).where(AuditLog.id == log_id))
        return entry"""
    },
    {
        "id": "hardcore-02-jwt-alg-bypass",
        "title": "JWT Signing Algorithm 'none' Bypass (Go / Chi + Golang JWT)",
        "language": "go",
        "true_is_vulnerable": True,
        "true_vuln_class": "auth_bypass",
        "flaw_description": "Token verification callback accepts jwt.SigningMethodNone or skips verifying token.Method is strictly HMAC-SHA256, allowing forged tokens.",
        "code": """func JWTAuthMiddleware(jwtKey []byte) func(http.Handler) http.Handler {
\treturn func(next http.Handler) http.Handler {
\t\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
\t\t\tauthHeader := r.Header.Get("Authorization")
\t\t\tif !strings.HasPrefix(authHeader, "Bearer ") {
\t\t\t\thttp.Error(w, "Missing auth token", http.StatusUnauthorized)
\t\t\t\treturn
\t\t\t}
\t\t\ttokenString := strings.TrimPrefix(authHeader, "Bearer ")
\t\t\ttoken, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
\t\t\t\t// Flaw: Accepts 'none' signing method from unverified client header
\t\t\t\tif t.Method.Alg() == "none" {
\t\t\t\t\treturn jwt.UnsafeAllowNoneSignatureType, nil
\t\t\t\t}
\t\t\t\treturn jwtKey, nil
\t\t\t})
\t\t\tif err != nil || !token.Valid {
\t\t\t\thttp.Error(w, "Invalid token", http.StatusUnauthorized)
\t\t\t\treturn
\t\t\t}
\t\t\tnext.ServeHTTP(w, r)
\t\t})
\t}
}"""
    },
    {
        "id": "hardcore-03-server-action-idor",
        "title": "Next.js Server Action Missing Role Verification (TypeScript / Next.js)",
        "language": "typescript",
        "true_is_vulnerable": True,
        "true_vuln_class": "missing_authz_check",
        "flaw_description": "Server action verifies authentication session, but fails to check whether caller has Admin role in the target team before deleting members.",
        "code": """"use server";

import { auth } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

export async function removeTeamMember(targetUserId: string, teamId: string) {
  const session = await auth();
  if (!session || !session.user) {
    throw new Error("Authentication required");
  }

  // Flaw: Checks authentication but does not verify caller is team administrator or workspace owner
  await prisma.teamMembership.delete({
    where: {
      teamId_userId: {
        teamId: teamId,
        userId: targetUserId,
      },
    },
  });

  return { success: true };
}"""
    },
    {
        "id": "hardcore-04-django-atomic-transfer",
        "title": "Pessimistic Row-Locked Multi-Tenant Asset Transfer (Python / Django)",
        "language": "python",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Uses transaction.atomic(), select_for_update(), verifies sender ownership, balance sufficiency, and idempotency key.",
        "code": """@api_view(['POST'])
@permission_classes([IsAuthenticated])
def execute_internal_asset_transfer(request):
    source_wallet_id = request.data.get('source_wallet_id')
    dest_wallet_id = request.data.get('dest_wallet_id')
    transfer_amount = Decimal(str(request.data.get('amount', '0')))
    idempotency_key = request.headers.get('X-Idempotency-Key')

    if transfer_amount <= 0 or not idempotency_key:
        return Response({'error': 'Invalid transfer parameters'}, status=400)

    with transaction.atomic():
        if TransferLog.objects.filter(idempotency_key=idempotency_key, user=request.user).exists():
            return Response({'status': 'duplicate_request_ignored'}, status=200)

        # Explicit ownership and pessimistic locking
        source = Wallet.objects.select_for_update().filter(id=source_wallet_id, owner=request.user).first()
        if not source or source.balance < transfer_amount:
            return Response({'error': 'Insufficient funds or wallet not owned'}, status=403)

        dest = Wallet.objects.select_for_update().filter(id=dest_wallet_id).first()
        if not dest:
            return Response({'error': 'Destination wallet not found'}, status=404)

        source.balance -= transfer_amount
        dest.balance += transfer_amount
        source.save()
        dest.save()

        TransferLog.objects.create(idempotency_key=idempotency_key, user=request.user, amount=transfer_amount)

    return Response({'status': 'transfer_completed'}, status=200)"""
    },
    {
        "id": "hardcore-05-flask-secure-reset",
        "title": "Constant-Time Single-Use Password Reset Token (Python / Flask)",
        "language": "python",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Validates single-use token in constant time, checks expiry timestamp, invalidates token atomically.",
        "code": """@app.route('/api/auth/consume-reset-token', methods=['POST'])
def consume_password_reset():
    data = request.get_json() or {}
    token_str = data.get('token')
    new_password = data.get('new_password')

    if not token_str or not new_password or len(new_password) < 10:
        return jsonify({'error': 'Invalid request parameters'}), 400

    token_hash = hashlib.sha256(token_str.encode('utf-8')).hexdigest()
    
    with db.session.begin():
        record = PasswordResetToken.query.filter_by(token_hash=token_hash).with_for_update().first()
        if not record:
            return jsonify({'error': 'Invalid or expired token'}), 400

        # Check single-use state and expiry in UTC
        if record.is_consumed or datetime.now(timezone.utc) > record.expires_at:
            return jsonify({'error': 'Token has expired or already been consumed'}), 400

        user = User.query.filter_by(id=record.user_id).first()
        user.set_password(new_password)
        record.is_consumed = True
        record.consumed_at = datetime.now(timezone.utc)

    return jsonify({'status': 'password_successfully_updated'}), 200"""
    },
    {
        "id": "hardcore-06-spring-spel-authz-mismatch",
        "title": "Spring Security SpEL Parameter Name Mismatch (Java / Spring Boot)",
        "language": "java",
        "true_is_vulnerable": True,
        "true_vuln_class": "incorrect_authz",
        "flaw_description": "SpEL expression checks #accountId against authentication principal, but controller parameter is named targetAccountId, causing SpEL to evaluate to null/true.",
        "code": """@RestController
@RequestMapping("/api/accounts")
public class UserAccountController {

    @Autowired
    private AccountService accountService;

    // Flaw: SpEL expression references #accountId, but parameter is named targetAccountId
    @PreAuthorize("#accountId == authentication.principal.id or hasRole('ADMIN')")
    @DeleteMapping("/{id}/terminate")
    public ResponseEntity<Void> terminateAccount(@PathVariable("id") Long targetAccountId) {
        accountService.deactivateAccount(targetAccountId);
        return ResponseEntity.noContent().build();
    }
}"""
    },
    {
        "id": "hardcore-07-gin-bitmask-zero",
        "title": "Zero-Bitmask Default Authorization Bypass Middleware (Go / Gin)",
        "language": "go",
        "true_is_vulnerable": True,
        "true_vuln_class": "incorrect_authz",
        "flaw_description": "Bitmask permission check evaluates `user.Permissions & requiredMask == requiredMask`. When requiredMask is 0, any caller satisfies the check.",
        "code": """func RequirePermission(requiredMask uint64) gin.HandlerFunc {
\treturn func(c *gin.Context) {
\t\tuserObj, exists := c.Get("current_user")
\t\tuser, ok := userObj.(*UserModel)

\t\t// Flaw: Bitwise check (user.Permissions & 0 == 0) always returns true even for unauthenticated callers
\t\tif exists && ok && (user.Permissions & requiredMask == requiredMask) {
\t\t\tc.Next()
\t\t\treturn
\t\t}

\t\tif requiredMask == 0 {
\t\t\tc.Next() // Bypass without checking authentication
\t\t\treturn
\t\t}

\t\tc.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient bitmask privileges"})
\t}
}"""
    },
    {
        "id": "hardcore-08-oauth2-pkce-exchange",
        "title": "Sound OAuth2 PKCE Cryptographic Code Exchange (Node.js / Express)",
        "language": "javascript",
        "true_is_vulnerable": False,
        "true_vuln_class": "none",
        "flaw_description": "Sound code baseline: Verifies PKCE code_verifier SHA-256 base64url encoding matches code_challenge, validates client_id and redirect_uri binding, consumes authorization code atomically.",
        "code": """app.post('/oauth/v2/token', async (req, res) => {
  const { grant_type, code, client_id, redirect_uri, code_verifier } = req.body;
  if (grant_type !== 'authorization_code' || !code || !code_verifier) {
    return res.status(400).json({ error: 'invalid_request' });
  }

  const authCode = await db.AuthCode.findOne({ where: { code } });
  if (!authCode || authCode.isUsed || new Date() > authCode.expiresAt) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  if (authCode.clientId !== client_id || authCode.redirectUri !== redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  // Cryptographic PKCE SHA-256 check
  const calculatedChallenge = crypto
    .createHash('sha256')
    .update(code_verifier)
    .digest('base64url');

  if (!crypto.timingSafeEqual(Buffer.from(calculatedChallenge), Buffer.from(authCode.codeChallenge))) {
    return res.status(400).json({ error: 'invalid_grant_verifier' });
  }

  await authCode.update({ isUsed: true });
  const token = generateAccessToken(authCode.userId, authCode.scope);
  return res.json({ access_token: token, token_type: 'Bearer', expires_in: 3600 });
});"""
    },
    {
        "id": "hardcore-09-bulk-batch-idor",
        "title": "Bulk Batch Resource Update IDOR (Python / FastAPI + SQLAlchemy)",
        "language": "python",
        "true_is_vulnerable": True,
        "true_vuln_class": "IDOR",
        "flaw_description": "Route verifies workspace membership, but updates tasks with `Task.id.in_(task_ids)` without adding `Task.workspace_id == workspace_id` filter.",
        "code": """@router.post("/workspaces/{ws_id}/tasks/bulk-archive")
async def bulk_archive_workspace_tasks(
    ws_id: UUID,
    payload: BulkTaskPayload,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    # Step 1: Verify caller belongs to workspace
    ws_member = await db.scalar(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == ws_id,
            WorkspaceMember.user_id == current_user.id
        )
    )
    if not ws_member:
        raise HTTPException(status_code=403, detail="Not a member of this workspace")

    # Flaw: Updates batch of task IDs globally without scoping to ws_id
    stmt = (
        update(Task)
        .where(Task.id.in_(payload.task_ids))
        .values(is_archived=True, archived_at=datetime.utcnow())
    )
    await db.execute(stmt)
    await db.commit()

    return {"status": "success", "count": len(payload.task_ids)}"""
    },
    {
        "id": "hardcore-10-express-webhook-timing",
        "title": "Webhook Signature String Equality Timing Leak (TypeScript / Express)",
        "language": "typescript",
        "true_is_vulnerable": True,
        "true_vuln_class": "auth_bypass",
        "flaw_description": "Calculates HMAC signature but compares with client header using !== operator instead of crypto.timingSafeEqual, exposing a timing side-channel attack.",
        "code": """import crypto from "crypto";
import { Request, Response } from "express";

export function verifyStripeWebhook(req: Request, res: Response, next: Function) {
  const signature = req.headers["stripe-signature"] as string;
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET!;

  if (!signature) {
    return res.status(401).json({ error: "Missing signature header" });
  }

  const computedHash = crypto
    .createHmac("sha256", webhookSecret)
    .update(req.body, "utf8")
    .digest("hex");

  // Flaw: Non-constant time string equality comparison leaks timing discrepancy
  if (computedHash !== signature) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  return next();
}"""
    }
]


def run_hardcore_test_suite(model_path: str = "checkpoints_1.5b", model_id: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct"):
    print("=" * 80)
    print("  HARDCORE UNSEEN MULTI-LANGUAGE SECURITY EVALUATION SUITE (10 CASES)")
    print("=" * 80)

    adapter_dir = resolve_best_checkpoint(model_path)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"[INFO] Running on device: {device} (adapter: {adapter_dir})")

    model, tokenizer = load_model_for_evaluation(model_id=model_id, adapter_path=adapter_dir, device=device)

    print("\n" + "=" * 80)
    print("  EVALUATING 10 HARDCORE UNSEEN CASES")
    print("=" * 80 + "\n")

    correct_count = 0
    results = []

    for idx, test_case in enumerate(HARDCORE_UNSEEN_CASES, 1):
        print(f"[{idx}/10] CASE: {test_case['title']}")
        print(f"LANGUAGE: {test_case['language']} | EXPECTED: is_vulnerable={test_case['true_is_vulnerable']}, class={test_case['true_vuln_class']}")
        print(f"SECURITY FLAW / RATIONALE: {test_case['flaw_description']}")
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

        pred_vuln = parsed.get("is_vulnerable")
        pred_class = parsed.get("vulnerability_class")
        confidence = parsed.get("confidence", 0.0)
        explanation = parsed.get("explanation", "")

        is_binary_correct = (pred_vuln == test_case["true_is_vulnerable"])
        is_class_correct = True
        if test_case["true_is_vulnerable"]:
            exp_class = str(test_case["true_vuln_class"]).lower()
            got_class = str(pred_class).lower()
            is_class_correct = (exp_class == got_class or (exp_class in got_class) or (got_class in exp_class))

        test_passed = (is_binary_correct and is_class_correct)
        if test_passed:
            correct_count += 1
            status = "PASSED (CORRECT)"
        else:
            status = "FAILED (INCORRECT)"

        print(f"MODEL PREDICTION: is_vulnerable={pred_vuln}, class={pred_class}, confidence={confidence:.2f}")
        print(f"EXPLANATION: {explanation[:180]}...")
        print(f"STATUS: {status}")
        print("=" * 80 + "\n")

        results.append({
            "id": test_case["id"],
            "title": test_case["title"],
            "language": test_case["language"],
            "expected_vuln": test_case["true_is_vulnerable"],
            "expected_class": test_case["true_vuln_class"],
            "pred_vuln": pred_vuln,
            "pred_class": pred_class,
            "confidence": confidence,
            "passed": test_passed,
        })

    accuracy = (correct_count / len(HARDCORE_UNSEEN_CASES)) * 100.0
    print("=" * 80)
    print(f"FINAL HARDCORE TEST SCORE: {correct_count} / {len(HARDCORE_UNSEEN_CASES)} ({accuracy:.1f}% Accuracy)")
    print("=" * 80)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hardcore Unseen Security Test Suite")
    parser.add_argument("--model_id", type=str, default="Qwen/Qwen2.5-Coder-1.5B-Instruct")
    parser.add_argument("--model_path", type=str, default="checkpoints_1.5b")
    args = parser.parse_args()

    run_hardcore_test_suite(model_path=args.model_path, model_id=args.model_id)
